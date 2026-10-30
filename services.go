package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ServiceObservation uses nil for fields not measured by a plugin/old collector.
// This preserves newer evidence when an older producer reports a partial result.
type ServiceObservation struct {
	EvidenceOnly        bool            `json:"evidence_only,omitempty"`
	Source              string          `json:"source,omitempty"`
	IP                  string          `json:"ip"`
	Port                int             `json:"port"`
	Protocol            string          `json:"protocol"`
	Service             *string         `json:"service,omitempty"`
	Banner              *string         `json:"banner,omitempty"`
	Scheme              *string         `json:"scheme,omitempty"`
	StatusCode          *int            `json:"status_code,omitempty"`
	Title               *string         `json:"title,omitempty"`
	Server              *string         `json:"server,omitempty"`
	FaviconMMH3         *int32          `json:"favicon_mmh3,omitempty"`
	FaviconSHA256       *string         `json:"favicon_sha256,omitempty"`
	FaviconMeasured     bool            `json:"-"`
	FingerprintEvidence json.RawMessage `json:"fingerprint_evidence,omitempty"`
	FingerprintMeasured bool            `json:"-"`
	Fingerprints        json.RawMessage `json:"fingerprints,omitempty"`
	TLSSubject          *string         `json:"tls_subject,omitempty"`
	TLSNotAfter         *time.Time      `json:"tls_not_after,omitempty"`
	ScreenshotRef       *string         `json:"screenshot_ref,omitempty"`
	MissCount           *int            `json:"miss_count,omitempty"`
}

func ptr[T any](v T) *T { return &v }
func legacyService(o Observation) []ServiceObservation {
	if o.EvidenceOnly || o.StatusCode <= 0 {
		return nil
	}
	scheme := "http"
	if o.Port == 443 || o.TLSSubject != "" || o.TLSNotAfter != nil {
		scheme = "https"
	}
	port := o.Port
	if port <= 0 {
		port = 80
		if scheme == "https" {
			port = 443
		}
	}
	ip := ""
	if len(o.IPs) > 0 {
		ip = o.IPs[0]
	}
	fingerprints := o.Fingerprints
	if fingerprints == nil {
		fingerprints = []string{}
	}
	raw, _ := json.Marshal(fingerprints)
	s := ServiceObservation{IP: ip, Port: port, Protocol: "tcp", Service: ptr(scheme), Scheme: ptr(scheme), StatusCode: ptr(o.StatusCode), Title: ptr(o.Title), Server: ptr(o.Server), Fingerprints: raw, TLSSubject: ptr(o.TLSSubject), TLSNotAfter: o.TLSNotAfter, MissCount: ptr(0)}
	// Missing old-format fields must not erase evidence produced by newer probes.
	s.FaviconMMH3, s.FaviconSHA256, s.FaviconMeasured = o.FaviconMMH3, o.FaviconSHA256, o.FaviconMeasured
	s.FingerprintEvidence, s.FingerprintMeasured = o.FingerprintEvidence, o.FingerprintMeasured
	return []ServiceObservation{s}
}
func serviceRank(s ServiceObservation) int {
	if s.Port == 443 {
		return 0
	}
	if s.Port == 80 {
		return 1
	}
	return s.Port + 2
}

// groupObservations makes asset events and miss counting happen once per host.
func groupObservations(input []Observation) []Observation {
	grouped := map[string]*Observation{}
	hosts := []string{}
	for _, o := range input {
		host, err := normalizeHost(o.Host)
		if err != nil {
			continue
		}
		o.Host = host
		if o.EvidenceOnly {
			// Do not let provider metadata become a DNS answer or a live HTTP summary.
			for i := range o.Services {
				o.Services[i].EvidenceOnly = true
				o.Services[i].FingerprintEvidence, o.Services[i].FingerprintMeasured = nil, false
				o.Services[i].FaviconMMH3, o.Services[i].FaviconSHA256, o.Services[i].FaviconMeasured = nil, nil, false
			}
			o = Observation{Host: host, Sources: o.Sources, Services: o.Services, PluginEvidence: o.PluginEvidence, EvidenceOnly: true, PreserveReachability: true}
		}
		services := slices.Clone(o.Services)
		if len(services) == 0 {
			services = legacyService(o)
		}
		current := grouped[host]
		if current == nil {
			copy := o
			copy.Services = nil
			copy.Sources = nil
			copy.IPs = nil
			copy.CNames = nil
			copy.Alive = nil
			copy.DNSChecked = false
			current = &copy
			grouped[host] = current
			hosts = append(hosts, host)
		}
		// Preserve the historical summary fields while choosing a stable successful image.
		if o.StatusCode > 0 && (current.StatusCode <= 0 || serviceRank(ServiceObservation{Port: o.Port}) < serviceRank(ServiceObservation{Port: current.Port})) {
			saved := *current
			*current = o
			current.Services = saved.Services
			current.Sources = saved.Sources
			current.IPs = saved.IPs
			current.CNames = saved.CNames
			current.Alive = saved.Alive
			current.DNSChecked = saved.DNSChecked
			current.EvidenceOnly = saved.EvidenceOnly
			current.PreserveReachability = saved.PreserveReachability
			current.PluginEvidence = saved.PluginEvidence
			current.NetworkEvidence, current.NetworkMeasured, current.IsCDN = saved.NetworkEvidence, saved.NetworkMeasured, saved.IsCDN
		}
		if o.NetworkMeasured {
			current.NetworkMeasured = true
			current.NetworkEvidence = o.NetworkEvidence
			current.IsCDN = o.IsCDN
		}
		current.EvidenceOnly = current.EvidenceOnly && o.EvidenceOnly
		current.PreserveReachability = current.PreserveReachability && o.PreserveReachability
		current.PluginEvidence = mergePluginEvidence(current.PluginEvidence, o.PluginEvidence)
		current.Services = append(current.Services, services...)
		current.Sources = append(current.Sources, o.Sources...)
		current.IPs = append(current.IPs, o.IPs...)
		current.CNames = append(current.CNames, o.CNames...)
		current.DNSChecked = current.DNSChecked || o.DNSChecked
		if o.Alive != nil {
			v := *o.Alive || (current.Alive != nil && *current.Alive)
			current.Alive = ptr(v)
		}
	}
	slices.Sort(hosts)
	out := make([]Observation, 0, len(hosts))
	for _, host := range hosts {
		o := grouped[host]
		for _, values := range []*[]string{&o.Sources, &o.IPs, &o.CNames} {
			if *values == nil {
				*values = []string{}
			}
			slices.Sort(*values)
			*values = slices.Compact(*values)
		}
		out = append(out, *o)
	}
	return out
}

// projectService fills the old asset summary for new service-only producers.
// TODO(discovery-vNext): remove this projection and legacy asset columns together.
func projectService(o *Observation, old Observation) {
	if o.EvidenceOnly || o.StatusCode > 0 {
		return
	}
	var best *ServiceObservation
	for i := range o.Services {
		s := &o.Services[i]
		if !s.EvidenceOnly && s.StatusCode != nil && *s.StatusCode > 0 && (best == nil || serviceRank(*s) < serviceRank(*best)) {
			best = s
		}
	}
	if best == nil {
		return
	}
	o.Port = best.Port
	o.StatusCode = *best.StatusCode
	o.Title = old.Title
	o.Server = old.Server
	o.TLSSubject = old.TLSSubject
	o.TLSNotAfter = old.TLSNotAfter
	o.Favicon = old.Favicon
	o.Fingerprints = old.Fingerprints
	o.Redirects = old.Redirects
	o.Security = old.Security
	o.SecurityRule = old.SecurityRule
	o.SecurityMatches = old.SecurityMatches
	if best.Title != nil {
		o.Title = *best.Title
	}
	if best.Server != nil {
		o.Server = *best.Server
	}
	if best.TLSSubject != nil {
		o.TLSSubject = *best.TLSSubject
	}
	if best.TLSNotAfter != nil {
		o.TLSNotAfter = best.TLSNotAfter
	}
	if best.FingerprintMeasured {
		o.FingerprintEvidence, o.FingerprintMeasured = best.FingerprintEvidence, true
	}
	if best.Fingerprints != nil {
		var values []json.RawMessage
		if json.Unmarshal(best.Fingerprints, &values) == nil {
			o.Fingerprints = []string{}
			for _, raw := range values {
				var name string
				if json.Unmarshal(raw, &name) != nil {
					var f struct {
						Name string `json:"name"`
					}
					json.Unmarshal(raw, &f)
					name = f.Name
				}
				if name != "" {
					o.Fingerprints = append(o.Fingerprints, name)
				}
			}
		}
	}
	if o.Fingerprints == nil {
		o.Fingerprints = []string{}
	}
	if o.Redirects == nil {
		o.Redirects = []string{}
	}
	if o.Alive == nil {
		o.Alive = ptr(true)
	}
}
func validateService(s ServiceObservation) (ServiceObservation, error) {
	if s.FaviconMeasured && !s.EvidenceOnly {
		if (s.FaviconMMH3 == nil) != (s.FaviconSHA256 == nil) {
			return s, errors.New("图标采集事实须同时提供两种哈希或同时为空")
		}
		if s.FaviconSHA256 != nil {
			raw, err := hex.DecodeString(*s.FaviconSHA256)
			if err != nil || len(raw) != 32 {
				return s, errors.New("图标 SHA-256 无效")
			}
			s.FaviconSHA256 = ptr(strings.ToLower(*s.FaviconSHA256))
		}
	}
	if s.Port < 1 || s.Port > 65535 {
		return s, errors.New("服务端口无效")
	}
	s.Protocol = strings.ToLower(s.Protocol)
	if s.Protocol == "" {
		s.Protocol = "tcp"
	}
	if s.Protocol != "tcp" && s.Protocol != "udp" {
		return s, errors.New("服务传输协议无效")
	}
	if s.IP != "" {
		ip, err := netip.ParseAddr(s.IP)
		if err != nil {
			return s, errors.New("服务 IP 无效")
		}
		s.IP = ip.Unmap().String()
	}
	if s.Fingerprints != nil {
		var v []json.RawMessage
		if string(s.Fingerprints) == "null" || json.Unmarshal(s.Fingerprints, &v) != nil {
			return s, errors.New("服务指纹须为数组")
		}
	}
	if s.MissCount != nil && *s.MissCount < 0 {
		return s, errors.New("服务缺失次数无效")
	}
	return s, nil
}
func upsertServices(ctx context.Context, tx pgx.Tx, asset int64, services []ServiceObservation, g ScopeGuard) error {
	for _, input := range services {
		if input.EvidenceOnly || !input.FaviconMeasured {
			input.FaviconMMH3, input.FaviconSHA256, input.FaviconMeasured = nil, nil, false
		}
		s, err := validateService(input)
		if err != nil {
			return err
		}
		var ip *string
		if s.IP != "" {
			if err = g.AllowIP(s.IP); err != nil {
				return errors.New("服务 IP 被范围规则拒绝")
			}
			ip = ptr(s.IP)
		}
		conflict := "(asset_id,ip,port,protocol)"
		if ip == nil {
			conflict = "(asset_id,port,protocol) WHERE ip IS NULL"
		}
		if s.EvidenceOnly || !s.FingerprintMeasured {
			s.FingerprintEvidence = nil
			s.FingerprintMeasured = false
		}
		var fingerprints any
		if s.Fingerprints != nil {
			fingerprints = s.Fingerprints
		}
		// TODO(discovery-vNext): keep asset_services and the old assets summary in one
		// transaction throughout the compatibility window; drop old columns only later.
		_, err = tx.Exec(ctx, `INSERT INTO asset_services(asset_id,ip,port,protocol,service,banner,scheme,status_code,title,server,favicon_mmh3,favicon_sha256,fingerprints,tls_subject,tls_not_after,screenshot_ref,miss_count,evidence_only,source,favicon_first_verified_at,fingerprint_evidence)
   VALUES($1,$2::inet,$3,$4,coalesce($5,''),coalesce($6,''),coalesce($7,''),coalesce($8,0),coalesce($9,''),coalesce($10,''),$11,$12,coalesce($13::jsonb,'[]'),coalesce($14,''),$15,coalesce($16,''),coalesce($17,0),$18,$19,CASE WHEN $20 AND $11::integer IS NOT NULL THEN clock_timestamp() END,coalesce($21::jsonb,'[]'))
   ON CONFLICT `+conflict+` DO UPDATE SET
   service=coalesce($5,asset_services.service),banner=coalesce($6,asset_services.banner),scheme=coalesce($7,asset_services.scheme),status_code=coalesce($8,asset_services.status_code),title=coalesce($9,asset_services.title),server=coalesce($10,asset_services.server),
   fingerprint_evidence=CASE WHEN $22 THEN $21::jsonb ELSE asset_services.fingerprint_evidence END, favicon_mmh3=CASE WHEN $20 THEN $11 ELSE asset_services.favicon_mmh3 END,favicon_sha256=CASE WHEN $20 THEN $12 ELSE asset_services.favicon_sha256 END,favicon_first_verified_at=coalesce(asset_services.favicon_first_verified_at,excluded.favicon_first_verified_at),fingerprints=coalesce($13::jsonb,asset_services.fingerprints),tls_subject=coalesce($14,asset_services.tls_subject),tls_not_after=coalesce($15,asset_services.tls_not_after),screenshot_ref=coalesce($16,asset_services.screenshot_ref),miss_count=coalesce($17,asset_services.miss_count),last_seen=now(),evidence_only=excluded.evidence_only,source=excluded.source WHERE NOT excluded.evidence_only OR asset_services.evidence_only`,
			asset, ip, s.Port, s.Protocol, s.Service, s.Banner, s.Scheme, s.StatusCode, s.Title, s.Server, s.FaviconMMH3, s.FaviconSHA256, fingerprints, s.TLSSubject, s.TLSNotAfter, s.ScreenshotRef, s.MissCount, s.EvidenceOnly, s.Source, s.FaviconMeasured, s.FingerprintEvidence, s.FingerprintMeasured)
		if err != nil {
			return err
		}
		if ip != nil {
			if err = linkAssetIP(ctx, tx, asset, g.Scope.ID, *ip); err != nil {
				return err
			}
		}
	}
	return nil
}
func linkAssetIP(ctx context.Context, tx pgx.Tx, asset, scope int64, ip string) error {
	_, err := tx.Exec(ctx, `WITH i AS(INSERT INTO ip_assets(scope_id,ip)VALUES($1,$2::inet)ON CONFLICT(scope_id,ip)DO UPDATE SET last_seen=now() RETURNING id)
 INSERT INTO asset_ips(asset_id,ip_asset_id)SELECT $3,id FROM i ON CONFLICT DO NOTHING`, scope, ip, asset)
	return err
}
func writeDNSHistory(ctx context.Context, tx pgx.Tx, asset int64, o Observation, g ScopeGuard) error {
	if !o.DNSChecked {
		return nil
	}
	record := func(kind, value string) error {
		_, err := tx.Exec(ctx, `INSERT INTO dns_records(scope_id,host,rtype,value)VALUES($1,$2,$3,$4)ON CONFLICT(scope_id,host,rtype,value)DO UPDATE SET last_seen=now()`, g.Scope.ID, o.Host, kind, value)
		return err
	}
	for _, raw := range o.IPs {
		ip, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		ip = ip.Unmap()
		if g.AllowIP(ip.String()) != nil {
			continue
		}
		kind := "AAAA"
		if ip.Is4() {
			kind = "A"
		}
		if err = record(kind, ip.String()); err != nil {
			return err
		}
		if err = linkAssetIP(ctx, tx, asset, g.Scope.ID, ip.String()); err != nil {
			return err
		}
	}
	for _, c := range o.CNames {
		if err := record("CNAME", c); err != nil {
			return err
		}
	}
	return nil
}

// Explicit column projection keeps future sensitive/internal columns out of APIs.
const assetServicesSQL = `SELECT jsonb_build_object('id',id,'asset_id',asset_id,'ip',host(ip),'port',port,'protocol',protocol,'service',service,'banner',banner,'scheme',scheme,'status_code',status_code,'title',title,'server',server,'favicon_mmh3',favicon_mmh3,'favicon_sha256',favicon_sha256,'favicon_legacy_sha256',favicon_legacy_sha256,'fingerprints',fingerprints,'fingerprint_evidence',fingerprint_evidence,'tls_subject',tls_subject,'tls_not_after',tls_not_after,'screenshot_ref',screenshot_ref,'first_seen',first_seen,'last_seen',last_seen,'miss_count',miss_count,'evidence_only',evidence_only,'source',source) FROM asset_services WHERE asset_id=$1 ORDER BY port,protocol,ip NULLS FIRST,id`

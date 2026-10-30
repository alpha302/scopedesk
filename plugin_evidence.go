package main

import (
	"encoding/json"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// PluginEvidence is provider-reported metadata, never a live reachability measurement.
type PluginEvidence struct {
	AccountID            *int64         `json:"account_id,omitempty"`
	ProviderTime         *time.Time     `json:"provider_time"`
	ProviderTimeRaw      *string        `json:"provider_time_raw"`
	ProviderTimeMeaning  string         `json:"provider_time_meaning,omitempty"`
	ProviderTimeTimezone string         `json:"provider_time_timezone,omitempty"`
	ObtainedAt           *time.Time     `json:"obtained_at,omitempty"`
	Source               string         `json:"source"`
	IP                   string         `json:"ip,omitempty"`
	Port                 int            `json:"port,omitempty"`
	Protocol             string         `json:"protocol,omitempty"`
	Fields               map[string]any `json:"fields"`
	ObservedAt           time.Time      `json:"observed_at"`
}

func observerSourcesOnly(sources []string, registry *PluginRegistry) bool {
	if len(sources) == 0 || registry == nil {
		return false
	}
	for _, source := range sources {
		m, ok := registry.Manifests[source]
		if !ok || m.Kind != "observer" {
			return false
		}
	}
	return true
}

// Bound asset payloads while keeping the most recently reported endpoints per source.
func mergePluginEvidence(old, incoming []PluginEvidence) []PluginEvidence {
	out := append([]PluginEvidence{}, old...)
	for _, item := range incoming {
		key := func(v PluginEvidence) string {
			account := ""
			if v.AccountID != nil {
				account = strconv.FormatInt(*v.AccountID, 10)
			}
			return v.Source + "|" + account + "|" + v.IP + "|" + strconv.Itoa(v.Port) + "|" + v.Protocol
		}
		for i := 0; i < len(out); i++ {
			if key(out[i]) == key(item) {
				fields := map[string]any{}
				for k, v := range out[i].Fields {
					fields[k] = v
				}
				for k, v := range item.Fields {
					fields[k] = v
				}
				item.Fields = fields
				out = append(out[:i], out[i+1:]...)
				break
			}
		}
		out = append(out, item)
	}
	if len(out) > 100 {
		out = out[len(out)-100:]
	}
	return out
}

func rejectedFieldsJSON(fields map[string]int) []byte {
	if fields == nil {
		return []byte("{}")
	}
	raw, _ := json.Marshal(fields)
	return raw
}

func pluginEvidenceContent(input []PluginEvidence) string {
	values := []string{}
	for _, item := range input {
		item.ObservedAt = time.Time{}
		item.ObtainedAt = nil
		raw, _ := json.Marshal(item)
		values = append(values, string(raw))
	}
	sort.Strings(values)
	raw, _ := json.Marshal(values)
	return string(raw)
}

func mapPluginObservation(row map[string]any, m PluginManifest, g ScopeGuard, result *PluginResult) Observation {
	ob := Observation{EvidenceOnly: true, Sources: []string{m.Name}, IPs: []string{}, CNames: []string{}, Fingerprints: []string{}, Redirects: []string{}}
	fields := map[string]any{}
	text := func(field string) *string {
		path, declared := m.Output.Mapping[field]
		if !declared {
			return nil
		}
		v := mappedValue(row, path)
		if v == nil {
			return nil
		}
		s, ok := v.(string)
		if !ok || len(s) > 8192 {
			result.RejectedFields["invalid_"+field]++
			return nil
		}
		fields[field] = s
		return ptr(s)
	}
	number := func(field string, min, max int) (int, bool) {
		path, declared := m.Output.Mapping[field]
		if !declared || mappedValue(row, path) == nil {
			return 0, false
		}
		n, err := strconv.Atoi(strings.TrimSpace(toMappingText(mappedValue(row, path))))
		if err != nil || n < min || n > max {
			result.RejectedFields["invalid_"+field]++
			return 0, false
		}
		return n, true
	}
	service := ServiceObservation{EvidenceOnly: true, Source: m.Name}
	for name, dest := range map[string]**string{"service": &service.Service, "banner": &service.Banner, "scheme": &service.Scheme, "title": &service.Title, "server": &service.Server, "tls_subject": &service.TLSSubject, "favicon_sha256": &service.FaviconSHA256} {
		*dest = text(name)
	}
	if service.Title != nil {
		ob.Title = *service.Title
	}
	if service.Server != nil {
		ob.Server = *service.Server
	}
	if service.TLSSubject != nil {
		ob.TLSSubject = *service.TLSSubject
	}
	if service.FaviconSHA256 != nil {
		// Provider claims stay in PluginEvidence.Fields, never in measured columns.
		service.FaviconSHA256 = nil
	}
	if code, ok := number("status_code", 100, 599); ok {
		ob.StatusCode = code
		service.StatusCode = ptr(code)
		fields["status_code"] = code
	}
	service.Port, _ = number("port", 1, 65535)
	ob.Port = service.Port
	validEndpoint := true
	if path, ok := m.Output.Mapping["ip"]; ok && mappedValue(row, path) != nil {
		value, ok := mappedValue(row, path).(string)
		if !ok || (value != "" && g.AllowIP(value) != nil) {
			result.RejectedFields["invalid_or_disallowed_ip"]++
			validEndpoint = false
		} else if value != "" {
			ip, err := netip.ParseAddr(value)
			if err != nil {
				result.RejectedFields["invalid_or_disallowed_ip"]++
				validEndpoint = false
			} else {
				service.IP = ip.Unmap().String()
				ob.IPs = []string{service.IP}
			}
		}
	}
	service.Protocol = "tcp"
	if path, ok := m.Output.Mapping["protocol"]; ok && mappedValue(row, path) != nil {
		value, ok := mappedValue(row, path).(string)
		value = strings.ToLower(value)
		if !ok || (value != "" && value != "tcp" && value != "udp") {
			result.RejectedFields["invalid_protocol"]++
			service.Protocol = ""
			validEndpoint = false
		} else if value != "" {
			service.Protocol = value
		}
	}
	if service.Port > 0 && validEndpoint {
		normalized, err := validateService(service)
		if err == nil {
			ob.Services = []ServiceObservation{normalized}
		} else {
			result.RejectedFields["invalid_service"]++
		}
	}
	ob.PluginEvidence = []PluginEvidence{{Source: m.Name, IP: service.IP, Port: service.Port, Protocol: service.Protocol, Fields: fields, ObservedAt: time.Now().UTC()}}
	return ob
}

package main

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
)

//go:embed third_party/cdncheck/sources_data.json third_party/cdncheck/manifest.json
var networkRuleFiles embed.FS

type NetworkEvidence struct {
	Category string `json:"category"`
	Provider string `json:"provider"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	Rule     string `json:"rule"`
	Source   string `json:"source"`
	Version  string `json:"version"`
}
type networkIdentity struct{ category, provider string }
type networkManifest struct {
	Repository  string `json:"repository"`
	Commit      string `json:"commit"`
	SHA256      string `json:"sha256"`
	RetrievedAt string `json:"retrieved_at"`
	Suffixes    []struct {
		Suffix           string `json:"suffix"`
		Category         string `json:"category"`
		Provider         string `json:"provider"`
		UpstreamProvider string `json:"upstream_provider"`
	} `json:"suffixes"`
}
type NetworkRules struct {
	manifest      networkManifest
	prefixes      map[netip.Prefix][]networkIdentity
	suffixes      map[string][]networkIdentity
	prefixLengths [2][]int
}

var networkOnce sync.Once
var networkDefault *NetworkRules
var networkLoadError error

func defaultNetworkRules() (*NetworkRules, error) {
	networkOnce.Do(func() { networkDefault, networkLoadError = loadNetworkRules() })
	return networkDefault, networkLoadError
}
func loadNetworkRules() (*NetworkRules, error) {
	raw, err := networkRuleFiles.ReadFile("third_party/cdncheck/sources_data.json")
	if err != nil {
		return nil, err
	}
	manifest, err := networkRuleFiles.ReadFile("third_party/cdncheck/manifest.json")
	if err != nil {
		return nil, err
	}
	rules := &NetworkRules{prefixes: map[netip.Prefix][]networkIdentity{}, suffixes: map[string][]networkIdentity{}}
	if err = json.Unmarshal(manifest, &rules.manifest); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != rules.manifest.SHA256 {
		return nil, errors.New("CDN 快照校验失败")
	}
	var data map[string]map[string][]string
	if err = json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	identities := map[string]bool{}
	for _, category := range []string{"cdn", "waf", "cloud"} {
		for provider, values := range data[category] {
			if len(values) > 0 {
				identities[category+"|"+provider+"|ip"] = true
			}
			for _, value := range values {
				prefix, e := netip.ParsePrefix(value)
				if e != nil {
					return nil, errors.New("CDN 快照含无效网段")
				}
				prefix = prefix.Masked()
				rules.prefixes[prefix] = append(rules.prefixes[prefix], networkIdentity{category, provider})
				family := 0
				if prefix.Addr().Is6() {
					family = 1
				}
				rules.prefixLengths[family] = append(rules.prefixLengths[family], prefix.Bits())
			}
		}
	}
	for i := range rules.prefixLengths {
		slices.Sort(rules.prefixLengths[i])
		rules.prefixLengths[i] = slices.Compact(rules.prefixLengths[i])
	}
	// common has no category in upstream. Only explicitly reviewed suffixes are enabled;
	// never infer CDN from a provider name or silently coerce WAF/cloud entries.
	for _, s := range rules.manifest.Suffixes {
		if !slices.Contains([]string{"cdn", "waf", "cloud"}, s.Category) || !slices.Contains(data["common"][s.UpstreamProvider], s.Suffix) {
			return nil, errors.New("CDN 后缀分类与快照不一致")
		}
		identities[s.Category+"|"+s.Provider+"|cname"] = true
		rules.suffixes[s.Suffix] = append(rules.suffixes[s.Suffix], networkIdentity{s.Category, s.Provider})
	}
	if len(identities) > 128 {
		return nil, errors.New("网络分类供应商数量超过证据容量，需显式调整上限")
	}
	return rules, nil
}
func (r *NetworkRules) Match(ips, cnames []string) []NetworkEvidence {
	out := []NetworkEvidence{}
	add := func(ids []networkIdentity, kind, value, rule string) {
		for _, id := range ids {
			out = append(out, NetworkEvidence{id.category, id.provider, kind, value, rule, r.manifest.Repository, r.manifest.Commit})
		}
	}
	for _, value := range ips {
		ip, e := netip.ParseAddr(value)
		if e != nil {
			continue
		}
		ip = ip.Unmap()
		family := 0
		if ip.Is6() {
			family = 1
		}
		// Preserve overlapping categories/providers, rather than first-match flattening.
		for _, bits := range r.prefixLengths[family] {
			prefix := netip.PrefixFrom(ip, bits).Masked()
			add(r.prefixes[prefix], "ip", ip.String(), prefix.String())
		}
	}
	for _, value := range cnames {
		host := strings.TrimSuffix(strings.ToLower(value), ".")
		for suffix := host; suffix != ""; {
			add(r.suffixes[suffix], "cname", host, suffix)
			i := strings.IndexByte(suffix, '.')
			if i < 0 {
				break
			}
			suffix = suffix[i+1:]
		}
	}
	slices.SortFunc(out, func(a, b NetworkEvidence) int {
		aa, _ := json.Marshal(a)
		bb, _ := json.Marshal(b)
		return strings.Compare(string(aa), string(bb))
	})
	out = slices.Compact(out)
	// Keep representative evidence for EVERY category/provider/type before any cap.
	// Repeated addresses in the same provider do not crowd out another category.
	representatives := []NetworkEvidence{}
	seen := map[string]bool{}
	for _, hit := range out {
		key := hit.Category + "|" + hit.Provider + "|" + hit.Type
		if !seen[key] {
			seen[key] = true
			representatives = append(representatives, hit)
		}
	}
	return representatives
}
func applyNetworkEvidence(o *Observation, rules *NetworkRules) {
	if rules == nil {
		return
	}
	o.NetworkEvidence = rules.Match(o.IPs, o.CNames)
	o.NetworkMeasured = true
	o.IsCDN = false
	for _, hit := range o.NetworkEvidence {
		if hit.Category == "cdn" {
			o.IsCDN = true
		}
	}
}

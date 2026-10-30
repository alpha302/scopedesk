package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type fingerprintSourceMetadata struct {
	Repository             string   `json:"repository"`
	Commit                 string   `json:"commit"`
	SHA256                 string   `json:"sha256"`
	CodeLicense            string   `json:"code_license"`
	RuleLicense            string   `json:"rule_license"`
	LicenseReferences      []string `json:"license_references"`
	ProjectUseAuthorized   bool     `json:"project_use_authorized,omitempty"`
	PermissionBasis        string   `json:"permission_basis,omitempty"`
	RedistributionReviewed bool     `json:"redistribution_reviewed"`
}
type conversionItem struct {
	Product  string   `json:"product"`
	Reasons  []string `json:"reasons"`
	Matchers int      `json:"matchers"`
}
type fingerprintConversionReport struct {
	SourceFormat         string                    `json:"source_format"`
	UnknownMatcherCounts int                       `json:"rules_with_incomplete_matcher_count"`
	UseScope             string                    `json:"use_scope,omitempty"`
	ConverterVersion     string                    `json:"converter_version"`
	Source               fingerprintSourceMetadata `json:"source"`
	OriginalRules        int                       `json:"original_rules"`
	ConvertedRules       int                       `json:"converted_rules"`
	SkippedRules         int                       `json:"skipped_rules"`
	SkippedRuleRatio     float64                   `json:"skipped_rule_ratio"`
	OriginalMatchers     int                       `json:"original_matchers"`
	ConvertedMatchers    int                       `json:"converted_matchers"`
	SkippedMatchers      int                       `json:"skipped_matchers"`
	SkippedMatcherRatio  float64                   `json:"skipped_matcher_ratio"`
	ReasonCounts         map[string]int            `json:"reason_counts"`
	Skipped              []conversionItem          `json:"skipped"`
	Written              bool                      `json:"written"`
	Note                 string                    `json:"note"`
}

func runFingerprintConvert(args []string) error {
	flags := flag.NewFlagSet("fingerprints-convert", flag.ContinueOnError)
	format := flags.String("format", "wappalyzer", "wappalyzer or httpgo")
	projectUse := flags.Bool("project-use", false, "use project-specific permission; does not grant general redistribution")
	input := flags.String("input", "", "pinned local fingerprints_data.json")
	metadata := flags.String("metadata", "", "source/checksum/license metadata")
	output := flags.String("output", "", "optional converted YAML; requires license review")
	reportPath := flags.String("report", "", "conversion report JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *input == "" || *metadata == "" || *reportPath == "" {
		return errors.New("需要 --input、--metadata 和 --report")
	}
	if *input == *reportPath || *input == *output || *metadata == *reportPath || *metadata == *output || *reportPath == *output {
		return errors.New("输入和输出文件必须不同")
	}
	raw, err := os.ReadFile(*input)
	if err != nil {
		return err
	}
	if len(raw) > 32<<20 {
		return errors.New("输入超过 32 MB")
	}
	sourceRaw, err := os.ReadFile(*metadata)
	if err != nil {
		return err
	}
	var source fingerprintSourceMetadata
	if err = json.Unmarshal(sourceRaw, &source); err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(source.Commit) || source.Repository == "" || source.SHA256 != hex.EncodeToString(sum[:]) {
		return errors.New("来源、固定提交或 SHA-256 无效")
	}
	var rules []FingerprintRule
	var report fingerprintConversionReport
	switch *format {
	case "wappalyzer":
		rules, report, err = convertWappalyzerData(raw, source)
	case "httpgo":
		rules, report, err = convertHTTPGoData(raw, source)
	default:
		return errors.New("不支持的来源格式")
	}
	if err != nil {
		return err
	}
	licenseName := strings.ToUpper(strings.TrimSpace(source.RuleLicense))
	licenseReady := source.RedistributionReviewed && licenseName != "" && !strings.Contains(licenseName, "UNREVIEWED") && licenseName != "UNKNOWN" && len(source.LicenseReferences) > 0
	projectReady := *projectUse && source.ProjectUseAuthorized && source.PermissionBasis != "" && source.RuleLicense == "LicenseRef-ScopeDesk-ProjectPermission"
	if *output != "" && (licenseReady || projectReady) {
		if projectReady && !licenseReady {
			report.UseScope = "ScopeDesk project-specific use; general redistribution not reviewed"
		}
		doc := struct {
			Schema int               `yaml:"schema"`
			Rules  []FingerprintRule `yaml:"rules"`
		}{1, rules}
		yamlRaw, e := yaml.Marshal(doc)
		if e != nil {
			return e
		}
		if _, e = parseFingerprintRules(yamlRaw); e != nil {
			return e
		}
		if e = os.WriteFile(*output, yamlRaw, 0644); e != nil {
			return e
		}
		report.Written = true
	}
	reportRaw, _ := json.MarshalIndent(report, "", "  ")
	if err = os.WriteFile(*reportPath, append(reportRaw, '\n'), 0644); err != nil {
		return err
	}
	fmt.Printf("规则 %d，兼容 %d，跳过 %d（%.2f%%）；匹配条件跳过 %.2f%%；规则文件写入：%t\n", report.OriginalRules, report.ConvertedRules, report.SkippedRules, report.SkippedRuleRatio*100, report.SkippedMatcherRatio*100, report.Written)
	if *output != "" && !report.Written {
		return errors.New("已生成兼容性报告；规则许可未完成核对，未写入规则文件")
	}
	return nil
}
func convertWappalyzerData(raw []byte, source fingerprintSourceMetadata) ([]FingerprintRule, fingerprintConversionReport, error) {
	report := fingerprintConversionReport{ConverterVersion: "2", SourceFormat: "wappalyzer", Source: source, ReasonCounts: map[string]int{}, Skipped: []conversionItem{}, Note: "Whole-product conservative conversion; unsupported detection conditions reject the entire product. Ratios describe data compatibility, not real-world detection coverage. Implies/version extraction are not inferred. License review controls output, independently of compatibility statistics."}
	var doc struct {
		Apps map[string]map[string]json.RawMessage `json:"apps"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, report, err
	}
	if len(doc.Apps) == 0 {
		return nil, report, errors.New("未找到 apps 格式规则")
	}
	names := make([]string, 0, len(doc.Apps))
	for name := range doc.Apps {
		names = append(names, name)
	}
	slices.Sort(names)
	report.OriginalRules = len(names)
	out := []FingerprintRule{}
	products := map[string]bool{}
	descriptive := []string{"cats", "description", "website", "cpe", "icon", "implies", "pricing", "oss", "saas"}
	for _, name := range names {
		app := doc.Apps[name]
		matchers := []FingerprintMatcher{}
		reasons := []string{}
		original := 0
		confidence := 80
		fields := make([]string, 0, len(app))
		for field := range app {
			fields = append(fields, field)
		}
		slices.Sort(fields)
		for _, field := range fields {
			value := app[field]
			if string(value) == "null" || string(value) == "[]" || string(value) == "{}" || string(value) == `""` {
				continue
			}
			if slices.Contains(descriptive, field) {
				continue
			}
			if !slices.Contains([]string{"headers", "cookies", "html", "meta", "scriptSrc"}, field) {
				original += countUpstreamMatchers(value)
				reasons = append(reasons, "unsupported_field:"+field)
				continue
			}
			patterns := map[string][]string{}
			if field == "html" || field == "scriptSrc" {
				values, ok := fingerprintStrings(value)
				if !ok {
					reasons = append(reasons, "invalid_patterns:html")
					original++
					continue
				}
				patterns[""] = values
			} else {
				var entries map[string]json.RawMessage
				if json.Unmarshal(value, &entries) != nil {
					reasons = append(reasons, "invalid_patterns:"+field)
					original++
					continue
				}
				for key, v := range entries {
					values, ok := fingerprintStrings(v)
					if !ok {
						reasons = append(reasons, "invalid_patterns:"+field)
						original++
						continue
					}
					patterns[key] = values
				}
			}
			keys := make([]string, 0, len(patterns))
			for key := range patterns {
				keys = append(keys, key)
			}
			slices.Sort(keys)
			for _, key := range keys {
				for _, pattern := range patterns[key] {
					original++
					parts := strings.Split(pattern, `\;`)
					pattern = parts[0]
					for _, tag := range parts[1:] {
						if strings.HasPrefix(tag, "confidence:") {
							n, e := strconv.Atoi(strings.TrimPrefix(tag, "confidence:"))
							if e != nil || n < 1 || n > 100 {
								reasons = append(reasons, "invalid_confidence")
							} else {
								confidence = min(confidence, n)
							}
						} else if !strings.HasPrefix(tag, "version:") {
							reasons = append(reasons, "unsupported_annotation")
						}
					}
					m := FingerprintMatcher{Kind: "regex", Pattern: pattern, Key: key}
					switch field {
					case "html":
						m.Field = "body"
					case "headers":
						m.Field = "header"
					case "cookies":
						m.Field = "cookie"
					case "meta":
						m.Field = "meta"
					case "scriptSrc":
						m.Field = "script_src"
					}
					if err := compileFingerprintMatcher(&m); err != nil {
						reasons = append(reasons, "unsupported_regex_or_matcher")
						continue
					}
					matchers = append(matchers, m)
				}
			}
		}
		report.OriginalMatchers += original
		if len(matchers) == 0 {
			reasons = append(reasons, "no_passive_matchers")
		}
		if len(matchers) > 64 {
			reasons = append(reasons, "matcher_limit")
		}
		productKey := strings.ToLower(strings.TrimSpace(name))
		if products[productKey] {
			reasons = append(reasons, "duplicate_product_name")
		}
		slices.Sort(reasons)
		reasons = slices.Compact(reasons)
		if len(reasons) > 0 {
			report.Skipped = append(report.Skipped, conversionItem{name, reasons, original})
			for _, reason := range reasons {
				report.ReasonCounts[reason]++
			}
			continue
		}
		// Wappalyzer passive signatures are alternatives. Preserve OR, never invent AND.
		unique := []FingerprintMatcher{}
		seen := map[string]bool{}
		for _, m := range matchers {
			v, _ := json.Marshal(m)
			key := string(v)
			if !seen[key] {
				unique = append(unique, m)
				seen[key] = true
			}
		}
		idHash := sha256.Sum256([]byte(source.Repository + "/" + name))
		out = append(out, FingerprintRule{ID: "import-" + hex.EncodeToString(idHash[:12]), Product: name, Combination: "any", Confidence: confidence, Source: source.Repository, Version: source.Commit, License: source.RuleLicense, Matchers: unique})
		products[productKey] = true
		report.ConvertedMatchers += len(matchers)
	}
	report.ConvertedRules = len(out)
	report.SkippedRules = report.OriginalRules - report.ConvertedRules
	report.SkippedRuleRatio = float64(report.SkippedRules) / float64(report.OriginalRules)
	report.SkippedMatchers = report.OriginalMatchers - report.ConvertedMatchers
	if report.OriginalMatchers > 0 {
		report.SkippedMatcherRatio = float64(report.SkippedMatchers) / float64(report.OriginalMatchers)
	}
	return out, report, nil
}
func fingerprintStrings(raw json.RawMessage) ([]string, bool) {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}, true
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many, true
	}
	return nil, false
}
func countUpstreamMatchers(raw json.RawMessage) int {
	var values []json.RawMessage
	if json.Unmarshal(raw, &values) == nil {
		return max(1, len(values))
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) == nil {
		n := 0
		for _, v := range fields {
			n += countUpstreamMatchers(v)
		}
		return max(1, n)
	}
	return 1
}

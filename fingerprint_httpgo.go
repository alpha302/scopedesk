package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// ScopeDesk-authored parser for httpgo's documented rule data, not its executor.
type httpGoToken struct{ kind, value string }
type httpGoParser struct {
	tokens          []httpGoToken
	position, depth int
}

func lexHTTPGo(expression string) ([]httpGoToken, error) {
	tokens := []httpGoToken{}
	for i := 0; i < len(expression); {
		ch := expression[i]
		if strings.ContainsRune(" \t\r\n", rune(ch)) {
			i++
			continue
		}
		if ch == '(' || ch == ')' {
			tokens = append(tokens, httpGoToken{kind: string(ch)})
			i++
			continue
		}
		if i+1 < len(expression) {
			op := expression[i : i+2]
			if slices.Contains([]string{"&&", "||", "!="}, op) {
				tokens = append(tokens, httpGoToken{kind: op})
				i += 2
				continue
			}
		}
		if ch == '=' {
			tokens = append(tokens, httpGoToken{kind: "="})
			i++
			continue
		}
		if ch == '"' {
			i++
			var value strings.Builder
			closed := false
			for i < len(expression) {
				ch = expression[i]
				i++
				if ch == '"' {
					closed = true
					break
				}
				if ch == '\\' {
					if i >= len(expression) {
						return tokens, errors.New("dangling_escape")
					}
					ch = expression[i]
					i++
				}
				value.WriteByte(ch)
			}
			if !closed {
				return tokens, errors.New("unclosed_literal")
			}
			tokens = append(tokens, httpGoToken{kind: "literal", value: value.String()})
			continue
		}
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch == '_' {
			start := i
			i++
			for i < len(expression) {
				ch = expression[i]
				if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch == '_' || ch >= '0' && ch <= '9') {
					break
				}
				i++
			}
			tokens = append(tokens, httpGoToken{kind: "field", value: expression[start:i]})
			continue
		}
		return tokens, errors.New("invalid_character")
	}
	return tokens, nil
}
func (p *httpGoParser) accept(kind string) bool {
	if p.position < len(p.tokens) && p.tokens[p.position].kind == kind {
		p.position++
		return true
	}
	return false
}
func httpGoGroup(kind string, left, right *FingerprintExpression) *FingerprintExpression {
	children := []*FingerprintExpression{}
	for _, node := range []*FingerprintExpression{left, right} {
		if node.Matcher == nil && node.Combination == kind {
			children = append(children, node.Children...)
		} else {
			children = append(children, node)
		}
	}
	return &FingerprintExpression{Combination: kind, Children: children}
}
func (p *httpGoParser) any() (*FingerprintExpression, error) {
	left, err := p.all()
	if err != nil {
		return nil, err
	}
	for p.accept("||") {
		right, e := p.all()
		if e != nil {
			return nil, e
		}
		left = httpGoGroup("any", left, right)
	}
	return left, nil
}
func (p *httpGoParser) all() (*FingerprintExpression, error) {
	left, err := p.primary()
	if err != nil {
		return nil, err
	}
	for p.accept("&&") {
		right, e := p.primary()
		if e != nil {
			return nil, e
		}
		left = httpGoGroup("all", left, right)
	}
	return left, nil
}
func (p *httpGoParser) primary() (*FingerprintExpression, error) {
	if p.accept("(") {
		p.depth++
		if p.depth > 16 {
			return nil, errors.New("nesting_limit")
		}
		node, err := p.any()
		p.depth--
		if err != nil {
			return nil, err
		}
		if !p.accept(")") {
			return nil, errors.New("unbalanced_parentheses")
		}
		return node, nil
	}
	if p.position+2 >= len(p.tokens) {
		return nil, errors.New("missing_condition")
	}
	field, op, value := p.tokens[p.position], p.tokens[p.position+1], p.tokens[p.position+2]
	if field.kind != "field" || !slices.Contains([]string{"=", "!="}, op.kind) || value.kind != "literal" {
		return nil, errors.New("invalid_condition")
	}
	p.position += 3
	matcher := &FingerprintMatcher{Kind: "contains", Pattern: value.value, CaseSensitive: true, Negate: op.kind == "!="}
	if matcher.Pattern == "" {
		return nil, errors.New("empty_condition")
	}
	switch field.value {
	case "body", "title":
		matcher.Field = field.value
	case "header":
		matcher.Field = "header_block"
	case "icon_hash":
		if matcher.Negate {
			return nil, errors.New("unsupported_icon_negation")
		}
		n, err := strconv.ParseInt(matcher.Pattern, 10, 32)
		if err != nil || strconv.FormatInt(n, 10) != matcher.Pattern {
			return nil, errors.New("invalid_icon_hash")
		}
		matcher.Field = "favicon_mmh3"
		matcher.Kind = "exact"
		matcher.Key = "httpgo_legacy"
	case "cert":
		return nil, errors.New("unavailable_full_certificate")
	default:
		return nil, errors.New("unsupported_field")
	}
	if err := compileFingerprintMatcher(matcher); err != nil {
		return nil, errors.New("unsupported_matcher")
	}
	return &FingerprintExpression{Matcher: matcher}, nil
}

func convertHTTPGoData(raw []byte, source fingerprintSourceMetadata) ([]FingerprintRule, fingerprintConversionReport, error) {
	report := fingerprintConversionReport{ConverterVersion: "httpgo-1", SourceFormat: "httpgo", Source: source, ReasonCounts: map[string]int{}, Skipped: []conversionItem{}, Note: "Documented case-sensitive contains, AND/OR precedence, parentheses and negation preserved as an expression tree. Full certificate rules, malformed conditions and branches identifying solely by absence are rejected whole. Duplicate product names with distinct conditions remain distinct rules; exact duplicates are dropped. Compatibility statistics are not measured detection accuracy. For lexical failures, matcher counts cover only the parsed prefix; see rules_with_incomplete_matcher_count."}
	var input []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &input); err != nil {
		return nil, report, err
	}
	if len(input) == 0 {
		return nil, report, errors.New("httpgo 规则数组为空")
	}
	report.OriginalRules = len(input)
	rules := []FingerprintRule{}
	seen := map[string]bool{}
	for index, item := range input {
		name, keyword, kind := "", "", ""
		nameErr := json.Unmarshal(item["name"], &name)
		keywordErr := json.Unmarshal(item["keyword"], &keyword)
		typeErr := json.Unmarshal(item["type"], &kind)
		reasons := []string{}
		tokens, lexErr := lexHTTPGo(keyword)
		original := 0
		for _, token := range tokens {
			if token.kind == "=" || token.kind == "!=" {
				original++
			}
		}
		report.OriginalMatchers += original
		if lexErr != nil {
			report.UnknownMatcherCounts++
			reasons = append(reasons, "invalid_expression:"+lexErr.Error())
		}
		if nameErr != nil || keywordErr != nil || typeErr != nil || name == "" || len(name) > 200 || !slices.Contains([]string{"cms", "other"}, kind) || len(keyword) > 16384 {
			reasons = append(reasons, "invalid_rule_metadata")
		}
		for key := range item {
			if !slices.Contains([]string{"name", "keyword", "type"}, key) {
				reasons = append(reasons, "unsupported_rule_field")
			}
		}
		parser := httpGoParser{tokens: tokens}
		node, parseErr := parser.any()
		if parseErr != nil {
			reasons = append(reasons, "invalid_expression:"+parseErr.Error())
		} else if parser.position != len(tokens) {
			reasons = append(reasons, "trailing_expression_tokens")
		} else {
			leaves := 0
			if err := compileFingerprintExpression(node, 0, &leaves); err != nil {
				reasons = append(reasons, "expression_limit")
			}
			if !expressionRequiresPositive(node) {
				reasons = append(reasons, "absence_only_branch")
			}
		}
		key := name + "\x00" + keyword
		if seen[key] {
			reasons = append(reasons, "duplicate_rule")
		}
		slices.Sort(reasons)
		reasons = slices.Compact(reasons)
		if len(reasons) > 0 {
			if name == "" {
				name = fmt.Sprintf("row-%d", index+1)
			}
			report.Skipped = append(report.Skipped, conversionItem{name, reasons, original})
			for _, reason := range reasons {
				report.ReasonCounts[reason]++
			}
			continue
		}
		seen[key] = true
		sum := sha256.Sum256([]byte(source.Repository + "\x00" + key))
		rules = append(rules, FingerprintRule{ID: "httpgo-" + hex.EncodeToString(sum[:12]), Product: name, Combination: "all", Confidence: 75, Source: source.Repository, Version: source.Commit, License: source.RuleLicense, Expression: node})
		report.ConvertedMatchers += original
	}
	report.ConvertedRules = len(rules)
	report.SkippedRules = report.OriginalRules - len(rules)
	report.SkippedRuleRatio = float64(report.SkippedRules) / float64(report.OriginalRules)
	report.SkippedMatchers = report.OriginalMatchers - report.ConvertedMatchers
	if report.OriginalMatchers > 0 {
		report.SkippedMatcherRatio = float64(report.SkippedMatchers) / float64(report.OriginalMatchers)
	}
	return rules, report, nil
}

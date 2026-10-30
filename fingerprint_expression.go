package main

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// Expressions retain grouping and negation; no DNF expansion or branch dropping.
type FingerprintExpression struct {
	Combination string                   `json:"combination,omitempty" yaml:"combination,omitempty"`
	Children    []*FingerprintExpression `json:"children,omitempty" yaml:"children,omitempty"`
	Matcher     *FingerprintMatcher      `json:"matcher,omitempty" yaml:"matcher,omitempty"`
}

func compileFingerprintExpression(node *FingerprintExpression, depth int, leaves *int) error {
	if node == nil || depth > 16 {
		return fmt.Errorf("指纹表达式为空或嵌套超过 16 层")
	}
	if node.Matcher != nil {
		if len(node.Children) > 0 || node.Combination != "" {
			return fmt.Errorf("表达式叶子不能包含分组")
		}
		*leaves++
		if *leaves > 64 {
			return fmt.Errorf("表达式超过 64 个条件")
		}
		return compileFingerprintMatcher(node.Matcher)
	}
	if !slices.Contains([]string{"all", "any"}, node.Combination) || len(node.Children) < 2 || len(node.Children) > 64 {
		return fmt.Errorf("表达式分组无效")
	}
	for _, child := range node.Children {
		if err := compileFingerprintExpression(child, depth+1, leaves); err != nil {
			return err
		}
	}
	return nil
}

// A successful rule must always have some positive identifying evidence.
// An OR branch consisting solely of absence must not identify a product.
func expressionRequiresPositive(node *FingerprintExpression) bool {
	if node.Matcher != nil {
		return !node.Matcher.Negate
	}
	if node.Combination == "all" {
		for _, child := range node.Children {
			if expressionRequiresPositive(child) {
				return true
			}
		}
		return false
	}
	for _, child := range node.Children {
		if !expressionRequiresPositive(child) {
			return false
		}
	}
	return true
}

type fingerprintInputs struct {
	observation Observation
	body        string
	headers     string
	meta        map[string][]string
	scripts     []string
}

func newFingerprintInputs(o Observation) fingerprintInputs {
	inputs := fingerprintInputs{observation: o, body: string(o.httpBody)}
	inputs.meta, inputs.scripts = passiveHTMLFeatures(o.httpBody)
	keys := make([]string, 0, len(o.httpHeaders))
	for key := range o.httpHeaders {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	var headers strings.Builder
	for _, key := range keys {
		for _, value := range o.httpHeaders[key] {
			headers.WriteString(key + ": " + value + "\n")
		}
	}
	inputs.headers = headers.String()
	return inputs
}

func (in fingerprintInputs) match(m FingerprintMatcher) (bool, bool, *FingerprintMatch) {
	o := in.observation
	values := []string{}
	known := true
	switch m.Field {
	case "title":
		values = []string{o.Title}
		if m.Negate {
			known = o.httpTitleComplete
		}
	case "server":
		values = []string{o.Server}
		known = o.httpHeaders != nil
	case "tls_subject":
		values = []string{o.TLSSubject}
		known = o.TLSNotAfter != nil || o.TLSSubject != ""
	case "body":
		values = []string{in.body}
		if m.Negate {
			known = o.httpBodyComplete
		}
	case "header_block":
		values = []string{in.headers}
		known = o.httpHeaders != nil
	case "meta":
		values = in.meta[strings.ToLower(m.Key)]
		if m.Negate {
			known = o.httpBodyComplete
		}
	case "script_src":
		values = in.scripts
		if m.Negate {
			known = o.httpBodyComplete
		}
	case "header":
		values = o.httpHeaders.Values(m.Key)
		known = o.httpHeaders != nil
	case "cookie":
		known = o.httpHeaders != nil
		for _, cookie := range (&http.Response{Header: o.httpHeaders}).Cookies() {
			if strings.EqualFold(cookie.Name, m.Key) {
				values = append(values, cookie.Value)
			}
		}
	case "favicon_mmh3":
		hash := o.FaviconMMH3
		if m.Key == "httpgo_legacy" {
			hash = o.httpgoFaviconMMH3
		}
		if hash != nil {
			values = []string{strconv.FormatInt(int64(*hash), 10)}
		} else {
			known = false
		}
	}
	if !known {
		return false, false, nil
	}
	hit := false
	matched := ""
	for _, value := range values {
		if value == "" && m.Pattern != "" {
			continue
		}
		switch m.Kind {
		case "regex":
			loc := m.compiled.FindStringIndex(value)
			if loc != nil {
				hit = true
				matched = value[loc[0]:loc[1]]
			}
		case "contains":
			if m.CaseSensitive {
				hit = strings.Contains(value, m.Pattern)
			} else {
				hit = strings.Contains(strings.ToLower(value), strings.ToLower(m.Pattern))
			}
			matched = m.Pattern
		case "exact":
			if m.CaseSensitive {
				hit = value == m.Pattern
			} else {
				hit = strings.EqualFold(value, m.Pattern)
			}
			matched = value
		}
		if hit {
			break
		}
	}
	if m.Negate {
		hit = !hit
		matched = "[absent from measured field]"
	}
	if !hit {
		return false, true, nil
	}
	if m.Field == "cookie" || m.Field == "header_block" || m.Field == "header" && !slices.Contains([]string{"server", "x-powered-by"}, strings.ToLower(m.Key)) {
		matched = "[redacted]"
	}
	evidence := &FingerprintMatch{Field: m.Field, Key: m.Key, Pattern: m.Pattern, Value: boundedFingerprintText(matched, 256), Negated: m.Negate}
	return true, true, evidence
}

func (in fingerprintInputs) evaluate(node *FingerprintExpression) (bool, bool, []FingerprintMatch) {
	if node.Matcher != nil {
		hit, known, ev := in.match(*node.Matcher)
		if ev != nil {
			return hit, known, []FingerprintMatch{*ev}
		}
		return hit, known, nil
	}
	matches := []FingerprintMatch{}
	unknown := false
	anyHit := false
	for _, child := range node.Children {
		hit, known, evidence := in.evaluate(child)
		if !known {
			unknown = true
			continue
		}
		if node.Combination == "all" && !hit {
			return false, true, nil
		}
		if hit {
			anyHit = true
			matches = append(matches, evidence...)
		}
	}
	if node.Combination == "any" {
		if anyHit {
			return true, true, matches
		}
		return false, !unknown, nil
	}
	if unknown {
		return false, false, nil
	}
	return true, true, matches
}

func (in fingerprintInputs) matchRule(rule FingerprintRule) (bool, []FingerprintMatch) {
	if rule.Expression != nil {
		hit, known, evidence := in.evaluate(rule.Expression)
		return hit && known, evidence
	}
	matches := []FingerprintMatch{}
	for _, matcher := range rule.Matchers {
		hit, known, evidence := in.match(matcher)
		if rule.Combination == "all" && (!known || !hit) {
			return false, nil
		}
		if hit {
			matches = append(matches, *evidence)
		}
	}
	return len(matches) > 0, matches
}

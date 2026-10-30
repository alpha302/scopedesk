package main

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

// Added now; execution is deferred with the functional regression suite.
func TestHTTPGoGroupingCaseAndUnknownNegation(t *testing.T) {
	expression := `body="Product" && (title="Console" || header="Server: vendor") && body!="maintenance"`
	tokens, err := lexHTTPGo(expression)
	if err != nil {
		t.Fatal(err)
	}
	parser := httpGoParser{tokens: tokens}
	node, err := parser.any()
	if err != nil || parser.position != len(tokens) {
		t.Fatal("expression not fully parsed", err)
	}
	leaves := 0
	if err = compileFingerprintExpression(node, 0, &leaves); err != nil {
		t.Fatal(err)
	}
	observation := Observation{Title: "Console", httpBody: []byte("Product ready"), httpBodyComplete: true, httpTitleComplete: true, httpHeaders: http.Header{}}
	hit, known, _ := newFingerprintInputs(observation).evaluate(node)
	if !hit || !known {
		t.Fatal("grouped positive case failed")
	}
	observation.httpBodyComplete = false
	hit, known, _ = newFingerprintInputs(observation).evaluate(node)
	if hit || known {
		t.Fatal("truncated body must not prove absence")
	}
	observation.httpBodyComplete = true
	observation.httpBody = []byte("product ready")
	hit, _, _ = newFingerprintInputs(observation).evaluate(node)
	if hit {
		t.Fatal("httpgo literals are case-sensitive")
	}
	observation.httpBody = []byte("Product maintenance")
	hit, _, _ = newFingerprintInputs(observation).evaluate(node)
	if hit {
		t.Fatal("negated condition was dropped")
	}
}

func TestHTTPGoConversionRejectsWholeRuleAndPreservesVariants(t *testing.T) {
	raw := []byte(`[
 {"name":"A","keyword":"body=\"Product\" && (title=\"UI\" || header=\"Server: vendor\")","type":"cms"},
 {"name":"A","keyword":"body=\"Variant\"","type":"cms"},
 {"name":"bad-cert","keyword":"body=\"Product\" || cert=\"Issuer\"","type":"cms"},
 {"name":"absence","keyword":"body=\"Product\" || title!=\"Other\"","type":"cms"},
 {"name":"malformed","keyword":"body=\"Product\" &&","type":"cms"},
 {"name":"quoted","keyword":"body=\"A&&B\"","type":"cms"}
 ]`)
	rules, report, err := convertHTTPGoData(raw, fingerprintSourceMetadata{Repository: "httpgo", Commit: strings.Repeat("0", 40), RuleLicense: "project-permission"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 || report.ConvertedRules != 3 || report.SkippedRules != 3 {
		t.Fatalf("unexpected conversion counts: %+v", report)
	}
	if rules[0].Product != "A" || rules[1].Product != "A" || rules[0].ID == rules[1].ID {
		t.Fatal("product variants must retain independent conditions")
	}
	if rules[2].Expression.Matcher.Pattern != "A&&B" {
		t.Fatal("logical characters inside a quoted literal were split")
	}
}

func TestHTTPGoIconBoundaryAndZero(t *testing.T) {
	body := make([]byte, 57) // base64 is exactly 76 bytes; httpgo appends two line feeds.
	encoded := base64.StdEncoding.EncodeToString(body)
	standard, _ := faviconHashes(body)
	legacy := faviconHTTPGoHash(body)
	if standard != murmur3Signed([]byte(encoded+"\n")) || legacy != murmur3Signed([]byte(encoded+"\n\n")) || standard == legacy {
		t.Fatal("hash conventions were conflated")
	}
	matcher := FingerprintMatcher{Field: "favicon_mmh3", Key: "httpgo_legacy", Kind: "exact", Pattern: "0", CaseSensitive: true}
	if err := compileFingerprintMatcher(&matcher); err != nil {
		t.Fatal(err)
	}
	inputs := newFingerprintInputs(Observation{FaviconMMH3: ptr(int32(123)), httpgoFaviconMMH3: ptr(int32(0))})
	hit, known, _ := inputs.match(matcher)
	if !hit || !known {
		t.Fatal("legacy zero hash must remain valid")
	}
	inputs = newFingerprintInputs(Observation{FaviconMMH3: ptr(int32(0))})
	hit, known, _ = inputs.match(matcher)
	if hit || known {
		t.Fatal("standard hash is not evidence for a missing legacy hash")
	}
}

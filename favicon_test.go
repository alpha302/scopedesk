package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func faviconPNG() []byte {
	b, _ := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aQFAAAAAASUVORK5CYII=")
	return b
}

func TestFaviconKnownHashVectors(t *testing.T) {
	// Independently checked with Python mmh3 5.2.1 + base64.encodebytes.
	data := make([]byte, 120)
	for i := range data {
		data[i] = byte(i)
	}
	for _, tc := range []struct {
		body []byte
		mmh  int32
		sha  string
	}{
		{[]byte("hello"), 1155597304, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
		{data, 2070964735, "f52b23db1fbb6ded89ef42a23ce0c8922c45f25c50b568a93bf1c075420bbb7c"},
		{faviconPNG(), -1607103925, "013dd20d64985832a0477794ac755032ef2ab31b63c1f879edf3576dfc29bd2f"},
	} {
		m, s := faviconHashes(tc.body)
		if m != tc.mmh || s != tc.sha {
			t.Fatal("hash/vector or base64 line convention", m, s)
		}
	}
	for _, tc := range []struct {
		text string
		want int32
	}{{"", 0}, {"foo", -156908512}, {"hello", 613153351}} {
		if got := murmur3Signed([]byte(tc.text)); got != tc.want {
			t.Fatal("raw murmur vector", tc, got)
		}
	}
}

func TestFaviconMagicAndSize(t *testing.T) {
	ico := make([]byte, 23)
	copy(ico, []byte{0, 0, 1, 0, 1, 0})
	binary.LittleEndian.PutUint32(ico[14:18], 1)
	binary.LittleEndian.PutUint32(ico[18:22], 22)
	webp := []byte("RIFF\x0c\x00\x00\x00WEBPVP8L\x00\x00\x00\x00")
	for _, body := range [][]byte{faviconPNG(), ico, append([]byte("GIF89a"), make([]byte, 7)...), {0xff, 0xd8, 0xff, 0xe0, 0xff, 0xd9}, webp, []byte("<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"></svg>")} {
		if !validFavicon(body) {
			t.Fatal("supported signature rejected", body[:min(12, len(body))])
		}
	}
	for _, body := range [][]byte{nil, []byte("<html><title>login</title></html>"), []byte("<html><svg/></html>"), []byte("<svg-bogus/>"), []byte("<svg>"), []byte("<!DOCTYPE svg SYSTEM 'https://outside.net/'><svg/>"), []byte("<svg xmlns='wrong'/>"), bytes.Repeat([]byte("x"), maxFaviconBytes+1)} {
		if validFavicon(body) {
			t.Fatal("invalid/oversized content accepted")
		}
	}
	boundary := append([]byte("<svg><!--"), bytes.Repeat([]byte("x"), maxFaviconBytes-len("<svg><!----></svg>"))...)
	boundary = append(boundary, []byte("--></svg>")...)
	if len(boundary) != maxFaviconBytes || !validFavicon(boundary) || validFavicon(append(boundary, ' ')) {
		t.Fatal("256 KB boundary")
	}
}

func TestFaviconSelectionAndAuthority(t *testing.T) {
	base, _ := url.Parse("http://api.example.com:80/a/page")
	for _, tc := range []struct{ html, want string }{
		{`<link rel="apple-touch-icon" href="/apple.png"><link rel="shortcut icon" href="/a.png?v=1"><link rel="icon" href="/b.png">`, "http://api.example.com:80/a.png?v=1"},
		{`<link rel=icon href="first.png"><link rel=icon href="second.png">`, "http://api.example.com:80/a/first.png"},
		{`<link rel=icon href="data:image/png;base64,AAAA"><link rel=icon href="//outside.net/icon"><link rel=apple-touch-icon href="/apple.png">`, "http://api.example.com:80/apple.png"},
		{`<link rel=icon href="http://api.example.com:443/icon">`, ""},
	} {
		got := declaredFavicon([]byte(tc.html), base)
		if tc.want == "" {
			if got != nil {
				t.Fatal(got)
			}
		} else if got == nil || got.String() != tc.want {
			t.Fatal("selection", got, tc.want)
		}
	}
	for _, tc := range []struct {
		from, to string
		allowed  bool
	}{
		{"http://api.example.com/a", "https://api.example.com/b", true},
		{"http://api.example.com:80/a", "http://API.example.com/b", true},
		{"https://api.example.com/a", "http://api.example.com/b", false},
		{"https://api.example.com/a", "https://child.api.example.com/b", false},
		{"https://api.example.com/a", "https://api.example.com:80/b", false},
		{"https://api.example.com/a", "https://user:secret@api.example.com/b", false},
		{"https://api.example.com/a", "data:image/png;base64,AAAA", false},
	} {
		a, _ := url.Parse(tc.from)
		b, _ := url.Parse(tc.to)
		if sameFaviconAuthority(a, b) != tc.allowed {
			t.Fatal("authority policy", tc)
		}
	}
}

type faviconRoundTrip func(*http.Request) (*http.Response, error)

func (f faviconRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type faviconLimit struct{ calls int }

func (l *faviconLimit) Wait(context.Context, int64, float64) error { l.calls++; return nil }

func faviconPipeline(handler http.HandlerFunc) (*Pipeline, *ScopeV2, *faviconLimit) {
	s := sampleScope()
	s.Active = true
	limit := &faviconLimit{}
	p := &Pipeline{Limit: limit, Guard: func(context.Context, int64) (ScopeGuard, error) { return ScopeGuard{Scope: s}, nil }}
	p.httpTransport = faviconRoundTrip(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		handler(w, r)
		res := w.Result()
		res.Request = r
		return res, nil
	})
	return p, &s, limit
}

func TestFaviconRequestsFallbackRedirectAndScope(t *testing.T) {
	for _, mode := range []string{"declared", "fallback", "no-declaration", "cross-host", "upgrade", "chain-limit", "revoked", "oversized", "budget", "html-image-type"} {
		t.Run(mode, func(t *testing.T) {
			requests := []string{}
			var scope *ScopeV2
			p, s, limit := faviconPipeline(func(w http.ResponseWriter, r *http.Request) {
				requests = append(requests, r.URL.String())
				if mode == "revoked" {
					scope.Confirmed = false
					http.Redirect(w, r, "/after", 302)
					return
				}
				if mode == "cross-host" {
					http.Redirect(w, r, "https://child.api.example.com/icon", 302)
					return
				}
				if mode == "upgrade" && r.URL.Scheme == "http" {
					http.Redirect(w, r, "https://api.example.com/icon", 301)
					return
				}
				if mode == "chain-limit" {
					http.Redirect(w, r, "/next", 302)
					return
				}
				if mode == "oversized" {
					w.Write(append(faviconPNG(), bytes.Repeat([]byte("x"), maxFaviconBytes)...))
					return
				}
				if mode == "html-image-type" || (mode == "fallback" && r.URL.Path != "/favicon.ico") {
					w.Header().Set("Content-Type", "image/png")
					w.Write([]byte("<html>login</html>"))
					return
				}
				w.Header().Set("Content-Type", "text/plain")
				w.Write(faviconPNG())
			})
			scope = s
			// The guard reads the current test scope on every request boundary.
			p.Guard = func(context.Context, int64) (ScopeGuard, error) { return ScopeGuard{Scope: *s}, nil }
			base, _ := url.Parse("http://api.example.com/")
			page := Observation{httpURL: base, httpBody: []byte(`<link rel=icon href="/icon?v=1">`)}
			if mode == "no-declaration" {
				page.httpBody = nil
			}
			b := &Budget{Limit: 10}
			if mode == "budget" {
				b.Limit = 1
				page.httpBody = []byte(`<link rel=icon href="/icon">`)
				p.httpTransport = faviconRoundTrip(func(r *http.Request) (*http.Response, error) {
					requests = append(requests, r.URL.String())
					return &http.Response{StatusCode: 404, Body: http.NoBody, Header: http.Header{}, Request: r}, nil
				})
			}
			mmh, sha, _ := p.collectFavicon(context.Background(), *s, page, b)
			want := 1
			if mode == "fallback" || mode == "upgrade" || mode == "chain-limit" || mode == "oversized" || mode == "html-image-type" || mode == "cross-host" {
				want = 2
			}
			if len(requests) != want || limit.calls != want || b.Used > 2 {
				t.Fatal("request/redirect budget", mode, requests, b.Used, limit.calls)
			}
			success := mode == "declared" || mode == "fallback" || mode == "no-declaration" || mode == "upgrade"
			if success {
				if mmh == nil || *mmh != -1607103925 || sha == nil {
					t.Fatal("valid icon missing", mmh, sha)
				}
			} else if mmh != nil || sha != nil {
				t.Fatal("unsafe image accepted", mode)
			}
		})
	}
}

func TestFaviconProviderAndLegacyAreNotFacts(t *testing.T) {
	m := observerMapping(PluginManifest{Name: "provider"})
	m.Exec.MaxOutput = 8000000
	m.Output.Format = "jsonl"
	m.Output.Mapping["favicon_sha256"] = "favicon_sha256"
	result := PluginResult{}
	if err := parsePluginStream(context.Background(), strings.NewReader(`{"host":"api.example.com","port":443,"favicon_sha256":"`+strings.Repeat("a", 64)+`"}`), m, func(context.Context) (ScopeGuard, error) { return ScopeGuard{Scope: sampleScope()}, nil }, &result); err != nil {
		t.Fatal(err)
	}
	o := result.Records[0].Observation
	if o.Favicon != "" || o.FaviconSHA256 != nil || o.FaviconMMH3 != nil || o.Services[0].FaviconSHA256 != nil || o.PluginEvidence[0].Fields["favicon_sha256"] != strings.Repeat("a", 64) {
		t.Fatal("provider hash promoted", o)
	}
	old := legacyService(Observation{StatusCode: 200, Favicon: strings.Repeat("b", 64)})
	if old[0].FaviconSHA256 != nil {
		t.Fatal("unverified legacy hash promoted")
	}
	zero := legacyService(Observation{StatusCode: 200, FaviconMMH3: ptr(int32(0)), FaviconSHA256: ptr(strings.Repeat("c", 64)), FaviconMeasured: true})
	if zero[0].FaviconMMH3 == nil || *zero[0].FaviconMMH3 != 0 || !zero[0].FaviconMeasured {
		t.Fatal("zero hash lost")
	}
	raw, _ := json.Marshal(Observation{FaviconMMH3: ptr(int32(0)), httpBody: []byte("private raw body")})
	if !strings.Contains(string(raw), `"favicon_mmh3":0`) || strings.Contains(string(raw), "private raw body") {
		t.Fatal("JSON zero or ephemeral body", string(raw))
	}
}

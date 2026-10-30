package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"math/bits"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/html"
)

const maxFaviconBytes = 256 * 1024

// Raw MurmurHash3 x86_32 with seed zero, exposed as a signed 32-bit value.
func murmur3Signed(data []byte) int32 {
	var h uint32
	n := len(data)
	for len(data) >= 4 {
		k := binary.LittleEndian.Uint32(data)
		k *= 0xcc9e2d51
		k = bits.RotateLeft32(k, 15)
		k *= 0x1b873593
		h ^= k
		h = bits.RotateLeft32(h, 13)*5 + 0xe6546b64
		data = data[4:]
	}
	var k uint32
	for i, v := range data {
		k |= uint32(v) << (8 * i)
	}
	if len(data) > 0 {
		k *= 0xcc9e2d51
		k = bits.RotateLeft32(k, 15)
		k *= 0x1b873593
		h ^= k
	}
	h ^= uint32(n)
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return int32(h)
}

func faviconHashes(body []byte) (int32, string) {
	encoded := base64.StdEncoding.EncodeToString(body)
	var wrapped strings.Builder
	for len(encoded) > 0 {
		n := min(76, len(encoded))
		wrapped.WriteString(encoded[:n])
		wrapped.WriteByte('\n')
		encoded = encoded[n:]
	}
	sum := sha256.Sum256(body)
	return murmur3Signed([]byte(wrapped.String())), hex.EncodeToString(sum[:])
}

func validFavicon(body []byte) bool {
	if len(body) == 0 || len(body) > maxFaviconBytes {
		return false
	}
	if bytes.HasPrefix(body, []byte("\x89PNG\r\n\x1a\n")) && len(body) >= 24 && string(body[12:16]) == "IHDR" {
		return true
	}
	if len(body) >= 22 && bytes.Equal(body[:4], []byte{0, 0, 1, 0}) {
		count := int(binary.LittleEndian.Uint16(body[4:6]))
		if count < 1 || count > (len(body)-6)/16 {
			return false
		}
		for i := 0; i < count; i++ {
			entry := body[6+i*16 : 22+i*16]
			size := uint64(binary.LittleEndian.Uint32(entry[8:12]))
			offset := uint64(binary.LittleEndian.Uint32(entry[12:16]))
			if size == 0 || offset < uint64(6+count*16) || offset+size > uint64(len(body)) {
				return false
			}
		}
		return true
	}
	if len(body) >= 13 && (bytes.HasPrefix(body, []byte("GIF87a")) || bytes.HasPrefix(body, []byte("GIF89a"))) {
		return true
	}
	if len(body) >= 4 && bytes.HasPrefix(body, []byte{0xff, 0xd8, 0xff}) && bytes.HasSuffix(body, []byte{0xff, 0xd9}) {
		return true
	}
	if len(body) >= 20 && string(body[:4]) == "RIFF" && string(body[8:12]) == "WEBP" && uint64(binary.LittleEndian.Uint32(body[4:8]))+8 == uint64(len(body)) && (string(body[12:16]) == "VP8 " || string(body[12:16]) == "VP8L" || string(body[12:16]) == "VP8X") {
		return true
	}
	// Parse XML only; never render SVG, execute scripts, or load external resources.
	decoder := xml.NewDecoder(bytes.NewReader(bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf})))
	depth := 0
	root := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return root && depth == 0
		}
		if err != nil {
			return false
		}
		switch token := token.(type) {
		case xml.StartElement:
			if depth == 0 {
				if root || token.Name.Local != "svg" || (token.Name.Space != "" && token.Name.Space != "http://www.w3.org/2000/svg") {
					return false
				}
				root = true
			}
			depth++
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && len(bytes.TrimSpace(token)) > 0 {
				return false
			}
		case xml.Directive:
			return false
		}
	}
}

func effectiveHTTPPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil {
			return ""
		}
		return strconv.Itoa(n)
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func sameFaviconAuthority(from, to *url.URL) bool {
	if from == nil || to == nil || to.User != nil || (to.Scheme != "http" && to.Scheme != "https") {
		return false
	}
	a, err := normalizeHost(from.Hostname())
	if err != nil {
		return false
	}
	b, err := normalizeHost(to.Hostname())
	if err != nil || a != b {
		return false
	}
	if from.Scheme == "https" && to.Scheme == "http" {
		return false
	}
	aPort, bPort := effectiveHTTPPort(from), effectiveHTTPPort(to)
	return aPort == bPort || (from.Scheme == "http" && aPort == "80" && to.Scheme == "https" && bPort == "443")
}

func declaredFavicon(page []byte, base *url.URL) *url.URL {
	z := html.NewTokenizer(bytes.NewReader(page))
	var apple *url.URL
	for {
		token := z.Next()
		if token == html.ErrorToken {
			return apple
		}
		if token != html.StartTagToken && token != html.SelfClosingTagToken {
			continue
		}
		t := z.Token()
		if t.Data != "link" {
			continue
		}
		var rel, href string
		for _, a := range t.Attr {
			switch a.Key {
			case "rel":
				rel = strings.ToLower(a.Val)
			case "href":
				href = a.Val
			}
		}
		words := strings.Fields(rel)
		icon, ios := false, false
		for _, word := range words {
			icon = icon || word == "icon"
			ios = ios || word == "apple-touch-icon"
		}
		if (!icon && !ios) || href == "" {
			continue
		}
		relative, err := url.Parse(strings.TrimSpace(href))
		if err != nil {
			continue
		}
		u := base.ResolveReference(relative)
		u.Fragment = ""
		if !sameFaviconAuthority(base, u) {
			continue
		}
		if icon {
			return u
		}
		if apple == nil {
			apple = u
		}
	}
}

type faviconFetchPolicy struct {
	origin    *url.URL
	remaining int
}

func (f *faviconFetchPolicy) allow(target, previous *url.URL) error {
	if f.remaining <= 0 {
		return errors.New("图标 HTTP 请求次数已达上限")
	}
	if !sameFaviconAuthority(f.origin, target) || !sameFaviconAuthority(previous, target) {
		return errors.New("图标跨主机、跨端口或降级重定向被拒绝")
	}
	f.remaining--
	return nil
}

func (p *Pipeline) collectFavicon(ctx context.Context, scope ScopeV2, page Observation, b *Budget) (mmh *int32, sha *string, checked bool) {
	mmh, sha, _, checked = p.collectFaviconDetailed(ctx, scope, page, b)
	return
}

// httpgo's pinned encoder appends an extra trailing newline at a 76-byte boundary.
// This compatibility value is ephemeral; standard favicon_mmh3 facts stay unchanged.
func faviconHTTPGoHash(body []byte) int32 {
	encoded := base64.StdEncoding.EncodeToString(body)
	var wrapped strings.Builder
	for i := range len(encoded) {
		wrapped.WriteByte(encoded[i])
		if (i+1)%76 == 0 {
			wrapped.WriteByte('\n')
		}
	}
	wrapped.WriteByte('\n')
	return murmur3Signed([]byte(wrapped.String()))
}
func (p *Pipeline) collectFaviconDetailed(ctx context.Context, scope ScopeV2, page Observation, b *Budget) (mmh *int32, sha *string, legacy *int32, checked bool) {
	if page.httpURL == nil {
		return nil, nil, nil, false
	}
	policy := &faviconFetchPolicy{origin: page.httpURL, remaining: 2}
	declared := declaredFavicon(page.httpBody, page.httpURL)
	fallback := page.httpURL.ResolveReference(&url.URL{Path: "/favicon.ico"})
	targets := []*url.URL{}
	if declared != nil {
		targets = append(targets, declared)
	}
	if declared == nil || declared.String() != fallback.String() {
		targets = append(targets, fallback)
	}
	for _, target := range targets {
		if ctx.Err() != nil || policy.remaining <= 0 {
			break
		}
		image, err := p.httpURL(ctx, scope, target, b, policy)
		if err != nil {
			continue
		}
		checked = true
		if image.StatusCode != 200 || !validFavicon(image.httpBody) {
			continue
		}
		h, s := faviconHashes(image.httpBody)
		return ptr(h), ptr(s), ptr(faviconHTTPGoHash(image.httpBody)), true
	}
	return nil, nil, nil, checked
}

func validateFaviconQuery(q urlQuery) error {
	if raw := q.Get("favicon_mmh3"); raw != "" {
		if _, err := strconv.ParseInt(raw, 10, 32); err != nil {
			return errors.New("favicon_mmh3 须为有符号 32 位整数")
		}
	}
	if raw := q.Get("favicon_sha256"); raw != "" {
		b, err := hex.DecodeString(raw)
		if err != nil || len(b) != 32 {
			return errors.New("favicon_sha256 须为 64 位十六进制字符串")
		}
	}
	return nil
}

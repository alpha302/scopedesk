package main

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestServiceValidationAndLegacyProjection(t *testing.T) {
	for _, s := range []ServiceObservation{{Port: 0}, {Port: 65536}, {Port: 80, Protocol: "icmp"}, {Port: 80, IP: "garbage"}, {Port: 80, Fingerprints: json.RawMessage(`{}`)}, {Port: 80, Fingerprints: json.RawMessage(`null`)}, {Port: 80, MissCount: ptr(-1)}} {
		if _, err := validateService(s); err == nil {
			t.Fatalf("invalid service accepted: %+v", s)
		}
	}
	s, err := validateService(ServiceObservation{Port: 443, Protocol: "TCP", IP: "::ffff:8.8.8.8"})
	if err != nil || s.Protocol != "tcp" || s.IP != "8.8.8.8" {
		t.Fatal("normalization")
	}
	old := Observation{Title: "keep title", Favicon: "keep hash", Security: true, SecurityRule: "vpn"}
	o := Observation{Services: []ServiceObservation{{Port: 8443, StatusCode: ptr(200), Server: ptr("new server"), Fingerprints: json.RawMessage(`[{"name":"Grafana","source":"rule"},"nginx"]`)}, {Port: 443, StatusCode: ptr(201)}}}
	projectService(&o, old)
	if o.Port != 443 || o.Title != old.Title || o.Favicon != old.Favicon || !o.Security || o.Alive == nil || !*o.Alive {
		t.Fatalf("projection %+v", o)
	}
	o = Observation{Services: []ServiceObservation{{Port: 8443, StatusCode: ptr(200), Fingerprints: json.RawMessage(`[{"name":"Grafana"},"nginx"]`)}}}
	projectService(&o, old)
	if strings.Join(o.Fingerprints, ",") != "Grafana,nginx" {
		t.Fatal("legacy fingerprint shape")
	}
	legacy := legacyService(Observation{StatusCode: 200, TLSSubject: "CN=fixture", Favicon: "", IPs: []string{"8.8.8.8"}})
	if len(legacy) != 1 || legacy[0].Port != 443 || *legacy[0].Scheme != "https" || legacy[0].FaviconSHA256 != nil || legacy[0].FaviconMMH3 != nil {
		t.Fatal("legacy service inference")
	}
	if len(legacyService(Observation{Host: "dns.example.com"})) != 0 {
		t.Fatal("invented HTTP service")
	}
}
func TestServiceGroupingAndSameRowFilters(t *testing.T) {
	input := []Observation{
		{Host: "API.example.com", Sources: []string{"a"}, IPs: []string{"8.8.8.8"}, StatusCode: 200, Port: 80, Alive: ptr(false), DNSChecked: true},
		{Host: "api.example.com", Sources: []string{"b", "a"}, IPs: []string{"1.1.1.1"}, StatusCode: 200, Port: 443, Alive: ptr(true)},
	}
	grouped := groupObservations(input)
	if len(grouped) != 1 || len(grouped[0].Services) != 2 || len(grouped[0].Sources) != 2 || !*grouped[0].Alive || !grouped[0].DNSChecked || grouped[0].Port != 443 {
		t.Fatalf("group=%+v", grouped)
	}
	where, args := assetWhere(User{ID: 7, Role: "user"}, url.Values{"port": {"443"}, "service": {"https"}})
	if strings.Count(where, "EXISTS(") != 1 || !strings.Contains(where, "svc.port=$3 AND svc.service=$4") || len(args) != 4 {
		t.Fatal("different-row service filter", where, args)
	}
	_, args = assetWhere(User{}, url.Values{"port": {"443 OR true"}})
	if args[len(args)-1] != -1 {
		t.Fatal("invalid port accepted")
	}
}

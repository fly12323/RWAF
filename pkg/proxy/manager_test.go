package proxy

import (
	"reflect"
	"testing"
)

func TestDomainNormalizationAndRejectAmbiguousInputs(t *testing.T) {
	values, err := NormalizeDomains(`["EXAMPLE.COM.","example.com","","bücher.example"]`)
	if err != nil || !reflect.DeepEqual(values, []string{"example.com", "xn--bcher-kva.example"}) {
		t.Fatal(values, err)
	}
	for _, invalid := range []string{`["https://example.com"]`, `["example.com:443"]`, `["*.example.com"]`, `["bad_name.test"]`, `["-bad.test"]`, `["a..test"]`, `"example.com"`} {
		if _, err := NormalizeDomains(invalid); err == nil {
			t.Fatalf("accepted %s", invalid)
		}
	}
	if value, err := requestHost("EXAMPLE.COM.:443"); err != nil || value != "example.com" {
		t.Fatal(value, err)
	}
}

func TestSharedPortNamedRouteAndDefault(t *testing.T) {
	manager := NewProxyManager(nil)
	manager.portSites[9000] = map[uint]*siteRoute{1: {id: 1, domains: []string{}}, 2: {id: 2, domains: []string{"two.test"}}, 3: {id: 3, domains: []string{"three.test"}}}
	for _, tc := range []struct {
		host string
		want uint
	}{{"two.test", 2}, {"three.test", 3}, {"unknown.test", 1}} {
		if route := manager.routeLocked(9000, tc.host); route == nil || route.id != tc.want {
			t.Fatal(tc, route)
		}
	}
	delete(manager.portSites[9000], 1)
	if manager.routeLocked(9000, "unknown.test") != nil {
		t.Fatal("unknown domain was routed to arbitrary site")
	}
}

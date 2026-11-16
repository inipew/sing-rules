package main

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestParseCIDRsCanonicalizesAndDropsInvalid(t *testing.T) {
	got, invalid := parseCIDRs([]string{
		"192.0.2.1/24", "192.0.2.0/24", "2001:db8::1/32", "not-a-cidr",
	})
	if invalid != 1 { t.Fatalf("invalid = %d, want 1", invalid) }
	want := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	if !reflect.DeepEqual(got, want) { t.Fatalf("got %v, want %v", got, want) }
}

func TestCollapseMergesSiblingNetworks(t *testing.T) {
	input := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/25"),
		netip.MustParsePrefix("192.0.2.128/25"),
		netip.MustParsePrefix("2001:db8::/33"),
		netip.MustParsePrefix("2001:db8:8000::/33"),
	}
	got := collapse(input)
	want := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	if !reflect.DeepEqual(got, want) { t.Fatalf("got %v, want %v", got, want) }
}

func TestCollapseDropsCoveredNetworks(t *testing.T) {
	got := collapse([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("10.1.0.0/16"),
		netip.MustParsePrefix("192.0.2.0/24"),
	})
	want := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.0.2.0/24")}
	if !reflect.DeepEqual(got, want) { t.Fatalf("got %v, want %v", got, want) }
}

func TestValidateMetaCubeXGeoIP(t *testing.T) {
	valid := []byte(`{"version":2,"rules":[{"ip_cidr":["1.2.3.0/24"]}]}`)
	if err := validateDownload("geoip-id.json", valid); err != nil { t.Fatalf("valid source rejected: %v", err) }
	invalid := []byte(`{"version":2,"rules":[{"domain":["example.com"]}]}`)
	if err := validateDownload("geoip-id.json", invalid); err == nil { t.Fatal("expected missing ip_cidr error") }
}

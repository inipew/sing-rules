package main

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestParsePrefixesCanonicalizesAndDropsInvalid(t *testing.T) {
	got, invalid, err := parsePrefixes([]string{
		"192.0.2.1/24",
		"192.0.2.0/24",
		"2001:db8::1/32",
		"not-a-cidr",
	})
	if err != nil {
		t.Fatalf("parsePrefixes() error = %v", err)
	}
	if invalid != 1 {
		t.Fatalf("invalid = %d, want 1", invalid)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("prefixes = %v, want %v", got, want)
	}
}

func TestCollapsePrefixesRemovesCoveredNetworks(t *testing.T) {
	input := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("10.1.0.0/16"),
		netip.MustParsePrefix("192.0.2.0/24"),
	}
	got := collapsePrefixes(input)
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.0.2.0/24"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("collapsePrefixes() = %v, want %v", got, want)
	}
}

func TestValidateDownloadedGeoIPSchema(t *testing.T) {
	valid := []byte(`{"version":2,"rules":[{"ip_cidr":["1.2.3.0/24"]}]}`)
	if err := validateDownloaded("geoip-id.json", valid); err != nil {
		t.Fatalf("valid MetaCubeX GeoIP rejected: %v", err)
	}
	invalid := []byte(`{"version":2,"rules":[{"domain":["example.com"]}]}`)
	if err := validateDownloaded("geoip-id.json", invalid); err == nil {
		t.Fatal("expected missing ip_cidr to be rejected")
	}
}

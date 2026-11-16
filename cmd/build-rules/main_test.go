package main

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseCIDRsCanonicalizesAndDropsInvalid(t *testing.T) {
	got, invalid := parseCIDRs([]string{
		"192.0.2.1/24", "192.0.2.0/24", "2001:db8::1/32", "not-a-cidr",
	})
	if invalid != 1 {
		t.Fatalf("invalid = %d, want 1", invalid)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestCollapseMergesSiblingNetworks(t *testing.T) {
	input := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/25"),
		netip.MustParsePrefix("192.0.2.128/25"),
		netip.MustParsePrefix("2001:db8::/33"),
		netip.MustParsePrefix("2001:db8:8000::/33"),
	}
	got := collapse(input)
	want := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestCollapseDropsCoveredNetworks(t *testing.T) {
	got := collapse([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("10.1.0.0/16"),
		netip.MustParsePrefix("192.0.2.0/24"),
	})
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.0.2.0/24"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestCollapseDoesNotMergeAcrossAddressFamilies(t *testing.T) {
	got := collapse([]netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("8000::/1"),
	})
	want := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("8000::/1"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestValidateMetaCubeXGeoIP(t *testing.T) {
	valid := []byte(`{"version":2,"rules":[{"ip_cidr":["1.2.3.0/24"]}]}`)
	if err := validateDownload("geoip-id.json", valid); err != nil {
		t.Fatalf("valid source rejected: %v", err)
	}
	invalid := []byte(`{"version":2,"rules":[{"domain":["example.com"]}]}`)
	if err := validateDownload("geoip-id.json", invalid); err == nil {
		t.Fatal("expected missing ip_cidr error")
	}
	invalidCIDR := []byte(`{"version":2,"rules":[{"ip_cidr":["not-a-cidr"]}]}`)
	if err := validateDownload("geoip-id.json", invalidCIDR); err == nil {
		t.Fatal("expected invalid CIDR source to be rejected")
	}
}

func TestStatsTracksStageFailures(t *testing.T) {
	s := &stats{}
	s.fail("format sample.json", errors.New("invalid rule"))
	if !s.failed() {
		t.Fatal("stage failure must fail the build")
	}
	got := s.snapshot()
	if !reflect.DeepEqual(got.stageFailed, []string{"format sample.json"}) {
		t.Fatalf("stageFailed = %v", got.stageFailed)
	}
}

func TestCLIDryRunDoesNotRequireBinary(t *testing.T) {
	c := &cli{bin: "binary-that-does-not-exist", dry: true}
	if err := c.check(); err != nil {
		t.Fatalf("dry-run check should not require sing-box binary: %v", err)
	}
}

func TestConvertAndDecompileDryRunKeepsInputs(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "adguard.txt")
	if err := os.WriteFile(input, []byte("example.com"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := &builder{
		cfg: config{output: dir},
		cli: &cli{bin: "unused", dir: dir, dry: true},
		stats: &stats{},
		dry: true,
	}
	b.convertAndDecompile()
	if _, err := os.Stat(input); err != nil {
		t.Fatalf("dry-run removed input file: %v", err)
	}
}

package netscan

import (
	"net"
	"testing"
)

func TestDetectCDNProviderCloudflare(t *testing.T) {
	ip := mustParseIP(t, "104.16.0.1") // dentro de 104.16.0.0/13
	provider, ok := DetectCDNProvider(ip)
	if !ok || provider != "Cloudflare" {
		t.Errorf("got (%q, %v), want (\"Cloudflare\", true)", provider, ok)
	}
}

func TestDetectCDNProviderFastly(t *testing.T) {
	ip := mustParseIP(t, "151.101.1.1") // dentro de 151.101.0.0/16
	provider, ok := DetectCDNProvider(ip)
	if !ok || provider != "Fastly" {
		t.Errorf("got (%q, %v), want (\"Fastly\", true)", provider, ok)
	}
}

func TestDetectCDNProviderNonCDN(t *testing.T) {
	ip := mustParseIP(t, "8.8.8.8")
	if provider, ok := DetectCDNProvider(ip); ok {
		t.Errorf("8.8.8.8 no debería matchear ningún proveedor CDN conocido, got %q", provider)
	}
}

func TestDetectCDNProviderNilIP(t *testing.T) {
	if _, ok := DetectCDNProvider(nil); ok {
		t.Error("una IP nil no debería producir match")
	}
}

func TestResolveCDNProviderLiteralIP(t *testing.T) {
	provider, ok := ResolveCDNProvider("104.16.0.1")
	if !ok || provider != "Cloudflare" {
		t.Errorf("got (%q, %v), want (\"Cloudflare\", true)", provider, ok)
	}
}

func TestResolveCDNProviderUnresolvableHost(t *testing.T) {
	if _, ok := ResolveCDNProvider("this-host-does-not-exist.invalid"); ok {
		t.Error("un host que no resuelve no debería reportar un proveedor CDN")
	}
}

func mustParseIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("IP inválida en test: %q", s)
	}
	return ip
}

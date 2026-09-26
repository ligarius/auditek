package subdomain

import (
	"reflect"
	"testing"
)

func TestParseCTNames(t *testing.T) {
	body := []byte(`[
		{"name_value": "www.example.com\n*.example.com"},
		{"name_value": "api.example.com"},
		{"name_value": "example.com"},
		{"name_value": "dev.example.com\napi.example.com"},
		{"name_value": "deep.internal.example.com"},
		{"name_value": "other.org"}
	]`)

	got, err := parseCTNames(body, "example.com")
	if err != nil {
		t.Fatalf("parseCTNames error: %v", err)
	}
	want := []string{"www", "api", "dev", "deep.internal"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseCTNames = %v, want %v", got, want)
	}
}

func TestParseCTNamesInvalid(t *testing.T) {
	if _, err := parseCTNames([]byte("no soy json"), "example.com"); err == nil {
		t.Error("se esperaba error con JSON inválido")
	}
}

func TestMergeCandidates(t *testing.T) {
	got := MergeCandidates([]string{"admin", "dev", "api"}, []string{"dev", "vpn", "", "api", "grafana"})
	want := []string{"admin", "dev", "api", "vpn", "grafana"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("MergeCandidates = %v, want %v", got, want)
	}
}

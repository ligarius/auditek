package netscan

import (
	"reflect"
	"testing"
)

func TestExpandHostsSingle(t *testing.T) {
	hosts, err := ExpandHosts("example.com")
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if !reflect.DeepEqual(hosts, []string{"example.com"}) {
		t.Errorf("got %v", hosts)
	}
}

func TestExpandHostsCIDR(t *testing.T) {
	hosts, err := ExpandHosts("192.168.1.0/30")
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	// /30 tiene 4 IPs; red y broadcast se excluyen, quedan 2 utilizables
	want := []string{"192.168.1.1", "192.168.1.2"}
	if !reflect.DeepEqual(hosts, want) {
		t.Errorf("got %v, want %v", hosts, want)
	}
}

func TestExpandHostsCIDRInvalid(t *testing.T) {
	if _, err := ExpandHosts("not-a-cidr/24"); err == nil {
		t.Fatal("esperaba error con CIDR inválido")
	}
}

func TestExpandHostsRange(t *testing.T) {
	hosts, err := ExpandHosts("10.0.0.1-3")
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	if !reflect.DeepEqual(hosts, want) {
		t.Errorf("got %v, want %v", hosts, want)
	}
}

func TestExpandHostsRangeInvalidFormat(t *testing.T) {
	if _, err := ExpandHosts("10.0.0.1-2-3"); err == nil {
		t.Fatal("esperaba error con formato de rango inválido")
	}
}

func TestParsePortsTop100(t *testing.T) {
	ports, err := ParsePorts("top100")
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if len(ports) != len(top100Ports) {
		t.Errorf("got %d ports, want %d", len(ports), len(top100Ports))
	}
}

func TestParsePortsList(t *testing.T) {
	ports, err := ParsePorts("80,443,8080")
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	want := []int{80, 443, 8080}
	if !reflect.DeepEqual(ports, want) {
		t.Errorf("got %v, want %v", ports, want)
	}
}

func TestParsePortsRange(t *testing.T) {
	ports, err := ParsePorts("1-5")
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	want := []int{1, 2, 3, 4, 5}
	if !reflect.DeepEqual(ports, want) {
		t.Errorf("got %v, want %v", ports, want)
	}
}

func TestParsePortsMixed(t *testing.T) {
	ports, err := ParsePorts("22,80-82,443")
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	want := []int{22, 80, 81, 82, 443}
	if !reflect.DeepEqual(ports, want) {
		t.Errorf("got %v, want %v", ports, want)
	}
}

func TestParsePortsInvalid(t *testing.T) {
	if _, err := ParsePorts("abc"); err == nil {
		t.Fatal("esperaba error con puerto no numérico")
	}
}

func TestIsPrivateTargetRFC1918(t *testing.T) {
	cases := map[string]bool{
		"10.1.2.3":       true,
		"172.16.5.5":     true,
		"192.168.1.100":  true,
		"127.0.0.1":      true,
		"169.254.1.1":    true,
		"8.8.8.8":        false,
		"example.com":    false,
		"192.168.1.0/24": true,
		"10.0.0.1-50":    true,
		"1.2.3.4-10":     false,
	}
	for target, want := range cases {
		if got := IsPrivateTarget(target); got != want {
			t.Errorf("IsPrivateTarget(%q) = %v, want %v", target, got, want)
		}
	}
}

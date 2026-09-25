package netscan

import "testing"

// hasDupes indica si el slice tiene puertos repetidos.
func hasDupes(ports []int) (int, bool) {
	seen := make(map[int]struct{}, len(ports))
	for _, p := range ports {
		if _, ok := seen[p]; ok {
			return p, true
		}
		seen[p] = struct{}{}
	}
	return 0, false
}

func TestDedupePorts(t *testing.T) {
	in := []int{6379, 5432, 6379, 80, 5432, 6379}
	got := dedupePorts(in)
	want := []int{6379, 5432, 80}
	if len(got) != len(want) {
		t.Fatalf("dedupePorts largo = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dedupePorts[%d] = %d, want %d (orden de primera aparición)", i, got[i], want[i])
		}
	}
}

func TestGetProfilePortsUnique(t *testing.T) {
	for _, name := range []string{"fast", "normal", "deep"} {
		p, dup := hasDupes(GetProfile(name).Ports)
		if dup {
			t.Errorf("perfil %q tiene el puerto %d repetido", name, p)
		}
	}
}

func TestParsePortsUnique(t *testing.T) {
	cases := []string{"top100", "6379,6379,5432,6379", "8000-8002,8001,8002"}
	for _, spec := range cases {
		ports, err := ParsePorts(spec)
		if err != nil {
			t.Fatalf("ParsePorts(%q) error: %v", spec, err)
		}
		if p, dup := hasDupes(ports); dup {
			t.Errorf("ParsePorts(%q) devolvió el puerto %d repetido", spec, p)
		}
	}
}

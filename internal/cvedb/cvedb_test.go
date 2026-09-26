package cvedb

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.20.0", "1.20.1", -1},
		{"1.20.1", "1.20.0", 1},
		{"7.4", "7.4.0", 0},    // segmento ausente == 0
		{"7.4", "7.4p1", -1},   // sufijo ordena por encima del vacío
		{"7.4p1", "7.4", 1},    //
		{"2.4.50", "2.4.9", 1}, // numérico, no lexicográfico (50 > 9)
		{"4.92", "4.100", -1},  //
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q)=%d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestMatchesVersionBounds(t *testing.T) {
	// Regresión: una Entry con solo MinVersion debe matchear cualquier versión
	// >= min (antes nunca matcheaba porque el código exigía MaxVersion).
	minOnly := Entry{Product: "x", MinVersion: "2.0"}
	if !matchesVersion(minOnly, "2.5") {
		t.Error("min-only: 2.5 debería matchear >=2.0")
	}
	if matchesVersion(minOnly, "1.9") {
		t.Error("min-only: 1.9 no debería matchear >=2.0")
	}

	// Rango [4.87, 4.92): min inclusivo, max exclusivo.
	rng := Entry{Product: "x", MinVersion: "4.87", MaxVersion: "4.92"}
	if !matchesVersion(rng, "4.88") {
		t.Error("4.88 debería caer en [4.87,4.92)")
	}
	if matchesVersion(rng, "4.92") {
		t.Error("4.92 debería quedar excluida (max exclusivo)")
	}
	if matchesVersion(rng, "4.86") {
		t.Error("4.86 debería quedar fuera del rango")
	}

	// Techo inclusivo (<=), reemplaza el viejo hack ".999".
	incl := Entry{Product: "x", MaxVersionIncl: "3.5"}
	if !matchesVersion(incl, "3.5") {
		t.Error("3.5 debería matchear <=3.5")
	}
	if matchesVersion(incl, "3.6") {
		t.Error("3.6 no debería matchear <=3.5")
	}

	// ExactMatch.
	ex := Entry{Product: "x", ExactMatch: "2.4.49"}
	if !matchesVersion(ex, "2.4.49") {
		t.Error("exact debería matchear 2.4.49")
	}
	if matchesVersion(ex, "2.4.50") {
		t.Error("exact no debería matchear 2.4.50")
	}

	// Sin ExactMatch ni límites: no debe matchear nada (evita falsos positivos).
	none := Entry{Product: "x"}
	if matchesVersion(none, "1.0") {
		t.Error("una Entry sin límites no debería matchear ninguna versión")
	}
}

func TestLookupCurated(t *testing.T) {
	if got := Lookup("apache", "2.4.49"); len(got) == 0 || got[0].CVE != "CVE-2021-41773" {
		t.Errorf("apache 2.4.49 debería dar CVE-2021-41773, got %+v", got)
	}
	if got := Lookup("apache", "2.4.48"); len(got) != 0 {
		t.Errorf("apache 2.4.48 no debería tener CVE, got %+v", got)
	}
	if got := Lookup("nginx", "1.20.0"); len(got) == 0 {
		t.Error("nginx 1.20.0 debería matchear <1.20.1")
	}
	if got := Lookup("nginx", "1.20.1"); len(got) != 0 {
		t.Error("nginx 1.20.1 no debería matchear (max exclusivo)")
	}
	if got := Lookup("openssh", "7.6"); len(got) == 0 {
		t.Error("openssh 7.6 debería matchear <7.7")
	}
	if got := Lookup("openssh", "7.7"); len(got) != 0 {
		t.Error("openssh 7.7 no debería matchear <7.7")
	}
	// Producto case-insensitive.
	if got := Lookup("Apache", "2.4.49"); len(got) == 0 {
		t.Error("Lookup debería normalizar el nombre del producto (case-insensitive)")
	}
	// Rango exim [4.87, 4.92).
	if got := Lookup("exim", "4.90"); len(got) == 0 {
		t.Error("exim 4.90 debería caer en el rango vulnerable")
	}
	if got := Lookup("exim", "4.92"); len(got) != 0 {
		t.Error("exim 4.92 debería quedar excluida")
	}
}

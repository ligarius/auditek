package engine

import "testing"

func TestBodySignature(t *testing.T) {
	// Misma plantilla, distintos dígitos/espacios -> misma firma.
	a := `<html><body>id 12345 <span>build 9a8b</span></body></html>`
	b := `<html><body>id 67890 <span>build 9a8b</span></body></html>`
	if bodySignature(a) != bodySignature(b) {
		t.Error("cuerpos con la misma plantilla (solo cambian dígitos) deberían tener igual firma")
	}
	// Plantilla distinta -> firma distinta.
	c := `<html><body>totalmente otra cosa</body></html>`
	if bodySignature(a) == bodySignature(c) {
		t.Error("cuerpos con plantilla distinta deberían diferir en firma")
	}
}

func TestCatchAllHit(t *testing.T) {
	sig := "abc:10"

	// Recurso específico que devuelve la página genérica -> es catch-all (FP).
	if !catchAllHit(true, "/.env", sig, sig, 200) {
		t.Error("una ruta específica con la firma del catch-all debería marcarse como hit")
	}
	// La raíz nunca se descarta (los findings de la home son legítimos).
	if catchAllHit(true, "/", sig, sig, 200) {
		t.Error("la raíz no debería descartarse")
	}
	// Firma distinta -> el recurso sí existe, no se descarta.
	if catchAllHit(true, "/.env", sig, "otra:5", 200) {
		t.Error("firma distinta no debería descartarse")
	}
	// Sin catch-all -> nunca se descarta.
	if catchAllHit(false, "/.env", sig, sig, 200) {
		t.Error("sin catch-all no debería descartarse nada")
	}
	// Status != 200 -> no aplica.
	if catchAllHit(true, "/.env", sig, sig, 404) {
		t.Error("con status 404 no debería aplicar la supresión")
	}
}

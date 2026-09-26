package adscan

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestIsProbableDC(t *testing.T) {
	if !IsProbableDC(map[int]bool{88: true, 389: true, 445: true}) {
		t.Error("Kerberos+LDAP debería identificarse como probable DC")
	}
	if IsProbableDC(map[int]bool{389: true, 445: true}) {
		t.Error("LDAP sin Kerberos no debería ser DC")
	}
	if IsProbableDC(map[int]bool{80: true, 443: true}) {
		t.Error("un web server no es un DC")
	}
}

func TestAnalyzeSurface(t *testing.T) {
	// DC con LDAP en claro y GC en claro; sin 445 (no probe SMB).
	open := map[int]bool{88: true, 389: true, 3268: true, 53: true}
	got := map[string]string{}
	for _, f := range Analyze("10.0.0.1", open, 1*time.Millisecond) {
		got[f.RuleID] = f.Severity
	}
	for _, id := range []string{"ad-domain-controller", "ad-ldap-cleartext", "ad-kerberos-exposed", "ad-global-catalog-cleartext"} {
		if _, ok := got[id]; !ok {
			t.Errorf("faltó el hallazgo %s (got %v)", id, got)
		}
	}
	// Con LDAPS presente, NO debe marcar ldap-cleartext.
	got2 := map[string]bool{}
	for _, f := range Analyze("10.0.0.1", map[int]bool{88: true, 389: true, 636: true}, time.Millisecond) {
		got2[f.RuleID] = true
	}
	if got2["ad-ldap-cleartext"] {
		t.Error("con LDAPS (636) no debería marcarse LDAP en claro")
	}
}

func TestParseNegotiateSecurityMode(t *testing.T) {
	// Construye una respuesta SMB2 mínima con SecurityMode = SIGNING_REQUIRED.
	msg := make([]byte, 100)
	msg[0], msg[1], msg[2], msg[3] = 0xFE, 'S', 'M', 'B'
	binary.LittleEndian.PutUint16(msg[66:], smbSigningRequired)
	mode, err := parseNegotiateSecurityMode(msg)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if mode&smbSigningRequired == 0 {
		t.Error("debería detectar SIGNING_REQUIRED")
	}

	// Firma inválida -> error.
	bad := make([]byte, 100)
	if _, err := parseNegotiateSecurityMode(bad); err == nil {
		t.Error("una firma inválida debería dar error")
	}
	// Demasiado corta -> error.
	if _, err := parseNegotiateSecurityMode([]byte{0xFE, 'S', 'M', 'B'}); err == nil {
		t.Error("una respuesta corta debería dar error")
	}
}

func TestSMB2NegotiateRequestShape(t *testing.T) {
	req := smb2NegotiateRequest()
	// prefijo NBSS (4) + header (64) + body (40) = 108
	if len(req) != 108 {
		t.Errorf("tamaño del request = %d, want 108", len(req))
	}
	msg := req[4:]
	if msg[0] != 0xFE || msg[1] != 'S' || msg[2] != 'M' || msg[3] != 'B' {
		t.Error("firma SMB2 ausente en el request")
	}
	// longitud NBSS declarada == len(msg)
	declared := int(req[1])<<16 | int(req[2])<<8 | int(req[3])
	if declared != len(msg) {
		t.Errorf("longitud NBSS declarada %d != %d", declared, len(msg))
	}
}

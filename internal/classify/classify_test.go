package classify

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		ruleID string
		domain string
		phase  string
	}{
		// Reconocimiento
		{"open-port", DomainNetwork, PhaseRecon},
		{"subdomain-discovered", DomainSubs, PhaseRecon},
		{"technology-detected", DomainWeb, PhaseRecon},
		{"ad-domain-controller", DomainAD, PhaseRecon},
		// Enumeración
		{"ad-smb-signing-not-required", DomainAD, PhaseEnum},
		{"ad-kerberos-exposed", DomainAD, PhaseEnum},
		{"lateral-movement-surface", DomainNetwork, PhaseEnum},
		{"exposed-swagger", DomainWeb, PhaseEnum},
		{"exposed-graphql-introspection", DomainWeb, PhaseEnum},
		// Escaneo / Vulnerabilidades
		{"CVE-2021-41773", DomainGeneral, PhaseVuln},
		{"GHSA-abcd-1234", DomainDeps, PhaseVuln},
		{"loose-dependency-version", DomainDeps, PhaseVuln},
		{"dockerfile-runs-as-root", DomainContainer, PhaseVuln},
		{"tls-cert-expired", DomainWeb, PhaseVuln},
		{"exposed-env-file", DomainWeb, PhaseVuln},
		{"redis-unauthenticated", DomainNetwork, PhaseVuln},
		{"exposed-admin-panel", DomainWeb, PhaseVuln},
		{"subdomain-takeover-hint", DomainSubs, PhaseVuln},
		// Explotación (confirmada, típicamente vía --exec-hook/import)
		{"ad-credentials-valid", DomainAD, PhaseExploit},
		{"vsftpd-backdoor-confirmed", DomainNetwork, PhaseExploit},
		{"secrets-validated", DomainWeb, PhaseExploit},
		{"lateral-movement-confirmed", DomainAD, PhaseExploit},
		// Post-explotación (correlación)
		{"path-ad-ntlm-relay", DomainAD, PhasePost},
		{"path-rce-plus-lateral", DomainGeneral, PhasePost},
		// Default
		{"algo-desconocido", DomainGeneral, PhaseVuln},
	}
	for _, c := range cases {
		d, p := Classify(c.ruleID)
		if d != c.domain || p != c.phase {
			t.Errorf("Classify(%q) = (%q,%q), want (%q,%q)", c.ruleID, d, p, c.domain, c.phase)
		}
	}
}

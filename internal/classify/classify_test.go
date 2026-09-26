package classify

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		ruleID string
		domain string
		phase  string
	}{
		{"ad-domain-controller", DomainAD, PhaseRecon},
		{"ad-smb-signing-not-required", DomainAD, PhaseLateral},
		{"ad-credentials-valid", DomainAD, PhaseLateral},
		{"path-ad-ntlm-relay", DomainAD, PhaseEscalate},
		{"path-rce-plus-lateral", DomainGeneral, PhaseEscalate},
		{"lateral-movement-surface", DomainNetwork, PhaseLateral},
		{"open-port", DomainNetwork, PhaseRecon},
		{"subdomain-discovered", DomainSubs, PhaseRecon},
		{"subdomain-takeover-hint", DomainSubs, PhaseInitial},
		{"technology-detected", DomainWeb, PhaseRecon},
		{"CVE-2021-41773", DomainGeneral, PhaseInitial},
		{"GHSA-abcd-1234", DomainDeps, PhaseInitial},
		{"loose-dependency-version", DomainDeps, PhaseRecon},
		{"dockerfile-runs-as-root", DomainContainer, PhaseRecon},
		{"tls-cert-expired", DomainWeb, PhaseRecon},
		{"exposed-env-file", DomainWeb, PhaseInitial},
		{"exposed-ssh-key", DomainWeb, PhaseInitial},
		{"redis-unauthenticated", DomainNetwork, PhaseInitial},
		{"exposed-admin-panel", DomainWeb, PhaseInitial},
		{"missing-security-headers", DomainWeb, PhaseRecon},
		{"algo-desconocido", DomainGeneral, PhaseRecon},
	}
	for _, c := range cases {
		d, p := Classify(c.ruleID)
		if d != c.domain || p != c.phase {
			t.Errorf("Classify(%q) = (%q,%q), want (%q,%q)", c.ruleID, d, p, c.domain, c.phase)
		}
	}
}

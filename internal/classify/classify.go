// Package classify asigna a cada hallazgo (por su RuleID) un dominio técnico y
// una fase de la kill-chain, para poder agrupar y categorizar la salida sin
// cambiar el esquema de persistencia. Se deriva en tiempo de render, así también
// aplica a scans antiguos ya guardados. Es una ayuda de organización, no una
// clasificación exacta: ante la duda cae en General / Reconocimiento.
package classify

import "strings"

// Fases de la kill-chain (simplificada).
const (
	PhaseRecon    = "Reconocimiento"
	PhaseInitial  = "Acceso inicial"
	PhaseLateral  = "Movimiento lateral"
	PhaseEscalate = "Escalada / Correlación"
)

// PhaseOrder es el orden de presentación (primero el impacto más alto).
var PhaseOrder = []string{PhaseEscalate, PhaseLateral, PhaseInitial, PhaseRecon}

// Dominios técnicos.
const (
	DomainNetwork   = "Red"
	DomainWeb       = "Web"
	DomainAD        = "Active Directory"
	DomainDeps      = "Dependencias"
	DomainSubs      = "Subdominios"
	DomainContainer = "Contenedor"
	DomainGeneral   = "General"
)

// Classify devuelve (dominio, fase) para un RuleID.
func Classify(ruleID string) (domain, phase string) {
	id := strings.ToLower(ruleID)

	switch {
	case strings.HasPrefix(id, "path-"): // hallazgos de correlación
		if strings.Contains(id, "-ad-") || strings.Contains(id, "ntlm") {
			return DomainAD, PhaseEscalate
		}
		return DomainGeneral, PhaseEscalate

	case strings.HasPrefix(id, "ad-"):
		if id == "ad-smb-signing-not-required" || id == "ad-credentials-valid" {
			return DomainAD, PhaseLateral
		}
		return DomainAD, PhaseRecon

	case id == "lateral-movement-surface":
		return DomainNetwork, PhaseLateral
	case id == "open-port":
		return DomainNetwork, PhaseRecon
	case id == "subdomain-discovered":
		return DomainSubs, PhaseRecon
	case id == "subdomain-takeover-hint":
		return DomainSubs, PhaseInitial
	case id == "technology-detected":
		return DomainWeb, PhaseRecon
	case strings.HasPrefix(id, "dockerfile-"):
		return DomainContainer, PhaseRecon
	case strings.HasPrefix(id, "cve-"):
		return DomainGeneral, PhaseInitial
	case strings.HasPrefix(id, "ghsa-"):
		return DomainDeps, PhaseInitial
	case id == "loose-dependency-version":
		return DomainDeps, PhaseRecon
	case strings.HasPrefix(id, "tls-") || id == "weak-tls-version":
		return DomainWeb, PhaseRecon
	case id == "missing-sri-external-script" || id == "exposed-cicd-config":
		return DomainWeb, PhaseRecon
	}

	// Exposición de secretos/credenciales -> acceso inicial.
	if containsAny(id, "env-file", "git-config", "wp-config", "ssh-key", "secret", "backup") {
		return DomainWeb, PhaseInitial
	}
	// Servicios de red sin auth / con acceso -> acceso inicial.
	if containsAny(id, "redis", "memcached", "elasticsearch", "ftp-anonymous", "smtp-vrfy", "pop3") {
		return DomainNetwork, PhaseInitial
	}
	// Paneles / credenciales por defecto -> acceso inicial.
	if containsAny(id, "admin", "default-credentials") {
		return DomainWeb, PhaseInitial
	}
	// Resto de misconfig/compliance web -> reconocimiento/exposición.
	if containsAny(id, "swagger", "graphql", "phpinfo", "directory-listing", "csp", "security-headers", "cookie", "https", "redirect", "error", "manifest") {
		return DomainWeb, PhaseRecon
	}

	return DomainGeneral, PhaseRecon
}

// Domain devuelve solo el dominio técnico.
func Domain(ruleID string) string { d, _ := Classify(ruleID); return d }

// Phase devuelve solo la fase.
func Phase(ruleID string) string { _, p := Classify(ruleID); return p }

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

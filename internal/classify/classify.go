// Package classify asigna a cada hallazgo (por su RuleID) un dominio técnico y
// una fase del ciclo de pentest, para agrupar y categorizar la salida sin
// cambiar el esquema de persistencia. Se deriva en tiempo de render, así también
// aplica a scans antiguos. Es una ayuda de organización, no exacta: ante la duda
// cae en General / Escaneo.
//
// El ciclo completo es: Reconocimiento → Enumeración → Escaneo/Vulnerabilidades
// → Explotación → Post-explotación → Reporte → Retest. Reporte y Retest son
// actividades (comandos/flujo), no categorías de hallazgo, así que las fases de
// hallazgo llegan hasta Post-explotación.
package classify

import "strings"

// Fases del ciclo de pentest que aplican a un hallazgo.
const (
	PhaseRecon   = "Reconocimiento"
	PhaseEnum    = "Enumeración"
	PhaseVuln    = "Escaneo / Vulnerabilidades"
	PhaseExploit = "Explotación"
	PhasePost    = "Post-explotación"
)

// PhaseOrder es el orden de presentación (orden natural del ciclo).
var PhaseOrder = []string{PhaseRecon, PhaseEnum, PhaseVuln, PhaseExploit, PhasePost}

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

// exploitConfirmed son RuleIDs que representan impacto CONFIRMADO, típicamente
// aportados por módulos externos vía --exec-hook / import.
var exploitConfirmed = map[string]bool{
	"vsftpd-backdoor-confirmed":  true,
	"redis-write-demonstrated":   true,
	"secrets-validated":          true,
	"lateral-movement-confirmed": true,
	"ad-credentials-valid":       true,
}

// Classify devuelve (dominio, fase) para un RuleID.
func Classify(ruleID string) (domain, phase string) {
	id := strings.ToLower(ruleID)

	switch {
	case strings.HasPrefix(id, "path-"): // correlación = potencial de post-explotación
		if strings.Contains(id, "-ad-") || strings.Contains(id, "ntlm") {
			return DomainAD, PhasePost
		}
		return DomainGeneral, PhasePost

	case exploitConfirmed[id]:
		return exploitDomain(id), PhaseExploit

	case strings.HasPrefix(id, "ad-"):
		if id == "ad-domain-controller" {
			return DomainAD, PhaseRecon
		}
		return DomainAD, PhaseEnum // ldap/kerberos/gc/firma-smb = enumeración de superficie

	case id == "lateral-movement-surface":
		return DomainNetwork, PhaseEnum
	case id == "open-port":
		return DomainNetwork, PhaseRecon
	case id == "subdomain-discovered":
		return DomainSubs, PhaseRecon
	case id == "technology-detected":
		return DomainWeb, PhaseRecon

	// Enumeración de superficie de aplicación.
	case containsAny(id, "swagger", "api-docs", "graphql", "directory-listing"):
		return DomainWeb, PhaseEnum

	// Vulnerabilidades / SCA.
	case strings.HasPrefix(id, "cve-"):
		return DomainGeneral, PhaseVuln
	case strings.HasPrefix(id, "ghsa-"):
		return DomainDeps, PhaseVuln
	case id == "loose-dependency-version":
		return DomainDeps, PhaseVuln
	case strings.HasPrefix(id, "dockerfile-"):
		return DomainContainer, PhaseVuln
	case strings.HasPrefix(id, "tls-") || id == "weak-tls-version":
		return DomainWeb, PhaseVuln
	case id == "missing-sri-external-script" || id == "exposed-cicd-config":
		return DomainWeb, PhaseVuln
	case id == "subdomain-takeover-hint":
		return DomainSubs, PhaseVuln
	}

	// Secretos/credenciales expuestos -> vulnerabilidad.
	if containsAny(id, "env-file", "git-config", "wp-config", "ssh-key", "secret", "backup") {
		return DomainWeb, PhaseVuln
	}
	// Servicios de red sin auth -> vulnerabilidad.
	if containsAny(id, "redis", "memcached", "elasticsearch", "ftp-anonymous", "smtp-vrfy", "pop3") {
		return DomainNetwork, PhaseVuln
	}
	// Paneles / credenciales por defecto y misconfig/compliance web -> vulnerabilidad.
	if containsAny(id, "admin", "default-credentials", "phpinfo", "csp", "security-headers", "cookie", "https", "redirect", "error", "manifest") {
		return DomainWeb, PhaseVuln
	}

	return DomainGeneral, PhaseVuln
}

func exploitDomain(id string) string {
	switch {
	case id == "ad-credentials-valid" || strings.Contains(id, "lateral"):
		return DomainAD
	case strings.Contains(id, "secret"):
		return DomainWeb
	default: // vsftpd, redis, etc.
		return DomainNetwork
	}
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

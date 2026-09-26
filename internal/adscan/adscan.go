// Package adscan hace reconocimiento de Active Directory SIN autenticarse:
// identifica Domain Controllers por su perfil de puertos, marca superficie AD
// insegura (LDAP sin TLS, Kerberos/KDC y Global Catalog expuestos) y comprueba
// la política de firma SMB con un único paquete SMB2 NEGOTIATE (sin login).
//
// Fiel al modelo de auditek: es detección pasiva/activa de reconocimiento, nunca
// intenta credenciales, spraying ni ejecución. La parte autenticada (validación
// de credenciales, enum de dominio, dumping) queda para un módulo --exec-hook.
package adscan

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// Finding es un hallazgo de reconocimiento AD, sin acoplar este paquete al
// esquema de persistencia; el llamador lo convierte a findings.Finding.
type Finding struct {
	RuleID   string
	RuleName string
	Target   string
	Severity string
	Impact   string
	Evidence string
}

// Puertos típicos de un entorno AD.
const (
	portKerberos      = 88
	portLDAP          = 389
	portLDAPS         = 636
	portGlobalCatalog = 3268
	portGCoverSSL     = 3269
	portSMB           = 445
	portDNS           = 53
	portKpasswd       = 464
)

// IsProbableDC decide si un host parece un Domain Controller por sus puertos
// abiertos: la señal fuerte es Kerberos (KDC) + LDAP juntos, que en la práctica
// solo exponen los DCs.
func IsProbableDC(open map[int]bool) bool {
	return open[portKerberos] && open[portLDAP]
}

// Analyze corre el reconocimiento AD sobre un host dado su conjunto de puertos
// abiertos. timeout aplica al probe SMB.
func Analyze(host string, open map[int]bool, timeout time.Duration) []Finding {
	var out []Finding

	isDC := IsProbableDC(open)
	if isDC {
		out = append(out, Finding{
			RuleID:   "ad-domain-controller",
			RuleName: "Probable Domain Controller (Active Directory)",
			Target:   host,
			Severity: "info",
			Impact:   "El host expone el perfil de puertos de un Domain Controller (Kerberos + LDAP). En un entorno empresarial el DC es el activo más crítico: controla autenticación, políticas y accesos de todo el dominio, y es el objetivo central de movimiento lateral y escalada.",
			Evidence: "Puertos AD abiertos: " + adPortsEvidence(open),
		})
	}

	// LDAP en claro (389 abierto sin 636/LDAPS): consultas y binds viajan sin TLS.
	if open[portLDAP] && !open[portLDAPS] {
		out = append(out, Finding{
			RuleID:   "ad-ldap-cleartext",
			RuleName: "LDAP sin LDAPS (directorio en texto claro)",
			Target:   host + ":" + strconv.Itoa(portLDAP),
			Severity: "medium",
			Impact:   "LDAP (389) está expuesto sin su equivalente cifrado LDAPS (636). Las consultas al directorio y, sobre todo, los binds con credenciales viajan sin TLS: un atacante en la red puede interceptarlos (sniffing) o manipularlos.",
			Evidence: "389/tcp abierto, 636/tcp no detectado",
		})
	}

	if open[portKerberos] {
		out = append(out, Finding{
			RuleID:   "ad-kerberos-exposed",
			RuleName: "Servicio Kerberos (KDC) accesible",
			Target:   host + ":" + strconv.Itoa(portKerberos),
			Severity: "info",
			Impact:   "El KDC de Kerberos es accesible. Con una lista de usuarios válidos, habilita técnicas como AS-REP roasting (usuarios sin preautenticación) y Kerberoasting — el punto de partida para obtener credenciales de servicio offline.",
			Evidence: "88/tcp abierto",
		})
	}

	// Global Catalog en claro (3268 sin 3269).
	if open[portGlobalCatalog] && !open[portGCoverSSL] {
		out = append(out, Finding{
			RuleID:   "ad-global-catalog-cleartext",
			RuleName: "Global Catalog sin cifrado (3268 sin 3269)",
			Target:   host + ":" + strconv.Itoa(portGlobalCatalog),
			Severity: "low",
			Impact:   "El Global Catalog (3268) responde en texto claro sin su variante TLS (3269). Expone consultas a nivel de bosque (forest-wide) que pueden interceptarse en la red.",
			Evidence: "3268/tcp abierto, 3269/tcp no detectado",
		})
	}

	// Firma SMB: un único NEGOTIATE, sin autenticar. Si falla el probe, se omite
	// el hallazgo (best-effort) en vez de romper el análisis.
	if open[portSMB] {
		if enabled, required, err := SMBSecurityMode(host, timeout); err == nil && !required {
			sev := "medium"
			note := "habilitada pero no obligatoria"
			if !enabled {
				note = "deshabilitada"
			}
			out = append(out, Finding{
				RuleID:   "ad-smb-signing-not-required",
				RuleName: "Firma SMB no requerida (riesgo de NTLM relay)",
				Target:   host + ":" + strconv.Itoa(portSMB),
				Severity: sev,
				Impact:   "El servidor SMB no exige firma de mensajes (" + note + "). Esto habilita ataques de NTLM relay: un atacante que capture una autenticación NTLM (ej. vía coerción/poisoning en la red interna) puede reenviarla a este host y autenticarse como la víctima — vector clásico de movimiento lateral en AD.",
				Evidence: "SMB2 NEGOTIATE: SigningRequired=false",
			})
		}
	}

	return out
}

func adPortsEvidence(open map[int]bool) string {
	names := []struct {
		port int
		name string
	}{
		{portKerberos, "Kerberos/88"}, {portLDAP, "LDAP/389"}, {portLDAPS, "LDAPS/636"},
		{portGlobalCatalog, "GC/3268"}, {portGCoverSSL, "GC-SSL/3269"}, {portSMB, "SMB/445"},
		{portDNS, "DNS/53"}, {portKpasswd, "kpasswd/464"},
	}
	first := true
	s := ""
	for _, n := range names {
		if open[n.port] {
			if !first {
				s += ", "
			}
			s += n.name
			first = false
		}
	}
	return s
}

// --- SMB2 NEGOTIATE (sin autenticación) ---

const smbSigningRequired = 0x0002
const smbSigningEnabled = 0x0001

// SMBSecurityMode envía un SMB2 NEGOTIATE y devuelve la política de firma del
// servidor (enabled, required) leída del SecurityMode de la respuesta. No hace
// session setup ni envía credenciales.
func SMBSecurityMode(host string, timeout time.Duration) (enabled, required bool, err error) {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(portSMB)), timeout)
	if err != nil {
		return false, false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err = conn.Write(smb2NegotiateRequest()); err != nil {
		return false, false, err
	}

	var lenb [4]byte
	if _, err = io.ReadFull(conn, lenb[:]); err != nil {
		return false, false, err
	}
	n := int(lenb[1])<<16 | int(lenb[2])<<8 | int(lenb[3]) // NBSS: longitud de 24 bits
	if n < 68 || n > 1<<20 {
		return false, false, fmt.Errorf("respuesta SMB de tamaño inesperado (%d)", n)
	}
	msg := make([]byte, n)
	if _, err = io.ReadFull(conn, msg); err != nil {
		return false, false, err
	}

	mode, err := parseNegotiateSecurityMode(msg)
	if err != nil {
		return false, false, err
	}
	return mode&smbSigningEnabled != 0, mode&smbSigningRequired != 0, nil
}

// parseNegotiateSecurityMode extrae el SecurityMode del cuerpo de una respuesta
// SMB2 NEGOTIATE (header de 64 bytes; SecurityMode en el offset 2 del cuerpo).
func parseNegotiateSecurityMode(msg []byte) (uint16, error) {
	if len(msg) < 68 {
		return 0, fmt.Errorf("respuesta SMB2 demasiado corta")
	}
	if msg[0] != 0xFE || msg[1] != 'S' || msg[2] != 'M' || msg[3] != 'B' {
		return 0, fmt.Errorf("no es una respuesta SMB2 (firma inválida)")
	}
	return binary.LittleEndian.Uint16(msg[66:68]), nil
}

// smb2NegotiateRequest arma un SMB2 NEGOTIATE mínimo ofreciendo los dialectos
// 2.0.2 y 2.1 (evita los negotiate contexts de 3.1.1), con prefijo NBSS.
func smb2NegotiateRequest() []byte {
	header := make([]byte, 64)
	header[0], header[1], header[2], header[3] = 0xFE, 'S', 'M', 'B'
	binary.LittleEndian.PutUint16(header[4:], 64) // StructureSize
	// Command NEGOTIATE = 0 (offset 12), resto en cero.

	body := []byte{
		0x24, 0x00, // StructureSize = 36
		0x02, 0x00, // DialectCount = 2
		0x01, 0x00, // SecurityMode = SIGNING_ENABLED
		0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // Capabilities
	}
	body = append(body, make([]byte, 16)...) // ClientGuid
	body = append(body, make([]byte, 8)...)  // ClientStartTime (dialectos < 3.1.1)
	body = append(body, 0x02, 0x02)          // Dialect 0x0202
	body = append(body, 0x10, 0x02)          // Dialect 0x0210

	msg := append(header, body...)
	out := make([]byte, 4+len(msg))
	// Prefijo NBSS: 4 bytes, longitud de 24 bits.
	out[0] = 0
	out[1] = byte(len(msg) >> 16)
	out[2] = byte(len(msg) >> 8)
	out[3] = byte(len(msg))
	copy(out[4:], msg)
	return out
}

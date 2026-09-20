package cvedb

import (
	"strconv"
	"strings"
	"sync"
)

var (
	cachedEntries []Entry
	cacheLoaded   bool
	cacheMu       sync.Mutex
)

func loadedCache() []Entry {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if !cacheLoaded {
		entries, err := LoadCache()
		if err == nil {
			cachedEntries = entries
		}
		cacheLoaded = true
	}
	return cachedEntries
}

// Entry representa una vulnerabilidad conocida para un producto/rango de versión.
// Esta es una base de datos LOCAL, curada a mano con un set reducido de CVEs
// bien documentados — no es un sync de NVD/OSV completo. Ver README para el
// alcance real y cómo se piensa expandir (comando `update-db` futuro).
type Entry struct {
	Product     string // nombre normalizado, ej. "apache", "nginx", "openssh", "jquery"
	MinVersion  string // vulnerable si version >= MinVersion (inclusivo); vacío = sin piso
	MaxVersion  string // vulnerable si version < MaxVersion (exclusivo)
	ExactMatch  string // alternativa a MaxVersion: solo esta versión exacta
	CVE         string
	Severity    string
	Impact      string
	Description string
}

var db = []Entry{
	{
		Product:     "apache",
		ExactMatch:  "2.4.49",
		CVE:         "CVE-2021-41773",
		Severity:    "critical",
		Description: "Path traversal en Apache HTTP Server 2.4.49",
		Impact:      "Permite leer archivos fuera del directorio web (path traversal) y, si mod_cgi está habilitado, ejecución remota de código (RCE) — compromiso total del servidor.",
	},
	{
		Product:     "apache",
		ExactMatch:  "2.4.50",
		CVE:         "CVE-2021-42013",
		Severity:    "critical",
		Description: "Fix incompleto de CVE-2021-41773 en Apache 2.4.50, sigue explotable",
		Impact:      "Igual que CVE-2021-41773: path traversal y potencial RCE — el parche de la versión anterior no cerró completamente la vulnerabilidad.",
	},
	{
		Product:     "nginx",
		MaxVersion:  "1.20.1",
		CVE:         "CVE-2021-23017",
		Severity:    "high",
		Description: "Off-by-one en el resolver DNS de nginx (versiones 0.6.18 a 1.20.0)",
		Impact:      "Puede provocar corrupción de memoria explotable, potencialmente llevando a ejecución remota de código si el servidor usa resolución DNS activa.",
	},
	{
		Product:     "openssh",
		MaxVersion:  "7.4",
		CVE:         "CVE-2016-10009",
		Severity:    "high",
		Description: "Vulnerabilidad de carga de módulos en agentes SSH reenviados (OpenSSH < 7.4)",
		Impact:      "Un servidor malicioso al que el cliente reenvía su agente SSH puede cargar código arbitrario en el proceso del agente.",
	},
	{
		Product:     "openssh",
		MaxVersion:  "7.7",
		CVE:         "CVE-2018-15473",
		Severity:    "medium",
		Description: "Enumeración de usuarios válidos en OpenSSH < 7.7 vía tiempo de respuesta",
		Impact:      "Permite a un atacante determinar qué nombres de usuario existen en el sistema, facilitando ataques de fuerza bruta dirigidos.",
	},
	{
		Product:     "jquery",
		MaxVersion:  "3.5.0",
		CVE:         "CVE-2020-11022",
		Severity:    "medium",
		Description: "XSS pasando HTML no confiable a los métodos .html()/.append() de jQuery < 3.5.0",
		Impact:      "Si la aplicación pasa contenido no sanitizado a estos métodos de jQuery, un atacante puede inyectar y ejecutar JavaScript arbitrario en el navegador de otros usuarios.",
	},
	{
		Product:     "iis",
		ExactMatch:  "6.0",
		CVE:         "CVE-2017-7269",
		Severity:    "critical",
		Description: "Buffer overflow en el módulo WebDAV de IIS 6.0 (ScStoragePathFromUrl)",
		Impact:      "Permite ejecución remota de código sin autenticación — un atacante puede tomar control total del servidor con una sola petición HTTP maliciosa.",
	},
	{
		Product:     "vsftpd",
		ExactMatch:  "2.3.4",
		CVE:         "CVE-2011-2523",
		Severity:    "critical",
		Description: "Backdoor en vsftpd 2.3.4 (versión comprometida distribuida entre jun-jul 2011)",
		Impact:      "El binario de esta versión específica contiene una puerta trasera que abre una shell de comandos en el puerto 6200 al detectar un patrón específico en el login — compromiso total del servidor.",
	},
	{
		Product:     "exim",
		MinVersion:  "4.87",
		MaxVersion:  "4.92",
		CVE:         "CVE-2019-10149",
		Severity:    "critical",
		Description: "Ejecución remota de comandos en Exim 4.87 a 4.91 (\"Return of the WIZard\")",
		Impact:      "Permite a un atacante remoto (en ciertas configuraciones, sin autenticación) ejecutar comandos arbitrarios con privilegios del servidor de correo.",
	},
}

// Lookup busca vulnerabilidades conocidas para un producto+versión detectados.
// Revisa primero el set curado a mano, y luego el caché local descargado de
// NVD (si existe, vía `auditek update-db`).
func Lookup(product, version string) []Entry {
	product = strings.ToLower(product)
	var matches []Entry

	for _, e := range append(append([]Entry{}, db...), loadedCache()...) {
		if e.Product != product {
			continue
		}
		if e.ExactMatch != "" && e.ExactMatch == version {
			matches = append(matches, e)
			continue
		}
		if e.MinVersion != "" && versionLess(version, e.MinVersion) {
			continue // versión más vieja que el piso del rango vulnerable
		}
		if e.MaxVersion != "" && versionLess(version, e.MaxVersion) {
			matches = append(matches, e)
		}
	}
	return matches
}

// versionLess compara versiones tipo "1.20.1" de forma simple (no soporta
// sufijos como -beta, rc, etc. — suficiente para el set curado de arriba).
func versionLess(a, b string) bool {
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")

	for i := 0; i < len(pa) || i < len(pb); i++ {
		na, nb := 0, 0
		if i < len(pa) {
			na, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			nb, _ = strconv.Atoi(pb[i])
		}
		if na != nb {
			return na < nb
		}
	}
	return false
}

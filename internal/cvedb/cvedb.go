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
	Product        string // nombre normalizado, ej. "apache", "nginx", "openssh", "jquery"
	MinVersion     string // vulnerable si version >= MinVersion (inclusivo); vacío = sin piso
	MaxVersion     string // vulnerable si version < MaxVersion (exclusivo); vacío = sin techo
	MaxVersionIncl string // vulnerable si version <= MaxVersionIncl (inclusivo); alternativa a MaxVersion
	ExactMatch     string // solo esta versión exacta (ignora los rangos)
	CVE            string
	Severity       string
	Impact         string
	Description    string
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
	product = strings.ToLower(strings.TrimSpace(product))
	version = strings.TrimSpace(version)
	var matches []Entry

	for _, e := range allEntries() {
		if strings.ToLower(e.Product) != product {
			continue
		}
		if matchesVersion(e, version) {
			matches = append(matches, e)
		}
	}
	return matches
}

func allEntries() []Entry {
	cache := loadedCache()
	out := make([]Entry, 0, len(db)+len(cache))
	out = append(out, db...)
	out = append(out, cache...)
	return out
}

// matchesVersion decide si `version` cae dentro del rango vulnerable de e.
// ExactMatch tiene prioridad. Con rangos, la versión debe satisfacer TODOS los
// límites presentes (>= MinVersion, < MaxVersion, <= MaxVersionIncl). Una Entry
// sin ExactMatch ni ningún límite NO matchea, para no marcar toda versión del
// producto como vulnerable (antes, una Entry con solo MinVersion nunca matcheaba).
func matchesVersion(e Entry, version string) bool {
	if e.ExactMatch != "" {
		return compareVersions(version, e.ExactMatch) == 0
	}
	bounded := false
	if e.MinVersion != "" {
		bounded = true
		if compareVersions(version, e.MinVersion) < 0 {
			return false
		}
	}
	if e.MaxVersion != "" {
		bounded = true
		if compareVersions(version, e.MaxVersion) >= 0 {
			return false
		}
	}
	if e.MaxVersionIncl != "" {
		bounded = true
		if compareVersions(version, e.MaxVersionIncl) > 0 {
			return false
		}
	}
	return bounded
}

// compareVersions compara versiones tipo "1.20.1", "7.4p1", "4.92".
// Devuelve -1 si a<b, 0 si son iguales, 1 si a>b. Cada segmento separado por
// "." se compara primero por su prefijo numérico y, en empate, por el sufijo
// alfanumérico ("" < "p1", así "7.4" < "7.4p1"). Los segmentos ausentes cuentan
// como {0, ""}, de modo que "7.4" == "7.4.0". No implementa la precedencia de
// pre-releases de SemVer (un sufijo siempre ordena por encima del vacío), lo
// que es correcto para versiones de parche tipo OpenSSH ("7.4p1").
func compareVersions(a, b string) int {
	sa := strings.Split(a, ".")
	sb := strings.Split(b, ".")
	n := len(sa)
	if len(sb) > n {
		n = len(sb)
	}
	for i := 0; i < n; i++ {
		var fa, fb string
		if i < len(sa) {
			fa = sa[i]
		}
		if i < len(sb) {
			fb = sb[i]
		}
		na, ra := splitNumSuffix(fa)
		nb, rb := splitNumSuffix(fb)
		if na != nb {
			if na < nb {
				return -1
			}
			return 1
		}
		if ra != rb {
			if ra < rb {
				return -1
			}
			return 1
		}
	}
	return 0
}

// splitNumSuffix parte "4p1" en (4, "p1"), "20" en (20, ""), "" en (0, "").
func splitNumSuffix(s string) (int, string) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	num := 0
	if i > 0 {
		num, _ = strconv.Atoi(s[:i])
	}
	return num, s[i:]
}

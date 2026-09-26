package cmd

import (
	"bufio"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"auditek/internal/auth"
	"auditek/internal/container"
	"auditek/internal/correlate"
	"auditek/internal/cvedb"
	"auditek/internal/engine"
	"auditek/internal/findings"
	"auditek/internal/netscan"
	"auditek/internal/progress"
	"auditek/internal/scope"
	"auditek/internal/subdomain"
	"auditek/internal/ui"
)

func confirmAuthorization(target string) bool {
	ui.Warn("Vas a escanear: %s", ui.Bold(target))
	fmt.Println("   Confirma que tienes autorización para evaluar este objetivo.")
	fmt.Print("   ¿Continuar? (s/n): ")

	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))

	return input == "s" || input == "si" || input == "sí" || input == "y" || input == "yes"
}

// confirmInternalAuthorization es la barrera reforzada para escaneos contra
// rangos de red privada (10.x, 172.16-31.x, 192.168.x, loopback). Escanear
// una red interna implica que quien lo corre YA ESTÁ DENTRO de esa red —
// es exactamente el escenario de reconocimiento previo a movimiento lateral,
// así que exige escribir una frase completa en vez de un simple "s", y deja
// un registro local de la confirmación con motivo declarado.
func confirmInternalAuthorization(target string) bool {
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  ATENCIÓN: '%s' es un rango de RED PRIVADA/INTERNA.\n", target)
	fmt.Println("  Escanear una red interna implica que ya tienes acceso a ella —")
	fmt.Println("  es el mismo tipo de reconocimiento que precede a un movimiento")
	fmt.Println("  lateral. Esto requiere autorización explícita para evaluar ESTA")
	fmt.Println("  red interna específicamente, no solo el sitio público del cliente.")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Print("  Escribe exactamente AUTORIZADO para confirmar que cuentas con\n  autorización explícita para escanear esta red interna: ")

	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input != "AUTORIZADO" {
		return false
	}

	logInternalScanAttempt(target)
	return true
}

// logInternalScanAttempt deja constancia local de que se confirmó un
// escaneo interno — no es un control de acceso (no impide nada por sí
// mismo), es trazabilidad para que quien lo corre tenga registro propio
// de cuándo y contra qué confirmó autorización.
func logInternalScanAttempt(target string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	dir := filepath.Join(home, ".auditek")
	os.MkdirAll(dir, 0700)
	path := filepath.Join(dir, "internal-scan-audit.log")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s | target=%s | confirmado=AUTORIZADO\n", time.Now().Format(time.RFC3339), target)
}

func normalizeTarget(target string) string {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return "https://" + target
	}
	return target
}

func validateStealthPrereqs(scopeFile, target string) error {
	if scopeFile == "" {
		return fmt.Errorf("--stealth requiere --scope <archivo>")
	}

	s, err := scope.Load(scopeFile)
	if err != nil {
		return err
	}

	token, err := auth.LoadToken()
	if err != nil {
		return fmt.Errorf("token no válido — ejecuta 'auditek auth' primero: %w", err)
	}
	if !token.IsValid() {
		return fmt.Errorf("token expirado — ejecuta 'auditek auth' nuevamente")
	}

	if !s.IsAuthorized(hostOnly(target)) {
		return fmt.Errorf("target '%s' no está autorizado en el scope declarado", target)
	}

	return nil
}

// hostOnly extrae el host (sin protocolo/puerto) para comparar contra scope.yaml,
// que declara dominios bare. Si target no es una URL válida (ej. IP o CIDR de red),
// lo devuelve tal cual.
func hostOnly(target string) string {
	t := target
	if !strings.Contains(t, "://") {
		t = "https://" + t
	}
	u, err := url.Parse(t)
	if err != nil || u.Hostname() == "" {
		return target
	}
	return u.Hostname()
}

// headerList implementa flag.Value para permitir --header repetido varias
// veces en la misma invocación (ej. --header "Cookie: a=1" --header "X-Api-Key: xyz").
type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error {
	*h = append(*h, v)
	return nil
}

// boolFlags lista los flags que NO toman valor (booleanos) — cualquier otro
// flag reconocido se asume que consume el siguiente token como su valor.
var boolFlags = map[string]bool{
	"--stealth": true, "-stealth": true,
	"--yes": true, "-yes": true,
	"--internal-yes": true, "-internal-yes": true,
	"--v": true, "-v": true,
	"--vv": true, "-vv": true,
	"--vvv": true, "-vvv": true,
	"--ct": true, "-ct": true,
}

// reorderArgs mueve los flags (--x) al frente y deja los posicionales al final,
// porque flag.Parse detiene el parseo en el primer argumento no-flag — sin esto,
// "scan web <target> --yes" o "report <id> --format json" ignoran/rompen el flag.
func reorderArgs(args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if !boolFlags[a] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		} else {
			positional = append(positional, a)
		}
	}
	return append(flags, positional...)
}

func runScanCmd(args []string) error {
	args = reorderArgs(args)

	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	stealthMode := fs.Bool("stealth", false, "modo evasión (requiere auth + scope)")
	scopeFile := fs.String("scope", "", "archivo scope.yaml (requerido con --stealth)")
	skipConfirm := fs.Bool("yes", false, "omite la confirmación de autorización")
	delayMs := fs.Int("delay", 150, "pausa entre requests en ms (0 = sin límite, no recomendado)")
	ports := fs.String("ports", "top100", "puertos a escanear (solo scan network): top100 | 80,443 | 1-1000")
	profile := fs.String("profile", "normal", "solo scan network: fast | normal | deep")
	excludeRules := fs.String("exclude-rule", "", "IDs de reglas a excluir, separados por coma (ej. missing-csp-header,directory-listing-enabled)")
	rulesDir := fs.String("rules", "rules", "directorio de reglas a cargar")
	internalYes := fs.Bool("internal-yes", false, "omite la confirmación reforzada para escaneos de red privada/interna (usar con extremo cuidado)")
	var headers headerList
	fs.Var(&headers, "header", "header custom a enviar en cada request (solo scan web); repetible, ej. --header \"Authorization: Bearer xyz\"")
	cookie := fs.String("cookie", "", "cookie a enviar en cada request (solo scan web), ej. --cookie \"session=abc123\"")
	depth := fs.String("depth", "normal", "solo scan subdomains: fast | normal | deep")
	focus := fs.String("focus", "", "solo scan subdomains: categorías separadas por coma (admin,dev,infra,remote-access,devops,web,sensitive,data) — si se pasa, ignora --depth")
	wordlistFile := fs.String("wordlist", "", "solo scan subdomains: archivo externo (una entrada por línea) — ignora --depth y --focus")
	ctLogs := fs.Bool("ct", false, "solo scan subdomains: además consulta Certificate Transparency (crt.sh) para descubrir subdominios reales")
	execHook := fs.String("exec-hook", "", "ruta a un programa externo (tuyo) a ejecutar tras el scan pasivo; debe imprimir en stdout un array JSON con el mismo formato de 'auditek import' — ver README")
	exportFmt := fs.String("export", "", "exportar el reporte sin preguntar: html | none (vacío = preguntar interactivamente)")
	vLvl1 := fs.Bool("v", false, "verbose: sub-pasos y evidencia completa por hallazgo")
	vLvl2 := fs.Bool("vv", false, "más verbose: inventario de red/HTTP (hosts, puertos, reglas)")
	vLvl3 := fs.Bool("vvv", false, "aún más verbose: traza de depuración (banners crudos, correlación)")
	fs.Parse(args)

	switch {
	case *vLvl3:
		ui.SetVerbosity(3)
	case *vLvl2:
		ui.SetVerbosity(2)
	case *vLvl1:
		ui.SetVerbosity(1)
	}

	rest := fs.Args()
	if len(rest) < 2 {
		return fmt.Errorf("uso: auditek scan [network|web|container] <target> [flags]")
	}
	scanType := rest[0]
	target := rest[1]
	excluded := parseExcludeList(*excludeRules)

	if *stealthMode {
		if err := validateStealthPrereqs(*scopeFile, target); err != nil {
			return err
		}
	} else if scanType == "network" && netscan.IsPrivateTarget(target) {
		if *internalYes {
			logInternalScanAttempt(target + " (confirmado vía --internal-yes)")
		} else if !confirmInternalAuthorization(target) {
			fmt.Println("Escaneo cancelado.")
			return nil
		}
	} else if !*skipConfirm && scanType != "container" {
		if !confirmAuthorization(target) {
			fmt.Println("Escaneo cancelado.")
			return nil
		}
	}

	switch scanType {
	case "network":
		return runNetworkScan(target, *stealthMode, *ports, *profile, excluded, *rulesDir, *execHook, *exportFmt)
	case "web":
		return runWebScan(target, *stealthMode, *delayMs, excluded, *rulesDir, parseHeaders([]string(headers), *cookie), *execHook, *exportFmt)
	case "subdomains":
		return runSubdomainScan(target, *depth, *focus, *wordlistFile, *ctLogs)
	case "container":
		return runContainerScan(target, excluded, *exportFmt)
	default:
		return fmt.Errorf("tipo de escaneo no reconocido: %s", scanType)
	}
}

func parseExcludeList(spec string) map[string]bool {
	m := map[string]bool{}
	if spec == "" {
		return m
	}
	for _, id := range strings.Split(spec, ",") {
		id = strings.TrimSpace(id)
		if id != "" {
			m[id] = true
		}
	}
	return m
}

// parseHeaders convierte los --header "Nombre: Valor" y el --cookie en un
// mapa listo para el HTTPScanner. Un header mal formado (sin ":") se ignora
// con un aviso, en vez de abortar todo el escaneo por un typo.
func parseHeaders(raw []string, cookie string) map[string]string {
	h := map[string]string{}
	for _, r := range raw {
		parts := strings.SplitN(r, ":", 2)
		if len(parts) != 2 {
			ui.Warn("--header ignorado (formato esperado 'Nombre: Valor'): %q", r)
			continue
		}
		h[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	if cookie != "" {
		h["Cookie"] = cookie
	}
	return h
}

func runSubdomainScan(domain, depth, focusSpec, wordlistFile string, useCT bool) error {
	// quita protocolo si el usuario lo puso por costumbre (scan subdomains https://x.cl)
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimSuffix(domain, "/")

	var wordlist []string
	var source string

	if wordlistFile != "" {
		wl, err := subdomain.LoadWordlistFile(wordlistFile)
		if err != nil {
			return fmt.Errorf("error leyendo wordlist externa: %w", err)
		}
		wordlist = wl
		source = fmt.Sprintf("archivo externo (%s, %d entradas)", wordlistFile, len(wl))
	} else {
		var focus []string
		if focusSpec != "" {
			for _, c := range strings.Split(focusSpec, ",") {
				focus = append(focus, strings.TrimSpace(c))
			}
		}
		wordlist = subdomain.BuildWordlist(depth, focus)
		if focusSpec != "" {
			source = fmt.Sprintf("foco: %s (%d entradas)", focusSpec, len(wordlist))
		} else {
			source = fmt.Sprintf("profundidad: %s (%d entradas)", depth, len(wordlist))
		}
	}

	ui.Title("Escaneo de subdominios", domain)

	// Fuente extra: Certificate Transparency (crt.sh). Descubre nombres reales
	// que la wordlist nunca adivinaría; se fusionan con los candidatos y se
	// confirman por DNS igual que el resto.
	ctSet := map[string]bool{}
	if useCT {
		ui.Step("Consultando Certificate Transparency %s", ui.Gray("· crt.sh"))
		ctLabels, err := subdomain.FetchCTLogs(domain, 20*time.Second)
		if err != nil {
			ui.Warn("CT no disponible (%v) — sigo solo con la wordlist", err)
		} else {
			for _, l := range ctLabels {
				ctSet[l] = true
			}
			before := len(wordlist)
			wordlist = subdomain.MergeCandidates(wordlist, ctLabels)
			ui.OK("CT aportó %d candidato(s) · %d nuevos sobre la wordlist", len(ctLabels), len(wordlist)-before)
		}
	}

	ui.Step("Resolviendo subdominios %s", ui.Gray("· "+source))
	ui.Detail(2, "candidatos: %d · concurrencia 20 · timeout 3s", len(wordlist))
	results := subdomain.Enumerate(domain, wordlist, 20, 3*time.Second)
	ui.OK("Resolución completa · %d subdominio(s) con respuesta", len(results))

	store, err := findings.Open()
	if err != nil {
		return err
	}
	defer store.Close()

	scanID := findings.NewScanID()
	if err := store.SaveScan(findings.Scan{
		ID: scanID, Type: "subdomains", Target: domain,
		StartedAt: time.Now(), Stealth: false,
	}); err != nil {
		return err
	}

	var toSave []findings.Finding
	for _, r := range results {
		internalNote := ""
		for _, ip := range r.IPs {
			if netscan.IsPrivateTarget(ip) {
				internalNote = " (resuelve a IP privada — posible exposición de topología interna)"
				break
			}
		}
		src := "wordlist DNS"
		if ctSet[r.Subdomain] {
			src = "Certificate Transparency + DNS"
		}
		toSave = append(toSave, findings.Finding{
			ScanID:    scanID,
			RuleID:    "subdomain-discovered",
			RuleName:  fmt.Sprintf("Subdominio encontrado: %s", r.FQDN),
			Target:    r.FQDN,
			Severity:  "info",
			Evidence:  fmt.Sprintf("Resuelve a: %s%s [fuente: %s]", strings.Join(r.IPs, ", "), internalNote, src),
			Timestamp: time.Now(),
		})
	}
	if err := store.SaveFindings(scanID, toSave); err != nil {
		return err
	}

	fmt.Println()
	ui.OK("Escaneo completo %s · %d subdominio(s) encontrado(s)", ui.Gray("("+scanID+")"), len(results))
	ui.Info("Genera el reporte con: auditek report %s", scanID)
	return nil
}

func runWebScan(target string, stealth bool, delayMs int, excluded map[string]bool, rulesDir string, headers map[string]string, execHook string, exportFmt string) error {
	target = normalizeTarget(target)

	ui.Title("Escaneo web", target)

	ui.Step("Cargando reglas")
	rules, err := engine.LoadRules(rulesDir)
	if err != nil {
		return fmt.Errorf("error cargando reglas: %w", err)
	}
	rules = engine.FilterRules(rules, excluded)
	ui.Detail(1, "%d reglas activas desde %q (excluidas: %d)", len(rules), rulesDir, len(excluded))
	if len(headers) > 0 {
		ui.Detail(2, "headers custom: %d · delay %dms", len(headers), delayMs)
	}

	ui.Step("Analizando %s", target)
	scanner := engine.NewHTTPScanner(rules, delayMs, headers)
	engineFindings := scanner.Scan(target)
	ui.OK("Análisis web completo · %d coincidencia(s) de regla", len(engineFindings))

	store, err := findings.Open()
	if err != nil {
		return fmt.Errorf("error abriendo base de datos local: %w", err)
	}
	defer store.Close()

	scanID := findings.NewScanID()
	if err := store.SaveScan(findings.Scan{
		ID: scanID, Type: "web", Target: target,
		StartedAt: time.Now(), Stealth: stealth,
	}); err != nil {
		return err
	}

	var toSave []findings.Finding
	for _, f := range engineFindings {
		toSave = append(toSave, findings.Finding{
			ScanID: scanID, RuleID: f.RuleID, RuleName: f.RuleName,
			Target: f.Target, Severity: f.Severity,
			CVE: strings.Join(f.CVE, ","), Impact: f.Impact, Evidence: f.Evidence,
			Timestamp: f.Timestamp,
		})
	}

	if execHook != "" {
		ui.Step("Ejecutando hook externo: %s", execHook)
		hookFindings := runExecHook(execHook, target, scanID)
		ui.Detail(1, "hook aportó %d hallazgo(s)", len(hookFindings))
		toSave = append(toSave, hookFindings...)
	}

	correlated := correlate.Correlate(scanID, toSave)
	ui.Detail(3, "correlación aportó %d hallazgo(s) derivado(s)", len(correlated))
	toSave = append(toSave, correlated...)

	if err := store.SaveFindings(scanID, toSave); err != nil {
		return err
	}

	// Mostrar hallazgos en pantalla
	displayFindings(toSave)

	// Ofrecer exportar HTML
	maybeExport(exportFmt, scanID, toSave, target)
	fmt.Println()
	ui.OK("Escaneo completo %s · %d hallazgos", ui.Gray("("+scanID+")"), len(toSave))
	ui.Info("Genera el reporte con: auditek report %s", scanID)

	return nil
}

// lateralMovementRisks son protocolos de gestión remota que, si están
// abiertos y accesibles dentro de una red interna, son el vector típico
// de movimiento lateral (RDP, WinRM, SMB) — no se prueba nada activamente,
// solo se marca el puerto abierto con severidad más alta y contexto claro,
// porque la detección pasiva de "está abierto" ya es información de riesgo
// real cuando el escaneo es interno.
var lateralMovementRisks = map[int]struct {
	name     string
	severity string
	impact   string
}{
	3389: {
		"RDP accesible dentro de la red interna", "high",
		"Si un atacante obtiene credenciales válidas (por phishing, reuso de contraseñas, o fuerza bruta), RDP es uno de los vectores más comunes de movimiento lateral entre estaciones y servidores Windows.",
	},
	5985: {
		"WinRM (HTTP) accesible dentro de la red interna", "high",
		"WinRM permite ejecución remota de comandos PowerShell — con credenciales válidas o un hash robado (pass-the-hash), es un vector directo de movimiento lateral y ejecución remota.",
	},
	5986: {
		"WinRM (HTTPS) accesible dentro de la red interna", "high",
		"Igual que WinRM sobre HTTP: permite ejecución remota de comandos con credenciales válidas — vector directo de movimiento lateral.",
	},
	445: {
		"SMB accesible dentro de la red interna", "high",
		"SMB es el vector de propagación más común en incidentes de ransomware (ej. WannaCry, NotPetya) y permite movimiento lateral vía admin shares (C$, ADMIN$) con credenciales válidas o robadas.",
	},
	22: {
		"SSH accesible dentro de la red interna", "medium",
		"Si las claves SSH se reutilizan entre servidores (patrón común), comprometer una máquina puede dar acceso directo a otras — revisar si hay reuso de claves privadas entre hosts.",
	},
}

func lateralMovementFinding(scanID, host string, port int) *findings.Finding {
	risk, ok := lateralMovementRisks[port]
	if !ok {
		return nil
	}
	return &findings.Finding{
		ScanID:    scanID,
		RuleID:    "lateral-movement-surface",
		RuleName:  risk.name,
		Target:    fmt.Sprintf("%s:%d", host, port),
		Severity:  risk.severity,
		Impact:    risk.impact,
		Evidence:  "Puerto de gestión remota accesible desde dentro de la red — sin intento de conexión ni autenticación.",
		Timestamp: time.Now(),
	}
}

func runNetworkScan(target string, stealth bool, portsSpec string, profileName string, excluded map[string]bool, rulesDir string, execHook string, exportFmt string) error {
	hosts, err := netscan.ExpandHosts(target)
	if err != nil {
		return fmt.Errorf("target inválido: %w", err)
	}

	ui.Title("Escaneo de red", target)

	// Si --ports no se especificó (usa default "top100"), usar profile
	var ports []int
	if portsSpec != "top100" {
		// Usuario especificó puertos explícitamente
		ports, err = netscan.ParsePorts(portsSpec)
		if err != nil {
			return fmt.Errorf("especificación de puertos inválida: %w", err)
		}
	} else {
		// Usar profile
		prof := netscan.GetProfile(profileName)
		ports = prof.Ports
		ui.Detail(1, "perfil: %s — %s", prof.Name, prof.Description)
	}

	prof := netscan.GetProfile(profileName)
	opts := netscan.ScanOptions{
		Timeout:     prof.Timeout,
		Concurrency: prof.Concurrency,
	}

	ui.Step("Escaneando puertos %s", ui.Gray(fmt.Sprintf("· %d host(s) × %d puerto(s)", len(hosts), len(ports))))
	ui.Detail(2, "concurrencia %d · timeout %v", prof.Concurrency, prof.Timeout)
	ui.Detail(3, "lista de puertos: %v", ports)

	// Crear barra de progreso
	totalChecks := len(hosts) * len(ports)
	bar := progress.NewProgressBar("Puertos", "abiertos", totalChecks)
	foundPorts := 0

	// Callback para actualizar progreso
	opts.ProgressFn = func(completed, total int) {
		// Contar puertos abiertos es complejo, por ahora solo mostrar progreso de conexiones
		bar.Update(completed, foundPorts)
	}

	results := netscan.ScanMultipleHosts(hosts, ports, opts)

	// Contar puertos abiertos
	for _, hostPorts := range results {
		foundPorts += len(hostPorts)
	}

	bar.Update(totalChecks, foundPorts) // fija el conteo final antes del resumen
	bar.Done()

	isInternal := netscan.IsPrivateTarget(target)
	if isInternal {
		ui.Detail(1, "objetivo en rango privado/interno — se marca superficie de movimiento lateral")
	}

	ui.Step("Identificando servicios y CVEs")
	tcpRules, err := engine.LoadRules(rulesDir)
	if err != nil {
		return fmt.Errorf("error cargando reglas: %w", err)
	}
	tcpRules = engine.FilterRules(tcpRules, excluded)
	ui.Detail(1, "%d reglas TCP activas (excluidas: %d)", len(tcpRules), len(excluded))
	tcpScanner := engine.NewTCPScanner(tcpRules)

	allowedPorts := map[int]bool{}
	for _, p := range ports {
		allowedPorts[p] = true
	}

	store, err := findings.Open()
	if err != nil {
		return err
	}
	defer store.Close()

	scanID := findings.NewScanID()
	if err := store.SaveScan(findings.Scan{
		ID: scanID, Type: "network", Target: target,
		StartedAt: time.Now(), Stealth: stealth,
	}); err != nil {
		return err
	}

	var toSave []findings.Finding
	totalOpen := 0
	for host, ports := range results {
		cdnProvider, behindCDN := netscan.ResolveCDNProvider(host)

		for _, p := range ports {
			totalOpen++
			ui.Detail(3, "%s:%d abierto (%s) banner=%q", host, p.Port, p.Service, p.Banner)
			ruleName := fmt.Sprintf("Puerto abierto: %d (%s)", p.Port, p.Service)
			evidence := p.Banner
			if p.Banner == "" && behindCDN {
				ruleName = fmt.Sprintf("Puerto abierto sin servicio backend visible: %d (%s)", p.Port, p.Service)
				evidence = fmt.Sprintf("El handshake TCP fue aceptado por el borde de %s (CDN/proxy anycast), pero no se recibió respuesta de aplicación. No se pudo confirmar que exista un servicio real detrás de este puerto — es un patrón esperado en infraestructura de CDN sin passthrough L4 configurado para él.", cdnProvider)
			}
			toSave = append(toSave, findings.Finding{
				ScanID:    scanID,
				RuleID:    "open-port",
				RuleName:  ruleName,
				Target:    fmt.Sprintf("%s:%d", host, p.Port),
				Severity:  "info",
				Evidence:  evidence,
				Timestamp: time.Now(),
			})

			if isInternal {
				if f := lateralMovementFinding(scanID, host, p.Port); f != nil {
					toSave = append(toSave, *f)
				}
			}

			for _, fp := range engine.ExtractFingerprintFromBanner(p.Banner) {
				for _, cve := range cvedb.Lookup(fp.Product, fp.Version) {
					toSave = append(toSave, findings.Finding{
						ScanID:    scanID,
						RuleID:    cve.CVE,
						RuleName:  fmt.Sprintf("%s (%s %s)", cve.Description, fp.Product, fp.Version),
						Target:    fmt.Sprintf("%s:%d", host, p.Port),
						Severity:  cve.Severity,
						CVE:       cve.CVE,
						Impact:    cve.Impact,
						Evidence:  fmt.Sprintf("Banner: %s", p.Banner),
						Timestamp: time.Now(),
					})
				}
			}
		}

		for _, tf := range tcpScanner.Scan(host, allowedPorts) {
			toSave = append(toSave, findings.Finding{
				ScanID: scanID, RuleID: tf.RuleID, RuleName: tf.RuleName,
				Target: tf.Target, Severity: tf.Severity,
				CVE: strings.Join(tf.CVE, ","), Impact: tf.Impact, Evidence: tf.Evidence,
				Timestamp: tf.Timestamp,
			})
		}
	}

	if execHook != "" {
		ui.Step("Ejecutando hook externo: %s", execHook)
		hookFindings := runExecHook(execHook, target, scanID)
		ui.Detail(1, "hook aportó %d hallazgo(s)", len(hookFindings))
		toSave = append(toSave, hookFindings...)
	}

	correlated := correlate.Correlate(scanID, toSave)
	ui.Detail(3, "correlación aportó %d hallazgo(s) derivado(s)", len(correlated))
	toSave = append(toSave, correlated...)

	if err := store.SaveFindings(scanID, toSave); err != nil {
		return err
	}

	// Mostrar hallazgos en pantalla
	displayFindings(toSave)

	// Ofrecer exportar HTML
	maybeExport(exportFmt, scanID, toSave, target)

	fmt.Println()
	ui.OK("Escaneo completo %s · %d puertos abiertos", ui.Gray("("+scanID+")"), totalOpen)
	ui.Info("Genera el reporte con: auditek report %s", scanID)

	return nil
}

// runContainerScan hace análisis estático de un Dockerfile (archivo o
// directorio que lo contenga) y reporta malas prácticas y secretos.
func runContainerScan(target string, excluded map[string]bool, exportFmt string) error {
	dockerfilePath, err := resolveDockerfile(target)
	if err != nil {
		return err
	}

	content, err := os.ReadFile(dockerfilePath)
	if err != nil {
		return fmt.Errorf("error leyendo Dockerfile: %w", err)
	}

	ui.Title("Análisis de contenedor", dockerfilePath)
	ui.Step("Analizando Dockerfile")
	issues := container.ScanDockerfile(string(content))
	ui.Detail(1, "%d issue(s) detectada(s) antes de filtrar exclusiones", len(issues))

	store, err := findings.Open()
	if err != nil {
		return fmt.Errorf("error abriendo base de datos local: %w", err)
	}
	defer store.Close()

	scanID := findings.NewScanID()
	if err := store.SaveScan(findings.Scan{
		ID: scanID, Type: "container", Target: dockerfilePath,
		StartedAt: time.Now(), Stealth: false,
	}); err != nil {
		return err
	}

	var toSave []findings.Finding
	for _, is := range issues {
		if excluded[is.RuleID] {
			continue
		}
		targetRef := dockerfilePath
		if is.Line > 0 {
			targetRef = fmt.Sprintf("%s:%d", dockerfilePath, is.Line)
		}
		toSave = append(toSave, findings.Finding{
			ScanID:    scanID,
			RuleID:    is.RuleID,
			RuleName:  is.RuleName,
			Target:    targetRef,
			Severity:  is.Severity,
			Impact:    is.Impact,
			Evidence:  is.Evidence,
			Timestamp: time.Now(),
		})
	}

	toSave = append(toSave, correlate.Correlate(scanID, toSave)...)

	if err := store.SaveFindings(scanID, toSave); err != nil {
		return err
	}

	displayFindings(toSave)

	maybeExport(exportFmt, scanID, toSave, dockerfilePath)

	fmt.Println()
	ui.OK("Escaneo completo %s · %d hallazgo(s)", ui.Gray("("+scanID+")"), len(toSave))
	ui.Info("Genera el reporte con: auditek report %s", scanID)
	return nil
}

// resolveDockerfile acepta la ruta de un Dockerfile o de un directorio que lo
// contenga y devuelve la ruta al archivo.
func resolveDockerfile(target string) (string, error) {
	info, err := os.Stat(target)
	if err != nil {
		return "", fmt.Errorf("no se pudo acceder a '%s': %w", target, err)
	}
	if !info.IsDir() {
		return target, nil
	}
	for _, name := range []string{"Dockerfile", "dockerfile", "Containerfile"} {
		candidate := filepath.Join(target, name)
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no se encontró un Dockerfile en el directorio '%s'", target)
}

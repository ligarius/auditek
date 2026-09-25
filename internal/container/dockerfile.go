// Package container hace análisis ESTÁTICO de Dockerfiles: detecta malas
// prácticas de seguridad y secretos hardcodeados sin necesidad de construir
// la imagen ni de docker/trivy. Es la base de `auditek scan container`.
package container

import (
	"regexp"
	"strings"
)

// Finding es un hallazgo de análisis de contenedor. Se mantiene desacoplado de
// internal/findings para que el paquete sea puro y testeable.
type Finding struct {
	RuleID   string
	RuleName string
	Severity string // critical | high | medium | low | info
	Impact   string
	Evidence string
	Line     int // línea del Dockerfile (1-indexado); 0 si no aplica
}

type instruction struct {
	verb string // FROM, RUN, ENV, ...
	args string
	line int // línea de inicio (1-indexado)
}

var (
	reSecretKey = regexp.MustCompile(`(?i)\b([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)[A-Z0-9_]*)\s*=\s*(\S+)`)
	reSecretVal = regexp.MustCompile(`AKIA[0-9A-Z]{16}|(?:sk|rk)_live_[0-9A-Za-z]{16,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|AIza[0-9A-Za-z_\-]{35}|xox[baprs]-[0-9A-Za-z\-]{10,}`)
	rePipeShell = regexp.MustCompile(`(?i)(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:sh|bash)\b`)
	reAddRemote = regexp.MustCompile(`(?i)^https?://`)
	reChmod777  = regexp.MustCompile(`chmod\s+(?:-[A-Za-z]+\s+)*777`)
	reAsStage   = regexp.MustCompile(`(?i)\s+AS\s+\S+$`)
	reVarValue  = regexp.MustCompile(`\$\{?[A-Za-z_]`) // valor tipo $VAR / ${VAR}: no es secreto hardcodeado
)

// ScanDockerfile analiza el contenido de un Dockerfile y devuelve los hallazgos.
func ScanDockerfile(content string) []Finding {
	instrs := parse(content)
	var out []Finding

	lastFrom := -1
	hasNonRootUser := false
	sawInstruction := false

	for i, in := range instrs {
		sawInstruction = true
		switch strings.ToUpper(in.verb) {
		case "FROM":
			lastFrom = i
			hasNonRootUser = false // cada stage reinicia el usuario efectivo
			if f, ok := checkUnpinned(in); ok {
				out = append(out, f)
			}
		case "USER":
			u := strings.ToLower(strings.TrimSpace(in.args))
			hasNonRootUser = u != "" && u != "root" && u != "0"
		case "ENV", "ARG":
			out = append(out, checkSecrets(in)...)
		case "RUN":
			out = append(out, checkRun(in)...)
			out = append(out, checkSecrets(in)...)
		case "ADD":
			if f, ok := checkAddRemote(in); ok {
				out = append(out, f)
			}
			out = append(out, checkCopyContext(in, "ADD")...)
		case "COPY":
			out = append(out, checkCopyContext(in, "COPY")...)
		case "EXPOSE":
			out = append(out, checkExpose(in)...)
		}
	}

	// Corre como root si el stage final nunca fijó un USER no-root.
	if sawInstruction && lastFrom >= 0 && !hasNonRootUser {
		out = append(out, Finding{
			RuleID:   "dockerfile-runs-as-root",
			RuleName: "Contenedor corre como root",
			Severity: "medium",
			Impact:   "Sin una instrucción USER no-root, el proceso corre como root dentro del contenedor; si es comprometido, el atacante tiene root en el contenedor y una mejor posición para escapar al host.",
			Evidence: "No hay instrucción USER no-root en el stage final",
			Line:     instrs[lastFrom].line,
		})
	}

	return out
}

func parse(content string) []instruction {
	var instrs []instruction
	var cur strings.Builder
	startLine := 0

	flush := func() {
		text := strings.TrimSpace(cur.String())
		cur.Reset()
		if text == "" {
			return
		}
		parts := strings.SplitN(text, " ", 2)
		args := ""
		if len(parts) > 1 {
			args = strings.TrimSpace(parts[1])
		}
		instrs = append(instrs, instruction{verb: parts[0], args: args, line: startLine})
	}

	for i, raw := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			if cur.Len() == 0 {
				continue
			}
		}
		if cur.Len() == 0 {
			startLine = i + 1
		}
		cont := strings.HasSuffix(trimmed, "\\")
		trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, "\\"))
		if cur.Len() > 0 {
			cur.WriteString(" ")
		}
		cur.WriteString(trimmed)
		if !cont {
			flush()
		}
	}
	flush()
	return instrs
}

func checkUnpinned(in instruction) (Finding, bool) {
	image := in.args
	if idx := reAsStage.FindStringIndex(image); idx != nil {
		image = image[:idx[0]]
	}
	image = strings.TrimSpace(image)
	if image == "" || strings.EqualFold(image, "scratch") || strings.HasPrefix(image, "$") {
		return Finding{}, false
	}
	if strings.Contains(image, "@sha256:") { // digest fijado
		return Finding{}, false
	}
	tag := ""
	if at := strings.LastIndex(image, ":"); at != -1 && !strings.Contains(image[at:], "/") {
		tag = image[at+1:]
	}
	if tag == "" || strings.EqualFold(tag, "latest") {
		return Finding{
			RuleID:   "dockerfile-unpinned-base",
			RuleName: "Imagen base sin versión fijada",
			Severity: "medium",
			Impact:   "Usar 'latest' o una imagen sin tag hace los builds no reproducibles y puede introducir cambios o vulnerabilidades sin aviso; fija una versión o un digest @sha256.",
			Evidence: "FROM " + in.args,
			Line:     in.line,
		}, true
	}
	return Finding{}, false
}

func checkSecrets(in instruction) []Finding {
	var out []Finding
	if m := reSecretKey.FindStringSubmatch(in.args); m != nil {
		val := strings.Trim(m[2], `"'`)
		if val != "" && !reVarValue.MatchString(val) { // ignora referencias a variables
			out = append(out, Finding{
				RuleID:   "dockerfile-hardcoded-secret",
				RuleName: "Secreto hardcodeado en el Dockerfile",
				Severity: "critical",
				Impact:   "Un secreto embebido en ENV/ARG/RUN queda en las capas de la imagen y en el historial de build — cualquiera con acceso a la imagen puede extraerlo. Usa secrets de build o variables en tiempo de ejecución.",
				Evidence: m[1] + "=" + mask(val),
				Line:     in.line,
			})
		}
	}
	if m := reSecretVal.FindString(in.args); m != "" {
		out = append(out, Finding{
			RuleID:   "dockerfile-hardcoded-secret",
			RuleName: "Secreto hardcodeado en el Dockerfile",
			Severity: "critical",
			Impact:   "El Dockerfile contiene material sensible reconocible (clave live, llave privada o token) que quedará en las capas de la imagen.",
			Evidence: mask(m),
			Line:     in.line,
		})
	}
	return out
}

func checkRun(in instruction) []Finding {
	var out []Finding
	if rePipeShell.MatchString(in.args) {
		out = append(out, Finding{
			RuleID:   "dockerfile-remote-pipe-shell",
			RuleName: "Código remoto ejecutado directo en shell (curl|bash)",
			Severity: "high",
			Impact:   "Descargar y ejecutar un script directamente (curl ... | bash) confía ciegamente en el servidor remoto y en la red: si cualquiera es comprometido, se ejecuta código arbitrario en el build. Descarga, verifica el hash y luego ejecuta.",
			Evidence: truncate(in.args, 120),
			Line:     in.line,
		})
	}
	if strings.Contains(in.args, "sudo ") {
		out = append(out, Finding{
			RuleID:   "dockerfile-sudo",
			RuleName: "Uso de sudo dentro del Dockerfile",
			Severity: "low",
			Impact:   "sudo en un Dockerfile suele ser innecesario (el build ya corre como root) y puede dejar binarios setuid o configuraciones que faciliten escalar privilegios en runtime.",
			Evidence: truncate(in.args, 120),
			Line:     in.line,
		})
	}
	if reChmod777.MatchString(in.args) {
		out = append(out, Finding{
			RuleID:   "dockerfile-chmod-777",
			RuleName: "Permisos world-writable (chmod 777)",
			Severity: "medium",
			Impact:   "chmod 777 da permisos de escritura a cualquier usuario; si un proceso del contenedor es comprometido, puede modificar esos archivos (binarios, configs) y persistir o escalar.",
			Evidence: truncate(in.args, 120),
			Line:     in.line,
		})
	}
	return out
}

func checkAddRemote(in instruction) (Finding, bool) {
	for _, f := range strings.Fields(in.args) {
		if reAddRemote.MatchString(f) {
			return Finding{
				RuleID:   "dockerfile-add-remote",
				RuleName: "ADD con URL remota",
				Severity: "medium",
				Impact:   "ADD con una URL descarga sin verificar integridad y no cachea bien; además ADD expande tarballs automáticamente. Prefiere COPY, o curl con verificación de hash en un RUN.",
				Evidence: truncate(in.args, 120),
				Line:     in.line,
			}, true
		}
	}
	return Finding{}, false
}

func checkCopyContext(in instruction, verb string) []Finding {
	var real []string
	for _, f := range strings.Fields(in.args) {
		if strings.HasPrefix(f, "--") { // ignora flags como --chown=...
			continue
		}
		real = append(real, f)
	}
	if len(real) >= 1 && real[0] == "." {
		return []Finding{{
			RuleID:   "dockerfile-copy-context",
			RuleName: verb + " de todo el contexto de build",
			Severity: "low",
			Impact:   "Copiar todo el contexto (" + verb + " . ) puede meter en la imagen archivos sensibles no intencionados (.env, .git, llaves) si no hay un .dockerignore adecuado.",
			Evidence: verb + " " + truncate(in.args, 100),
			Line:     in.line,
		}}
	}
	return nil
}

func checkExpose(in instruction) []Finding {
	for _, f := range strings.Fields(in.args) {
		port := f
		if slash := strings.Index(port, "/"); slash != -1 {
			port = port[:slash]
		}
		if port == "22" {
			return []Finding{{
				RuleID:   "dockerfile-expose-ssh",
				RuleName: "Puerto SSH (22) expuesto en la imagen",
				Severity: "low",
				Impact:   "Exponer SSH desde un contenedor es un antipatrón: amplía la superficie de ataque y suele indicar que se usa el contenedor como una VM. Gestiona el acceso por otros medios.",
				Evidence: "EXPOSE " + in.args,
				Line:     in.line,
			}}
		}
	}
	return nil
}

func mask(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 4 {
		return "****"
	}
	n := 4
	if len(s) < 8 {
		n = 2
	}
	return s[:n] + strings.Repeat("*", 4)
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

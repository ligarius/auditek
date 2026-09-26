// Package ui centraliza el estilo de la salida en terminal: colores ANSI,
// símbolos, badges de severidad y helpers de sección/paso. El color se
// desactiva solo cuando la salida no es una terminal (pipe o redirección a
// archivo), con la variable de entorno NO_COLOR, o con TERM=dumb — así los
// reportes redirigidos (`auditek ... > out.txt`) quedan en texto plano limpio.
package ui

import (
	"fmt"
	"os"
	"strings"
)

var enabled = detectColor()

func detectColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false // salida redirigida o a archivo: sin color ni animación
	}
	enableVT() // Windows: habilita secuencias ANSI; no-op en el resto
	return true
}

// SetEnabled fuerza el color on/off (p. ej. desde un flag --color/--no-color).
func SetEnabled(v bool) { enabled = v }

// Enabled indica si el color/animación está activo (hay TTY).
func Enabled() bool { return enabled }

// Códigos ANSI.
const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cBlue   = "\033[34m"
	cCyan   = "\033[36m"
	cGray   = "\033[90m"
	cCrit   = "\033[1;91m" // rojo intenso + negrita para crítico
)

func paint(code, s string) string {
	if !enabled {
		return s
	}
	return code + s + cReset
}

// sym devuelve el glifo bonito con TTY, o un equivalente ASCII sin él.
func sym(fancy, plain string) string {
	if enabled {
		return fancy
	}
	return plain
}

func Bold(s string) string   { return paint(cBold, s) }
func Dim(s string) string    { return paint(cDim, s) }
func Red(s string) string    { return paint(cRed, s) }
func Green(s string) string  { return paint(cGreen, s) }
func Yellow(s string) string { return paint(cYellow, s) }
func Blue(s string) string   { return paint(cBlue, s) }
func Cyan(s string) string   { return paint(cCyan, s) }
func Gray(s string) string   { return paint(cGray, s) }

// Rule devuelve una línea horizontal de n caracteres (─ con TTY, - sin él).
func Rule(n int) string { return strings.Repeat(sym("─", "-"), n) }

// Title imprime un encabezado de sección: título en negrita y subtítulo en gris.
func Title(title, subtitle string) {
	fmt.Println()
	head := Bold(title)
	if subtitle != "" {
		head += "  " + Gray(sym("·", "-")+" "+subtitle)
	}
	fmt.Println(head)
	fmt.Println(Gray(Rule(60)))
}

// Step marca el inicio de una fase: "▶ ...".
func Step(format string, a ...any) {
	fmt.Printf("%s %s\n", Cyan(sym("▶", "»")), fmt.Sprintf(format, a...))
}

// OK marca el resultado exitoso de una fase: "✓ ...".
func OK(format string, a ...any) {
	fmt.Printf("%s %s\n", Green(sym("✓", "+")), fmt.Sprintf(format, a...))
}

// Warn imprime una advertencia no fatal: "⚠ ...".
func Warn(format string, a ...any) {
	fmt.Printf("%s %s\n", Yellow(sym("⚠", "!")), fmt.Sprintf(format, a...))
}

// Fail imprime un error: "✗ ...".
func Fail(format string, a ...any) {
	fmt.Printf("%s %s\n", Red(sym("✗", "x")), fmt.Sprintf(format, a...))
}

// Info imprime una línea secundaria en gris: "· ...".
func Info(format string, a ...any) {
	fmt.Printf("%s %s\n", Gray(sym("·", "-")), Gray(fmt.Sprintf(format, a...)))
}

// sevMeta mapea una severidad a su etiqueta corta, palabra, color ANSI y si su
// marcador va relleno (●) o hueco (○).
func sevMeta(sev string) (label, word, code string, filled bool) {
	switch strings.ToLower(sev) {
	case "critical":
		return "CRIT", "crítico", cCrit, true
	case "high":
		return "ALTO", "alto", cRed, true
	case "medium":
		return "MEDIO", "medio", cYellow, true
	case "low":
		return "BAJO", "bajo", cBlue, true
	default:
		return "INFO", "info", cGray, false
	}
}

// SeverityBadge devuelve la etiqueta corta (ancho fijo) coloreada: "CRIT ".
func SeverityBadge(sev string) string {
	label, _, code, _ := sevMeta(sev)
	return paint(code, fmt.Sprintf("%-5s", label))
}

// SeverityDot devuelve el marcador coloreado: ● (relleno) u ○ (hueco).
func SeverityDot(sev string) string {
	_, _, code, filled := sevMeta(sev)
	glyph := "○"
	if filled {
		glyph = "●"
	}
	return paint(code, sym(glyph, "*"))
}

// ColorBySeverity pinta text con el color asociado a una severidad
// (critical/high/medium/low/info). Útil para elementos que no son un hallazgo
// pero comparten la paleta, como la postura de riesgo agregada.
func ColorBySeverity(sev, text string) string {
	_, _, code, _ := sevMeta(sev)
	return paint(code, text)
}

// SeverityCount devuelve "<n> <palabra>" coloreado por severidad, o en gris si n==0.
func SeverityCount(sev string, n int) string {
	_, word, code, _ := sevMeta(sev)
	s := fmt.Sprintf("%d %s", n, word)
	if n == 0 {
		return Gray(s)
	}
	return paint(code, s)
}

// verbosity controla cuánto detalle se imprime:
//
//	0  normal   — títulos, fases, hallazgos y resumen.
//	1  -v       — sub-pasos y detalle por hallazgo (evidencia completa).
//	2  -vv      — inventario de red/HTTP (hosts, puertos, reglas cargadas).
//	3  -vvv     — traza de depuración (banners crudos, timings, correlación).
var verbosity int

// SetVerbosity fija el nivel de detalle (típicamente contando -v/-vv/-vvv).
func SetVerbosity(n int) { verbosity = n }

// Verbosity devuelve el nivel de detalle actual.
func Verbosity() int { return verbosity }

// V indica si el nivel de detalle actual alcanza al menos level.
func V(level int) bool { return verbosity >= level }

// Detail imprime una línea de detalle en gris solo si verbosity >= level,
// prefijada con un marcador tenue del nivel (v / vv / vvv).
func Detail(level int, format string, a ...any) {
	if verbosity < level {
		return
	}
	tag := strings.Repeat("v", level)
	fmt.Printf("%s %s\n",
		Gray(sym("│", "|")+fmt.Sprintf("%-3s", tag)),
		Gray(fmt.Sprintf(format, a...)))
}

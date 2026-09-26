package progress

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"auditek/internal/ui"
)

// ProgressBar renderiza una barra de progreso en una sola línea (con retorno de
// carro) mientras hay TTY; si la salida está redirigida no anima nada y solo
// imprime un resumen al terminar.
type ProgressBar struct {
	label     string
	unit      string
	total     int
	completed int
	found     int
	startTime time.Time
	mu        sync.Mutex
}

// NewProgressBar crea una barra con una etiqueta (p. ej. "Puertos") y la unidad
// de lo encontrado (p. ej. "abiertos").
func NewProgressBar(label, unit string, total int) *ProgressBar {
	return &ProgressBar{
		label:     label,
		unit:      unit,
		total:     total,
		startTime: time.Now(),
	}
}

func (p *ProgressBar) Update(completed, found int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.completed = completed
	p.found = found

	if !ui.Enabled() {
		return // sin TTY: nada de animación; el resumen sale en Done()
	}

	percent := 0
	if p.total > 0 {
		percent = completed * 100 / p.total
	}
	elapsed := time.Since(p.startTime).Seconds()
	rate := 0.0
	if elapsed > 0 {
		rate = float64(completed) / elapsed
	}
	eta := 0.0
	if rate > 0 {
		eta = float64(p.total-completed) / rate
	}

	const barLen = 20
	filled := percent * barLen / 100
	if filled > barLen {
		filled = barLen
	}
	bar := ui.Cyan(strings.Repeat("█", filled)) + ui.Gray(strings.Repeat("░", barLen-filled))
	dot := ui.Dim("·")

	// \r vuelve al inicio; \033[K limpia hasta el fin de línea por si la
	// anterior era más larga (ETA/rate cambiantes).
	fmt.Printf("\r\033[K%s %s [%s] %s  %d/%d %s %d %s %s %.0f/s %s ETA %.0fs",
		ui.Cyan("▶"),
		fmt.Sprintf("%-10s", p.label),
		bar,
		fmt.Sprintf("%3d%%", percent),
		completed, p.total,
		dot, found, p.unit,
		dot, rate,
		dot, eta,
	)
}

// Done limpia la barra animada y deja una línea de resumen "✓ etiqueta ...".
func (p *ProgressBar) Done() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if ui.Enabled() {
		fmt.Print("\r\033[K") // borra la barra en curso
	}
	ui.OK("%s  %d/%d %s %d %s",
		fmt.Sprintf("%-10s", p.label),
		p.completed, p.total,
		ui.Dim("·"), p.found, p.unit)
}

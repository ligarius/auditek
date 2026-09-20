package progress

import (
	"fmt"
	"sync"
	"time"
)

type ProgressBar struct {
	total     int
	completed int
	startTime time.Time
	mu        sync.Mutex
	found     int
}

func NewProgressBar(total int) *ProgressBar {
	return &ProgressBar{
		total:     total,
		completed: 0,
		startTime: time.Now(),
	}
}

func (p *ProgressBar) Update(completed, found int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.completed = completed
	p.found = found

	percent := 0
	if p.total > 0 {
		percent = (completed * 100) / p.total
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

	// Barra visual (20 caracteres)
	barLen := 20
	filled := (percent * barLen) / 100
	bar := ""
	for i := 0; i < barLen; i++ {
		if i < filled {
			bar += "="
		} else {
			bar += "-"
		}
	}

	fmt.Printf("\r[%s] %d%% | %d/%d puertos escaneados | %d abiertos | %.1f puertos/seg | ETA: %.0fs",
		bar, percent, completed, p.total, found, rate, eta)
}

func (p *ProgressBar) Done() {
	fmt.Printf("\n")
}

//go:build !windows

package ui

// enableVT es un no-op fuera de Windows: las terminales POSIX ya interpretan
// secuencias ANSI de forma nativa.
func enableVT() {}

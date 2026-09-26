//go:build windows

package ui

import (
	"syscall"
	"unsafe"
)

// enableVT activa el procesamiento de secuencias ANSI en la consola de Windows
// (necesario en conhost/PowerShell antiguos; Windows Terminal ya lo trae). Usa
// solo stdlib vía kernel32.
func enableVT() {
	const enableVirtualTerminalProcessing = 0x0004

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")

	h, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	if err != nil {
		return
	}
	var mode uint32
	if r, _, _ := getConsoleMode.Call(uintptr(h), uintptr(unsafe.Pointer(&mode))); r == 0 {
		return
	}
	setConsoleMode.Call(uintptr(h), uintptr(mode|enableVirtualTerminalProcessing))
}

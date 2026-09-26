package cmd

import (
	"flag"
	"fmt"

	"auditek/internal/auth"
	"auditek/internal/ui"
)

func runAuthCmd(args []string) error {
	fs := flag.NewFlagSet("auth", flag.ExitOnError)
	token := fs.String("token", "", "token profesional")
	fs.Parse(args)

	if *token == "" {
		return fmt.Errorf("debes proporcionar --token")
	}

	if err := auth.SaveToken(*token); err != nil {
		return err
	}

	ui.OK("Autenticación exitosa — credenciales guardadas en ~/.auditek/credentials.json")
	return nil
}

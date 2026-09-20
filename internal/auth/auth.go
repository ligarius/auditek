package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const credentialsFile = "credentials.json"

type Claims struct {
	ClientID  string `json:"client_id"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
	jwt.RegisteredClaims
}

type Token struct {
	Raw    string `json:"raw"`
	Claims Claims `json:"claims"`
}

func configDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".auditek")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

func SaveToken(rawToken string) error {
	claims, err := parseAndValidate(rawToken, embeddedPublicKey)
	if err != nil {
		return fmt.Errorf("token inválido: %w", err)
	}

	dir, err := configDir()
	if err != nil {
		return err
	}

	t := Token{Raw: rawToken, Claims: *claims}
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(dir, credentialsFile)
	return os.WriteFile(path, data, 0600)
}

func LoadToken() (*Token, error) {
	dir, err := configDir()
	if err != nil {
		return nil, err
	}

	path := filepath.Join(dir, credentialsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no hay credenciales guardadas — ejecuta 'auditek auth --token <token>'")
	}

	var t Token
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func (t *Token) IsValid() bool {
	return time.Now().Unix() < t.Claims.ExpiresAt
}

func parseAndValidate(rawToken string, publicKey []byte) (*Claims, error) {
	key, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return nil, fmt.Errorf("clave pública inválida: %w", err)
	}

	token, err := jwt.ParseWithClaims(rawToken, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("método de firma inesperado")
		}
		return key, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("claims inválidos")
	}
	return claims, nil
}

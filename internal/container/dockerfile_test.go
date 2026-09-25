package container

import (
	"strings"
	"testing"
)

func ids(fs []Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[f.RuleID]++
	}
	return m
}

func TestScanDockerfileInsecure(t *testing.T) {
	df := `FROM ubuntu:latest
ENV DB_PASSWORD=SuperSecret123
ARG API_KEY=ak_live_1234567890abcdef
RUN curl https://get.example.com/install.sh | bash
RUN chmod 777 /app && sudo useradd app
ADD https://example.com/app.tar.gz /app/
COPY . /app
EXPOSE 22 8080
`
	got := ids(ScanDockerfile(df))

	want := []string{
		"dockerfile-unpinned-base",
		"dockerfile-hardcoded-secret",
		"dockerfile-remote-pipe-shell",
		"dockerfile-chmod-777",
		"dockerfile-sudo",
		"dockerfile-add-remote",
		"dockerfile-copy-context",
		"dockerfile-expose-ssh",
		"dockerfile-runs-as-root",
	}
	for _, id := range want {
		if got[id] == 0 {
			t.Errorf("esperaba hallazgo %q, no apareció (got=%v)", id, got)
		}
	}
	// Debe detectar al menos los dos secretos hardcodeados (ENV y ARG).
	if got["dockerfile-hardcoded-secret"] < 2 {
		t.Errorf("esperaba >=2 secretos hardcodeados, got %d", got["dockerfile-hardcoded-secret"])
	}
}

func TestScanDockerfileClean(t *testing.T) {
	df := `FROM golang:1.22-alpine@sha256:abc123
ENV APP_TOKEN=$BUILD_TOKEN
RUN go build ./...
COPY ./bin/app /usr/local/bin/app
USER app
EXPOSE 8080
`
	got := ids(ScanDockerfile(df))
	if len(got) != 0 {
		t.Errorf("Dockerfile limpio no debería producir hallazgos, got=%v", got)
	}
}

func TestSecretsAreMasked(t *testing.T) {
	fs := ScanDockerfile("FROM alpine:3.19\nUSER app\nENV DB_PASSWORD=SuperSecretValue123\n")
	for _, f := range fs {
		if f.RuleID == "dockerfile-hardcoded-secret" {
			if strings.Contains(f.Evidence, "SuperSecretValue123") {
				t.Errorf("la evidencia no debe contener el secreto completo: %q", f.Evidence)
			}
			return
		}
	}
	t.Fatal("no se detectó el secreto hardcodeado")
}

func TestSecretReportedOncePerLine(t *testing.T) {
	// La AWS key matchea el patrón de nombre (AWS_SECRET_ACCESS_KEY=...) y el
	// de valor (AKIA...) a la vez; debe reportarse una sola vez.
	df := "FROM alpine:3.19\nUSER app\nENV AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if n := ids(ScanDockerfile(df))["dockerfile-hardcoded-secret"]; n != 1 {
		t.Errorf("un secreto en una línea debe reportarse 1 vez, got %d", n)
	}
}

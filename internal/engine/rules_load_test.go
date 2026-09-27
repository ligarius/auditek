package engine

import "testing"

// TestRealRulesLoad valida que TODAS las reglas YAML del repo parsean, y que las
// reglas de archivo crudo tienen el matcher negativo de HTML (anti falso positivo
// por catch-all/SPA). Usa el directorio real ../../rules.
func TestRealRulesLoad(t *testing.T) {
	rules, err := LoadRules("../../rules")
	if err != nil {
		t.Fatalf("LoadRules devolvió error: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("no se cargó ninguna regla")
	}

	byID := map[string]Rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}

	// Reglas que no deben matchear si el cuerpo es HTML.
	for _, id := range []string{"exposed-env-file", "exposed-git-config", "exposed-ssh-key"} {
		r, ok := byID[id]
		if !ok {
			t.Errorf("no se encontró la regla %s", id)
			continue
		}
		if !hasHTMLNegativeMatcher(r) {
			t.Errorf("la regla %s debería tener un matcher negativo de HTML", id)
		}
	}

	// El login ahora exige un campo de contraseña.
	if r, ok := byID["login-no-bruteforce-protection"]; ok {
		if !ruleHasWord(r, `type="password"`) {
			t.Error("login-no-bruteforce-protection debería exigir un campo de contraseña")
		}
	}
}

func hasHTMLNegativeMatcher(r Rule) bool {
	for _, h := range r.HTTP {
		for _, m := range h.Matchers {
			if m.Negative {
				for _, w := range m.Words {
					if w == "<html" || w == "<!DOCTYPE" {
						return true
					}
				}
			}
		}
	}
	return false
}

func ruleHasWord(r Rule, word string) bool {
	for _, h := range r.HTTP {
		for _, m := range h.Matchers {
			for _, w := range m.Words {
				if w == word {
					return true
				}
			}
		}
	}
	return false
}

package engine

import (
	"fmt"
	"os"
	"path/filepath"

	yaml "github.com/goccy/go-yaml"
)

func LoadRules(dir string) ([]Rule, error) {
	var rules []Rule

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return rules, nil
	}

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("error leyendo %s: %w", path, err)
		}

		var r Rule
		if err := yaml.Unmarshal(data, &r); err != nil {
			return fmt.Errorf("regla inválida en %s: %w", path, err)
		}

		if r.ID == "" {
			return fmt.Errorf("regla en %s no tiene 'id'", path)
		}

		rules = append(rules, r)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return rules, nil
}

// FilterRules devuelve las reglas cuyo ID no está en excludeIDs.
func FilterRules(rules []Rule, excludeIDs map[string]bool) []Rule {
	if len(excludeIDs) == 0 {
		return rules
	}
	var out []Rule
	for _, r := range rules {
		if !excludeIDs[r.ID] {
			out = append(out, r)
		}
	}
	return out
}

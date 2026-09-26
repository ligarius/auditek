package engine

import "testing"

func TestParseComposerLock(t *testing.T) {
	body := `{
		"packages": [
			{"name": "monolog/monolog", "version": "1.25.1"},
			{"name": "guzzlehttp/guzzle", "version": "v6.5.8"}
		],
		"packages-dev": [
			{"name": "phpunit/phpunit", "version": "9.5.0+build.1"}
		]
	}`
	got := parseComposerLock(body)
	want := map[string]string{
		"monolog/monolog":   "1.25.1",
		"guzzlehttp/guzzle": "6.5.8", // prefijo v quitado
		"phpunit/phpunit":   "9.5.0", // metadato +build quitado
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("len = %d, want %d (%v)", len(got), len(want), got)
	}
}

func TestParsePackageLockV3(t *testing.T) {
	body := `{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "root", "version": "1.0.0"},
			"node_modules/lodash": {"version": "4.17.19"},
			"node_modules/express": {"version": "4.17.1"},
			"node_modules/express/node_modules/@scope/pkg": {"version": "2.0.0"}
		}
	}`
	got := parsePackageLock(body)
	for k, v := range map[string]string{
		"lodash":     "4.17.19",
		"express":    "4.17.1",
		"@scope/pkg": "2.0.0",
	} {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["root"]; ok {
		t.Error("la raíz (\"\") no debería incluirse como dependencia")
	}
}

func TestParsePackageLockV1(t *testing.T) {
	body := `{
		"lockfileVersion": 1,
		"dependencies": {
			"lodash": {"version": "4.17.11"},
			"express": {
				"version": "4.16.0",
				"dependencies": {
					"qs": {"version": "6.5.1"}
				}
			}
		}
	}`
	got := parsePackageLock(body)
	for k, v := range map[string]string{"lodash": "4.17.11", "express": "4.16.0", "qs": "6.5.1"} {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestNodeModulesName(t *testing.T) {
	cases := map[string]string{
		"node_modules/foo":                     "foo",
		"node_modules/a/node_modules/@scope/b": "@scope/b",
		"":                                     "",
		"other":                                "",
	}
	for in, want := range cases {
		if got := nodeModulesName(in); got != want {
			t.Errorf("nodeModulesName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseLockInvalid(t *testing.T) {
	if got := parseComposerLock("no json"); got != nil {
		t.Errorf("composer inválido debería dar nil, got %v", got)
	}
	if got := parsePackageLock("no json"); got != nil {
		t.Errorf("package-lock inválido debería dar nil, got %v", got)
	}
}

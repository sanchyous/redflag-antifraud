package main

import "testing"

// TestRequireAPIKeyParsing проверяет разбор REQUIRE_API_KEY (та же логика, что FAIL_MODE: strings.EqualFold).
// Сам отказ запуска (os.Exit) не тестируется юнит-тестом намеренно: main() не рефакторится ради этого под
// testability — риск внести регрессию в проверенный порядок старта выше пользы от теста самого os.Exit.
func TestRequireAPIKeyParsing(t *testing.T) {
	cases := map[string]bool{
		"":        false,
		"false":   false,
		"0":       false,
		"true":    true,
		"True":    true,
		"TRUE":    true,
		"garbage": false,
	}
	for v, want := range cases {
		t.Run(v, func(t *testing.T) {
			t.Setenv("REQUIRE_API_KEY", v)
			cfg := loadConfig()
			if cfg.RequireAPIKey != want {
				t.Fatalf("REQUIRE_API_KEY=%q: got %v, want %v", v, cfg.RequireAPIKey, want)
			}
		})
	}
}

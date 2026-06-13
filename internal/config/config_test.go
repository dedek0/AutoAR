package config

import (
	"os"
	"strings"
	"testing"
)

func TestDetectEnvironment(t *testing.T) {
	env := DetectEnvironment()
	if env != "docker" && env != "local" {
		t.Errorf("DetectEnvironment() = %q, want \"docker\" or \"local\"", env)
	}
}

func TestGetConfigValueFromEnv(t *testing.T) {
	const key = "AUTOAR_TEST_CONFIG_KEY_98765"
	os.Setenv(key, "env-value")
	defer os.Unsetenv(key)

	got := GetConfigValue(key, "fallback")
	if got != "env-value" {
		t.Errorf("GetConfigValue() = %q, want %q", got, "env-value")
	}
}

func TestGetConfigValueFallback(t *testing.T) {
	const key = "AUTOAR_NONEXISTENT_KEY_98765"
	os.Unsetenv(key)

	got := GetConfigValue(key, "default-fallback")
	if got != "default-fallback" {
		t.Errorf("GetConfigValue() = %q, want %q", got, "default-fallback")
	}
}

func TestGetConfigValueEmptyEnvFallsBack(t *testing.T) {
	const key = "AUTOAR_EMPTY_KEY_98765"
	os.Setenv(key, "")
	defer os.Unsetenv(key)

	got := GetConfigValue(key, "fallback-val")
	if got != "fallback-val" {
		t.Errorf("GetConfigValue() = %q, want %q", got, "fallback-val")
	}
}

func TestGetRoot(t *testing.T) {
	got := GetRoot()
	if got == "" {
		t.Error("GetRoot() should not return empty string")
	}
}

func TestGetResultsDir(t *testing.T) {
	got := GetResultsDir()
	if got == "" {
		t.Error("GetResultsDir() should not return empty string")
	}
}

func TestGetConfigFile(t *testing.T) {
	got := GetConfigFile()
	if got == "" {
		t.Error("GetConfigFile() should not return empty string")
	}
}

func TestGetEnv(t *testing.T) {
	got := GetEnv()
	if got != "docker" && got != "local" {
		t.Errorf("GetEnv() = %q, want \"docker\" or \"local\"", got)
	}
}

func TestGetBoolConfig(t *testing.T) {
	const key = "AUTOAR_TEST_BOOL_98765"

	// Default when not set
	if got := GetBoolConfig(key, false); got != false {
		t.Errorf("GetBoolConfig(default=false) = %v, want false", got)
	}

	os.Setenv(key, "true")
	defer os.Unsetenv(key)
	if got := GetBoolConfig(key, false); got != true {
		t.Errorf("GetBoolConfig(default=false) with env=true = %v, want true", got)
	}
}

func TestGetIntConfig(t *testing.T) {
	const key = "AUTOAR_TEST_INT_98765"

	// Default when not set
	if got := GetIntConfig(key, 42); got != 42 {
		t.Errorf("GetIntConfig(default=42) = %d, want 42", got)
	}

	os.Setenv(key, "99")
	defer os.Unsetenv(key)
	if got := GetIntConfig(key, 42); got != 99 {
		t.Errorf("GetIntConfig(default=42) with env=99 = %d, want 99", got)
	}
}

func TestGetGlobalThreads(t *testing.T) {
	os.Unsetenv("GLOBAL_THREADS")
	got := GetGlobalThreads()
	if got != DefaultGlobalThreads {
		t.Errorf("GetGlobalThreads() = %d, want %d", got, DefaultGlobalThreads)
	}
}

func TestGetGlobalConcurrency(t *testing.T) {
	os.Unsetenv("GLOBAL_CONCURRENCY")
	got := GetGlobalConcurrency()
	if got != DefaultGlobalConcurrency {
		t.Errorf("GetGlobalConcurrency() = %d, want %d", got, DefaultGlobalConcurrency)
	}
}

func TestGenerateYAMLConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := tmpDir + "/autoar.yaml"

	os.Setenv("DB_TYPE", "postgresql")
	os.Setenv("DB_HOST", "localhost")
	os.Setenv("SHODAN_API_KEY", "super-secret-key")
	defer func() {
		os.Unsetenv("DB_TYPE")
		os.Unsetenv("DB_HOST")
		os.Unsetenv("SHODAN_API_KEY")
	}()

	err := GenerateYAMLConfig(configFile)
	if err != nil {
		t.Fatalf("GenerateYAMLConfig() error = %v", err)
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("failed to read generated config: %v", err)
	}

	content := string(data)

	// Must NOT contain sensitive API key values
	if strings.Contains(content, "super-secret-key") {
		t.Error("Generated config must NOT contain sensitive API key values (SHODAN_API_KEY)")
	}

	// Must contain operational settings
	if !strings.Contains(content, "db_type") {
		t.Error("Generated config should contain db_type setting")
	}

	// Must start with header
	if !strings.HasPrefix(content, "# AutoAR Configuration") {
		t.Error("Generated config should start with comment header")
	}
}

func TestGenerateYAMLConfigNoSecretsInOutput(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := tmpDir + "/autoar.yaml"

	// Set a sensitive key
	os.Setenv("GITHUB_TOKEN", "ghp_secrettoken123")
	os.Setenv("OPENROUTER_API_KEY", "sk-or-secret")
	defer os.Unsetenv("GITHUB_TOKEN")
	defer os.Unsetenv("OPENROUTER_API_KEY")

	err := GenerateYAMLConfig(configFile)
	if err != nil {
		t.Fatalf("GenerateYAMLConfig() error = %v", err)
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("failed to read generated config: %v", err)
	}

	content := string(data)
	if strings.Contains(content, "ghp_secrettoken123") {
		t.Error("Generated config leaks GITHUB_TOKEN value")
	}
	if strings.Contains(content, "sk-or-secret") {
		t.Error("Generated config leaks OPENROUTER_API_KEY value")
	}
}

func TestEnvOverridesYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := tmpDir + "/autoar.yaml"

	// Write a YAML config with a test value
	yamlContent := `test_override_key: "from-yaml"`
	os.WriteFile(configFile, []byte(yamlContent), 0644)

	// Set the same key as env var
	const envKey = "TEST_OVERRIDE_KEY_98765"
	os.Setenv(envKey, "from-env")
	defer os.Unsetenv(envKey)

	// Override AutoARConfigFile to point to our test YAML
	origFile := AutoARConfigFile
	AutoARConfigFile = configFile
	defer func() { AutoARConfigFile = origFile }()

	// Reset viper state
	mu.Lock()
	ini = false
	v = nil
	mu.Unlock()

	got := GetConfigValue(envKey, "default")
	if got != "from-env" {
		t.Errorf("GetConfigValue() = %q, want env value 'from-env' (env should override YAML)", got)
	}
}

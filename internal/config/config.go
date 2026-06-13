package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/spf13/viper"
)

var (
	AutoARRoot       string
	AutoARResultsDir string
	AutoARConfigFile string
	AutoAREnv        string

	// v is the package-level Viper instance for YAML config
	v   *viper.Viper
	mu  sync.RWMutex
	ini bool
)

// sensitiveKeys lists environment variable keys that must NEVER be written to YAML.
var sensitiveKeys = map[string]bool{
	"GITHUB_TOKEN": true, "SHODAN_API_KEY": true, "VIRUSTOTAL_API_KEY": true,
	"SECURITYTRAILS_API_KEY": true, "WORDPRESS_API_KEY": true, "BEVIGIL_API_KEY": true,
	"BINARYEDGE_API_KEY": true, "URLSCAN_API_KEY": true, "CENSYS_API_ID": true,
	"CENSYS_API_SECRET": true, "CERTSPOTTER_API_KEY": true, "CHAOS_API_KEY": true,
	"FOFA_EMAIL": true, "FOFA_KEY": true, "FULLHUNT_API_KEY": true, "INTELX_API_KEY": true,
	"PASSIVETOTAL_USERNAME": true, "PASSIVETOTAL_API_KEY": true, "QUAKE_USERNAME": true,
	"QUAKE_PASSWORD": true, "THREATBOOK_API_KEY": true, "WHOISXMLAPI_API_KEY": true,
	"ZOOMEYE_USERNAME": true, "ZOOMEYE_PASSWORD": true, "ZOOMEYEAPI_API_KEY": true,
	"H1_API_KEY": true, "INTIGRITI_TOKEN": true, "INTIGRITI_API_KEY": true,
	"OPENROUTER_API_KEY": true, "OPENCODE_API_KEY": true, "GEMINI_API_KEY": true,
	"DB_PASSWORD": true, "R2_ACCESS_KEY_ID": true, "R2_SECRET_ACCESS_KEY": true,
	"AWS_ACCESS_KEY_ID": true, "AWS_SECRET_ACCESS_KEY": true,
}

func init() {
	AutoAREnv = DetectEnvironment()

	// Use dynamic env-based fallback instead of hardcoded /app paths
	AutoARRoot = resolveRoot()
	AutoARResultsDir = resolveResultsDir()
	AutoARConfigFile = resolveConfigFile()
}

func resolveRoot() string {
	if v := os.Getenv("AUTOAR_ROOT"); v != "" {
		return v
	}
	if AutoAREnv == "docker" {
		return "/app"
	}
	return GetRootDir()
}

func resolveResultsDir() string {
	if v := os.Getenv("AUTOAR_RESULTS_DIR"); v != "" {
		return v
	}
	if AutoAREnv == "docker" {
		return "/app/new-results"
	}
	return filepath.Join(AutoARRoot, "new-results")
}

func resolveConfigFile() string {
	if v := os.Getenv("AUTOAR_CONFIG_FILE"); v != "" {
		return v
	}
	if AutoAREnv == "docker" {
		return "/app/autoar.yaml"
	}
	return filepath.Join(AutoARRoot, "autoar.yaml")
}

// initViper lazily initializes the Viper instance reading autoar.yaml.
func initViper() {
	mu.Lock()
	defer mu.Unlock()
	if ini {
		return
	}
	ini = true

	v = viper.New()
	v.SetConfigFile(AutoARConfigFile)
	v.SetConfigType("yaml")
	v.AutomaticEnv()
	v.SetEnvPrefix("AUTOAR")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	if err := v.ReadInConfig(); err != nil {
		// Config file is optional; missing file is not an error
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Fprintf(os.Stderr, "[config] warning: cannot read %s: %v\n", AutoARConfigFile, err)
		}
	}
}

// GetConfigValue returns a configuration value with precedence:
//
//	1. Environment variable (highest)
//	2. YAML config value (autoar.yaml)
//	3. Default value (lowest)
func GetConfigValue(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	initViper()
	if v != nil && v.IsSet(key) {
		return v.GetString(key)
	}
	return defaultValue
}

// GetBoolConfig returns a boolean configuration value with the same precedence as GetConfigValue.
func GetBoolConfig(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return strings.ToLower(value) == "true" || value == "1"
	}
	initViper()
	if v != nil && v.IsSet(key) {
		return v.GetBool(key)
	}
	return defaultValue
}

// GetIntConfig returns an integer configuration value with the same precedence.
func GetIntConfig(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var n int
		if _, err := fmt.Sscanf(value, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	initViper()
	if v != nil && v.IsSet(key) {
		return v.GetInt(key)
	}
	return defaultValue
}

// --- Global concurrency settings ---

const (
	DefaultGlobalThreads     = 100
	DefaultGlobalConcurrency = 25
)

// GetGlobalThreads returns the global thread limit for external tools.
func GetGlobalThreads() int {
	return GetIntConfig("GLOBAL_THREADS", DefaultGlobalThreads)
}

// GetGlobalConcurrency returns the global goroutine concurrency limit.
func GetGlobalConcurrency() int {
	return GetIntConfig("GLOBAL_CONCURRENCY", DefaultGlobalConcurrency)
}

// --- Path accessors ---

func GetRoot() string       { return AutoARRoot }
func GetResultsDir() string  { return AutoARResultsDir }
func GetConfigFile() string  { return AutoARConfigFile }
func GetEnv() string         { return AutoAREnv }

// DetectEnvironment detects if running in Docker or local.
func DetectEnvironment() string {
	if _, err := os.Stat("/app/main.sh"); err == nil {
		return "docker"
	}
	return "local"
}

// GetRootDir returns the AutoAR root directory by probing cwd then executable dir.
func GetRootDir() string {
	if cwd, err := os.Getwd(); err == nil {
		if _, err := os.Stat(filepath.Join(cwd, "modules")); err == nil {
			return cwd
		}
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		if _, err := os.Stat(filepath.Join(exeDir, "modules")); err == nil {
			return exeDir
		}
	}
	return "."
}

// GenerateYAMLConfig generates a YAML config from environment variables.
// SECURITY: sensitive API keys and secrets are NEVER written to disk.
func GenerateYAMLConfig(configFile string) error {
	dir := filepath.Dir(configFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	var builder strings.Builder
	builder.WriteString("# AutoAR Configuration\n")
	builder.WriteString("# Generated automatically from environment variables\n")
	builder.WriteString("# NOTE: API keys and secrets are read from environment variables only.\n\n")

	// Non-sensitive operational settings that CAN be exported
	operationalSettings := []struct{ key, yamlKey string }{
		{"DB_TYPE", "db_type"},
		{"DB_HOST", "db_host"},
		{"DB_PORT", "db_port"},
		{"DB_USER", "db_user"},
		{"DB_NAME", "db_name"},
		{"SAVE_TO_DB", "save_to_db"},
		{"VERBOSE", "verbose"},
		{"GLOBAL_THREADS", "global_threads"},
		{"GLOBAL_CONCURRENCY", "global_concurrency"},
	}

	builder.WriteString("# Database Configuration\n")
	for _, s := range operationalSettings {
		if value := os.Getenv(s.key); value != "" {
			builder.WriteString(fmt.Sprintf("%s: \"%s\"\n", s.yamlKey, value))
		}
	}

	// Tool-specific non-sensitive configuration
	toolSettings := []struct{ key, yamlKey string }{
		{"NUCLEI_TEMPLATES_PATH", "nuclei.templates_path"},
		{"NUCLEI_RATE_LIMIT", "nuclei.rate_limit"},
		{"NUCLEI_CONCURRENCY", "nuclei.concurrency"},
		{"FFUF_WORDLIST_PATH", "ffuf.wordlist_path"},
		{"FFUF_THREADS", "ffuf.threads"},
		{"SUBFINDER_THREADS", "subfinder.threads"},
		{"GITHUB_MAX_REPOS", "github_scan.max_repos"},
		{"GITHUB_PARALLEL_JOBS", "github_scan.parallel_jobs"},
	}

	hasToolSettings := false
	for _, s := range toolSettings {
		if os.Getenv(s.key) != "" {
			if !hasToolSettings {
				builder.WriteString("\n# Tool Configuration\n")
				hasToolSettings = true
			}
			builder.WriteString(fmt.Sprintf("%s: \"%s\"\n", s.yamlKey, os.Getenv(s.key)))
		}
	}

	// Document which keys are env-only (never exported)
	builder.WriteString("\n# API keys and secrets must be set via environment variables.\n")
	builder.WriteString("# They are NOT written to this file for security reasons.\n")
	builder.WriteString("# Required env vars: GITHUB_TOKEN, SHODAN_API_KEY, VIRUSTOTAL_API_KEY, etc.\n")

	return os.WriteFile(configFile, []byte(builder.String()), 0644)
}

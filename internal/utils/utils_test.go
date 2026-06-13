package utils

import (
	"regexp"
	"testing"
)

func TestSanitizeTargetSegmentExtended(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   string
	}{
		{"clean domain", "example.com", "example.com"},
		{"with https", "https://example.com", "example.com"},
		{"with http", "http://example.com", "example.com"},
		{"with trailing slash", "example.com/", "example.com"},
		{"special chars replaced", "example.com@#$%", "example.com"},
		{"dots collapsed", "example..com", "example-com"},
		{"leading/trailing dots stripped", ".example.com.", "example.com"},
		{"empty becomes unknown", "", "unknown"},
		{"only special chars", "@#$%", "unknown"},
		{"with port", "example.com:8080", "example.com-8080"},
		{"path component", "example.com/path/to/page", "example.com-path-to-page"},
		{"query string", "example.com?q=1&r=2", "example.com-q-1-r-2"},
		{"hash", "example.com#section", "example.com-section"},
		{"mixed case preserved", "Example.COM", "Example.COM"},
		{"underscores preserved", "my_example.com", "my_example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeTargetSegment(tt.target)
			if got != tt.want {
				t.Errorf("SanitizeTargetSegment(%q) = %q, want %q", tt.target, got, tt.want)
			}
		})
	}
}

func TestURLSlugExtended(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"simple URL", "https://example.com/page", "https:__example.com_page"},
		{"no slashes", "example.com", "example.com"},
		{"empty", "", ""},
		{"multiple slashes", "a/b/c/d", "a_b_c_d"},
		{"trailing slash", "example.com/", "example.com_"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := URLSlug(tt.url)
			if got != tt.want {
				t.Errorf("URLSlug(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestUniqueStringsExtended(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"no duplicates", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"with duplicates", []string{"a", "b", "a", "c", "b"}, []string{"a", "b", "c"}},
		{"empty strings filtered", []string{"a", "", "b", "  ", "c"}, []string{"a", "b", "c"}},
		{"whitespace trimmed", []string{" a ", "a", "b"}, []string{"a", "b"}},
		{"nil input", nil, []string{}},
		{"all empty", []string{"", "", ""}, []string{}},
		{"single element", []string{"only"}, []string{"only"}},
		{"large list", []string{"a", "b", "c", "d", "e", "a", "c"}, []string{"a", "b", "c", "d", "e"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := UniqueStrings(tt.in)
			if len(got) != len(tt.want) {
				t.Errorf("UniqueStrings() returned %d items, want %d: %v", len(got), len(tt.want), got)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("UniqueStrings()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestScanContentForSecretsExtended(t *testing.T) {
	patterns := map[string][]*regexp.Regexp{
		"aws_key": {regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		"github":  {regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`)},
	}

	tests := []struct {
		name    string
		content string
		source  string
		want    int
	}{
		{"AWS key found", "AKIAIOSFODNN7EXAMPLE", "config.js", 1},
		{"GitHub token found", "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "env", 1},
		{"no secrets", "no sensitive data here", "readme.md", 0},
		{"duplicate matches deduped", "key1: AKIAIOSFODNN7EXAMPLE key2: AKIAIOSFODNN7EXAMPLE", "config.js", 1},
		{"empty source", "AKIAIOSFODNN7EXAMPLE", "", 1},
		{"multiple different secrets", "AKIAIOSFODNN7EXAMPLE and ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "", 2},
		{"empty content", "", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScanContentForSecrets(tt.content, tt.source, patterns)
			if len(got) != tt.want {
				t.Errorf("ScanContentForSecrets() returned %d findings, want %d: %v", len(got), tt.want, got)
			}
		})
	}
}

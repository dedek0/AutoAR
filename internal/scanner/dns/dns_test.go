package dns

import (
	"testing"
)

func TestIsSummaryLine(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		// Should return true (summary lines)
		{"", true},
		{"   ", true},
		{"\t", true},
		{"=== DNS Takeover Summary ===", true},
		{"Scan Date: 2024-01-15", true},
		{"Total Subdomains: 150", true},
		{"Azure Vulnerabilities Found: 3", true},
		{"AWS Vulnerabilities Found: 1", true},
		{"Total Vulnerabilities: 5", true},
		{"Tools Used: nuclei, dnsreaper", true},
		{"Target Domain: example.com", true},
		{"FINDINGS SUMMARY", true},
		{"NOTES", true},
		{"Review individual findings for accuracy", true},
		{"Always manually validate takeover findings", true},
		{"Dangling IP detection results", true},

		// Should return false (actual data lines)
		{"sub.example.com CNAME target.example.com", false},
		{"vulnerable.example.com CNAME azurefd.net", false},
		{"192.168.1.1", false},
		{"https://example.com/login", false},
		{"admin.example.com", false},
		{"some random text without prefix", false},
		{"note: something important", false},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			got := isSummaryLine(tt.line)
			if got != tt.want {
				t.Errorf("isSummaryLine(%q) = %v, want %v", tt.line, got, tt.want)
			}
		})
	}
}

func TestCountStatus(t *testing.T) {
	tests := []struct {
		name     string
		statusMap map[string]string
		status   string
		want     int
	}{
		{
			name:      "empty map",
			statusMap: map[string]string{},
			status:    "vulnerable",
			want:      0,
		},
		{
			name: "no matches",
			statusMap: map[string]string{
				"a": "safe",
				"b": "unknown",
			},
			status: "vulnerable",
			want:   0,
		},
		{
			name: "some matches",
			statusMap: map[string]string{
				"a": "vulnerable",
				"b": "safe",
				"c": "vulnerable",
				"d": "safe",
			},
			status: "vulnerable",
			want:   2,
		},
		{
			name: "all match",
			statusMap: map[string]string{
				"a": "vulnerable",
				"b": "vulnerable",
			},
			status: "vulnerable",
			want:   2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countStatus(tt.statusMap, tt.status)
			if got != tt.want {
				t.Errorf("countStatus() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestHasSuffix(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		suffixes []string
		want     bool
	}{
		{
			name:     "exact match lowercase",
			s:        "example.com",
			suffixes: []string{".com"},
			want:     true,
		},
		{
			name:     "case insensitive match",
			s:        "EXAMPLE.COM",
			suffixes: []string{".com"},
			want:     true,
		},
		{
			name:     "no match",
			s:        "example.org",
			suffixes: []string{".com", ".net"},
			want:     false,
		},
		{
			name:     "multiple suffixes second matches",
			s:        "test.net",
			suffixes: []string{".com", ".net"},
			want:     true,
		},
		{
			name:     "empty string",
			s:        "",
			suffixes: []string{".com"},
			want:     false,
		},
		{
			name:     "empty suffixes",
			s:        "example.com",
			suffixes: []string{},
			want:     false,
		},
		{
			name:     "complex suffix",
			s:        "app.azurefd.net",
			suffixes: []string{".azurefd.net", ".cloudfront.net"},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasSuffix(tt.s, tt.suffixes)
			if got != tt.want {
				t.Errorf("hasSuffix(%q, %v) = %v, want %v", tt.s, tt.suffixes, got, tt.want)
			}
		})
	}
}

func TestMin(t *testing.T) {
	tests := []struct{ a, b, want int }{
		{1, 2, 1},
		{2, 1, 1},
		{5, 5, 5},
		{0, 0, 0},
		{-1, 1, -1},
		{-5, -3, -5},
	}
	for _, tt := range tests {
		got := min(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("min(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestMax(t *testing.T) {
	tests := []struct{ a, b, want int }{
		{1, 2, 2},
		{2, 1, 2},
		{5, 5, 5},
		{0, 0, 0},
		{-1, 1, 1},
		{-5, -3, -3},
	}
	for _, tt := range tests {
		got := max(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("max(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

package nuclei

import (
	"testing"
)

func TestExtractDomainFromURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "https with path",
			url:  "https://example.com/login",
			want: "example.com",
		},
		{
			name: "http with path",
			url:  "http://sub.example.com/api/v1",
			want: "sub.example.com",
		},
		{
			name: "https no path",
			url:  "https://example.com",
			want: "example.com",
		},
		{
			name: "http no path",
			url:  "http://example.com",
			want: "example.com",
		},
		{
			name: "no scheme with path",
			url:  "example.com/page",
			want: "example.com",
		},
		{
			name: "no scheme no path",
			url:  "example.com",
			want: "example.com",
		},
		{
			name: "with port",
			url:  "https://example.com:8080/api",
			want: "example.com:8080",
		},
		{
			name: "complex subdomain",
			url:  "https://app.staging.example.com/dashboard",
			want: "app.staging.example.com",
		},
		{
			name: "empty string",
			url:  "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDomainFromURL(tt.url)
			if got != tt.want {
				t.Errorf("extractDomainFromURL(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestSanitizeNucleiTarget(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantOk  bool
	}{
		// Valid targets
		{
			name:   "valid https url",
			raw:    "https://example.com",
			want:   "https://example.com",
			wantOk: true,
		},
		{
			name:   "valid http url",
			raw:    "http://example.com/login",
			want:   "http://example.com/login",
			wantOk: true,
		},
		{
			name:   "valid hostname",
			raw:    "example.com",
			want:   "example.com",
			wantOk: true,
		},
		{
			name:   "hostname with port",
			raw:    "example.com:8080",
			want:   "example.com:8080",
			wantOk: true,
		},
		{
			name:   "ip address",
			raw:    "192.168.1.1",
			want:   "192.168.1.1",
			wantOk: true,
		},
		{
			name:   "ip with port",
			raw:    "10.0.0.1:443",
			want:   "10.0.0.1:443",
			wantOk: true,
		},
		{
			name:   "with leading whitespace",
			raw:    "  https://example.com",
			want:   "https://example.com",
			wantOk: true,
		},
		{
			name:   "html entity decoded",
			raw:    "https://example.com&amp;param=1",
			want:   "https://example.com&param=1",
			wantOk: true,
		},

		// Invalid targets
		{
			name:   "empty string",
			raw:    "",
			want:   "",
			wantOk: false,
		},
		{
			name:   "only whitespace",
			raw:    "   ",
			want:   "",
			wantOk: false,
		},
		{
			name:   "contains angle brackets",
			raw:    "https://example.com<script>",
			want:   "",
			wantOk: false,
		},
		{
			name:   "contains quotes",
			raw:    `https://example.com"test"`,
			want:   "",
			wantOk: false,
		},
		{
			name:   "contains space",
			raw:    "https://example .com",
			want:   "",
			wantOk: false,
		},
		{
			name:   "template placeholder %s",
			raw:    "https://%s.example.com",
			want:   "",
			wantOk: false,
		},
		{
			name:   "ends with %",
			raw:    "https://example.com%",
			want:   "",
			wantOk: false,
		},
		{
			name:   "ftp scheme",
			raw:    "ftp://example.com",
			want:   "",
			wantOk: false,
		},
		{
			name:   "invalid url parse",
			raw:    "://example.com",
			want:   "",
			wantOk: false,
		},
		{
			name:   "backtick",
			raw:    "https://example.com`test`",
			want:   "",
			wantOk: false,
		},
		{
			name:   "hostname with 5-digit port (regex allows it)",
			raw:    "example.com:99999",
			want:   "example.com:99999",
			wantOk: true,
		},
		{
			name:   "hostname with 6-digit port (rejected)",
			raw:    "example.com:999999",
			want:   "",
			wantOk: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := sanitizeNucleiTarget(tt.raw)
			if ok != tt.wantOk {
				t.Errorf("sanitizeNucleiTarget(%q) ok = %v, want %v", tt.raw, ok, tt.wantOk)
			}
			if got != tt.want {
				t.Errorf("sanitizeNucleiTarget(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestMaxNuclei(t *testing.T) {
	tests := []struct{ a, b, want int }{
		{1, 2, 2},
		{2, 1, 2},
		{5, 5, 5},
		{0, 0, 0},
		{-1, 1, 1},
	}
	for _, tt := range tests {
		got := max(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("max(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

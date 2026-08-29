package nuclei

import (
	"testing"

"os"
"path/filepath"
"strings"
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

// ── tests merged from upstream master ──

func TestReadTargetLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	content := strings.Join([]string{
		"example.com",
		"example.com",     // duplicate -> deduped
		"https://foo.com", // valid URL
		"bad target",      // contains a space -> skipped
		"<script>",        // angle brackets -> skipped
		"example.com:443", // host:port -> valid
		"",                // blank line -> skipped
		"sub.example.com",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := readTargetLines(path)
	if err != nil {
		t.Fatalf("readTargetLines error: %v", err)
	}
	want := []string{"example.com", "https://foo.com", "example.com:443", "sub.example.com"}
	if len(got) != len(want) {
		t.Fatalf("readTargetLines returned %d targets %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("target[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

func TestReadTargetLinesMissingFile(t *testing.T) {
	if _, err := readTargetLines(filepath.Join(t.TempDir(), "does-not-exist.txt")); err == nil {
		t.Fatal("expected an error reading a missing target file, got nil")
	}
}

func TestCountLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "count.txt")
	// Two blank lines (one interior, one trailing) must not be counted.
	if err := os.WriteFile(path, []byte("a\nb\n\nc\n"), 0644); err != nil {
		t.Fatal(err)
	}
	n, err := countLines(path)
	if err != nil {
		t.Fatalf("countLines error: %v", err)
	}
	if n != 3 {
		t.Errorf("countLines = %d, want 3", n)
	}
}

func TestCountLinesEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	n, err := countLines(path)
	if err != nil {
		t.Fatalf("countLines error: %v", err)
	}
	if n != 0 {
		t.Errorf("countLines(empty) = %d, want 0", n)
	}
}

func TestCountLinesMissingFile(t *testing.T) {
	if _, err := countLines(filepath.Join(t.TempDir(), "does-not-exist.txt")); err == nil {
		t.Fatal("expected an error counting lines in a missing file, got nil")
	}
}

func TestScanRequestHeadersDefault(t *testing.T) {
	t.Setenv("AUTOAR_SCAN_USER_AGENT", "") // force the default branch

	got := scanRequestHeaders()
	if len(got) != 1 {
		t.Fatalf("scanRequestHeaders() = %#v, want exactly one header", got)
	}
	if !strings.HasPrefix(got[0], "User-Agent: ") {
		t.Errorf("header %q is missing the 'User-Agent: ' prefix", got[0])
	}
	// The default must look like a real browser, not nuclei's self-identifying UA
	// (commodity WAFs reject the latter, producing silent false negatives).
	if !strings.Contains(got[0], "Mozilla/5.0") || !strings.Contains(got[0], "Chrome/") {
		t.Errorf("default User-Agent %q does not look like a browser", got[0])
	}
	if strings.Contains(strings.ToLower(got[0]), "nuclei") {
		t.Errorf("default User-Agent %q must not identify as nuclei", got[0])
	}
}

func TestScanRequestHeadersOverride(t *testing.T) {
	const custom = "MyScanner/1.2 (contact@example.com)"
	t.Setenv("AUTOAR_SCAN_USER_AGENT", custom)

	got := scanRequestHeaders()
	want := "User-Agent: " + custom
	if len(got) != 1 || got[0] != want {
		t.Fatalf("scanRequestHeaders() = %#v, want [%q]", got, want)
	}
}

func TestDirExists(t *testing.T) {
	dir := t.TempDir()
	if !dirExists(dir) {
		t.Errorf("dirExists(%q) = false, want true", dir)
	}

	file := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if dirExists(file) {
		t.Errorf("dirExists(%q) = true, want false (it is a regular file)", file)
	}
	if dirExists(filepath.Join(dir, "missing")) {
		t.Errorf("dirExists(missing path) = true, want false")
	}
}

func TestMaxHelper(t *testing.T) {
	cases := []struct{ a, b, want int }{
		{3, 7, 7},
		{7, 3, 7},
		{4, 4, 4},
		{-1, -5, -1},
	}
	for _, tc := range cases {
		if got := max(tc.a, tc.b); got != tc.want {
			t.Errorf("max(%d, %d) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

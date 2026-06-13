package monitor

import (
	"regexp"
	"testing"
)

func TestLooksLikeSHA256Hex(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{
			name: "valid lowercase hex",
			s:    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			want: true,
		},
		{
			name: "valid uppercase hex",
			s:    "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
			want: true,
		},
		{
			name: "valid mixed case hex",
			s:    "a1B2c3D4e5F6a1B2c3D4e5F6a1B2c3D4e5F6a1B2c3D4e5F6a1B2c3D4e5F6a1B2",
			want: true,
		},
		{
			name: "all zeros",
			s:    "0000000000000000000000000000000000000000000000000000000000000000",
			want: true,
		},
		{
			name: "all fs",
			s:    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			want: true,
		},
		{
			name: "too short",
			s:    "a1b2c3d4",
			want: false,
		},
		{
			name: "too long",
			s:    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2extra",
			want: false,
		},
		{
			name: "contains non-hex chars",
			s:    "g1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			want: false,
		},
		{
			name: "contains spaces",
			s:    "a1b2c3d4 e5f6a1b2 c3d4e5f6 a1b2c3d4 e5f6a1b2 c3d4e5f6 a1b2c3d4 e5f6",
			want: false,
		},
		{
			name: "empty string",
			s:    "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := looksLikeSHA256Hex(tt.s)
			if got != tt.want {
				t.Errorf("looksLikeSHA256Hex(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestDefaultRegexPattern(t *testing.T) {
	pattern := defaultRegexPattern()
	if pattern == "" {
		t.Error("defaultRegexPattern() returned empty string")
	}

	// Verify it's a valid regex
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Errorf("defaultRegexPattern() returned invalid regex: %v", err)
	}

	// Test that it matches expected date formats
	validDates := []string{
		"January 15, 2024",
		"Jun 3, 2024",
		"2024-01-15",
		"2024-12-31",
	}
	for _, d := range validDates {
		if !re.MatchString(d) {
			t.Errorf("pattern should match date %q", d)
		}
	}

	// Test that it doesn't match non-dates
	invalidDates := []string{
		"not a date",
		"12345",
		"example.com",
	}
	for _, d := range invalidDates {
		if re.MatchString(d) {
			t.Errorf("pattern should not match %q", d)
		}
	}
}

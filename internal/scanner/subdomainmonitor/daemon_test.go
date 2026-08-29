package subdomainmonitor

import (
	"strings"
	"testing"
)

func TestFormatChangeAlert(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		result *MonitorResult
		want   []string // substrings that must appear in output
	}{
		{
			name:   "new subdomains only",
			domain: "example.com",
			result: &MonitorResult{
				NewSubdomains: []SubdomainChange{
					{Subdomain: "api.example.com", Message: "new subdomain found"},
					{Subdomain: "staging.example.com", Message: "new subdomain found"},
				},
			},
			want: []string{
				"Subdomain Monitor Alert",
				"example.com",
				"2 new",
				"api.example.com",
				"staging.example.com",
			},
		},
		{
			name:   "became live only",
			domain: "test.com",
			result: &MonitorResult{
				BecameLive: []SubdomainChange{
					{Subdomain: "app.test.com", Message: "HTTP 200"},
				},
			},
			want: []string{
				"test.com",
				"1",
				"became **live**",
				"app.test.com",
			},
		},
		{
			name:   "became dead only",
			domain: "down.com",
			result: &MonitorResult{
				BecameDead: []SubdomainChange{
					{Subdomain: "old.down.com", Message: "connection refused"},
					{Subdomain: "legacy.down.com", Message: "timeout"},
				},
			},
			want: []string{
				"down.com",
				"2",
				"became **dead**",
				"old.down.com",
				"legacy.down.com",
			},
		},
		{
			name:   "status changes only",
			domain: "changed.com",
			result: &MonitorResult{
				StatusChanges: []SubdomainChange{
					{Subdomain: "www.changed.com", Message: "200 -> 404"},
				},
			},
			want: []string{
				"changed.com",
				"1",
				"status change",
				"www.changed.com",
			},
		},
		{
			name:   "mixed changes",
			domain: "multi.com",
			result: &MonitorResult{
				NewSubdomains: []SubdomainChange{
					{Subdomain: "new.multi.com", Message: "discovered"},
				},
				BecameLive: []SubdomainChange{
					{Subdomain: "live.multi.com", Message: "now responding"},
				},
				BecameDead: []SubdomainChange{
					{Subdomain: "dead.multi.com", Message: "no response"},
				},
				StatusChanges: []SubdomainChange{
					{Subdomain: "status.multi.com", Message: "301 -> 200"},
				},
			},
			want: []string{
				"multi.com",
				"1 new",
				"1",
				"became **live**",
				"became **dead**",
				"status change",
				"new.multi.com",
				"live.multi.com",
				"dead.multi.com",
				"status.multi.com",
			},
		},
		{
			name:   "no changes",
			domain: "stable.com",
			result: &MonitorResult{
				TotalChecked: 50,
			},
			want: []string{
				"stable.com",
				"Subdomain Monitor Alert",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatChangeAlert(tt.domain, tt.result)
			for _, substr := range tt.want {
				if !strings.Contains(got, substr) {
					t.Errorf("formatChangeAlert() output missing %q\nGot:\n%s", substr, got)
				}
			}
		})
	}
}

// ── tests merged from upstream master ──

func TestChangeSection(t *testing.T) {
	if got := changeSection("**%d** changed", nil); got != "" {
		t.Errorf("empty changes should render nothing, got %q", got)
	}

	one := []SubdomainChange{{Subdomain: "a.example.com", Message: "became live"}}
	got := changeSection("**%d** became **live**", one)
	if !strings.Contains(got, "a.example.com") || !strings.Contains(got, "became live") {
		t.Errorf("section missing subdomain/message: %q", got)
	}
	if !strings.Contains(got, "1") {
		t.Errorf("section header should include the count: %q", got)
	}

	// One over the cap: exactly maxAlertItemsPerCategory bullets, then a summary.
	n := maxAlertItemsPerCategory + 5
	many := make([]SubdomainChange, n)
	for i := range many {
		many[i] = SubdomainChange{Subdomain: "h", Message: "m"}
	}
	got = changeSection("**%d** status change(s)", many)
	if bullets := strings.Count(got, "•"); bullets != maxAlertItemsPerCategory {
		t.Errorf("expected %d bullets at cap, got %d", maxAlertItemsPerCategory, bullets)
	}
	if !strings.Contains(got, "…and 5 more") {
		t.Errorf("expected overflow summary '…and 5 more', got %q", got)
	}
}

// TestFormatChangeAlert covers the top-level alert assembler: it names the domain,
// includes only the non-empty categories, and renders new JS endpoints.

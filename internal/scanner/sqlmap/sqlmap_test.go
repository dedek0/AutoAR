package sqlmap

import (
	"testing"
)

func TestDedupeSQLMapFindings(t *testing.T) {
	tests := []struct {
		name string
		in   []sqlmapFinding
		want []sqlmapFinding
	}{
		{
			name: "empty input",
			in:   []sqlmapFinding{},
			want: []sqlmapFinding{},
		},
		{
			name: "no duplicates",
			in: []sqlmapFinding{
				{TemplateID: "t1", MatchedAt: "http://a.com", Severity: "high"},
				{TemplateID: "t2", MatchedAt: "http://b.com", Severity: "low"},
			},
			want: []sqlmapFinding{
				{TemplateID: "t1", MatchedAt: "http://a.com", Severity: "high"},
				{TemplateID: "t2", MatchedAt: "http://b.com", Severity: "low"},
			},
		},
		{
			name: "exact duplicates removed",
			in: []sqlmapFinding{
				{TemplateID: "t1", MatchedAt: "http://a.com", Severity: "high"},
				{TemplateID: "t1", MatchedAt: "http://a.com", Severity: "high"},
				{TemplateID: "t1", MatchedAt: "http://a.com", Severity: "high"},
			},
			want: []sqlmapFinding{
				{TemplateID: "t1", MatchedAt: "http://a.com", Severity: "high"},
			},
		},
		{
			name: "different template IDs are unique",
			in: []sqlmapFinding{
				{TemplateID: "t1", MatchedAt: "http://a.com", Severity: "high"},
				{TemplateID: "t2", MatchedAt: "http://a.com", Severity: "high"},
			},
			want: []sqlmapFinding{
				{TemplateID: "t1", MatchedAt: "http://a.com", Severity: "high"},
				{TemplateID: "t2", MatchedAt: "http://a.com", Severity: "high"},
			},
		},
		{
			name: "different matched-at are unique",
			in: []sqlmapFinding{
				{TemplateID: "t1", MatchedAt: "http://a.com", Severity: "high"},
				{TemplateID: "t1", MatchedAt: "http://b.com", Severity: "high"},
			},
			want: []sqlmapFinding{
				{TemplateID: "t1", MatchedAt: "http://a.com", Severity: "high"},
				{TemplateID: "t1", MatchedAt: "http://b.com", Severity: "high"},
			},
		},
		{
			name: "different severity are unique",
			in: []sqlmapFinding{
				{TemplateID: "t1", MatchedAt: "http://a.com", Severity: "high"},
				{TemplateID: "t1", MatchedAt: "http://a.com", Severity: "critical"},
			},
			want: []sqlmapFinding{
				{TemplateID: "t1", MatchedAt: "http://a.com", Severity: "high"},
				{TemplateID: "t1", MatchedAt: "http://a.com", Severity: "critical"},
			},
		},
		{
			name: "preserves first occurrence order",
			in: []sqlmapFinding{
				{TemplateID: "t3", MatchedAt: "http://c.com", Severity: "medium"},
				{TemplateID: "t1", MatchedAt: "http://a.com", Severity: "high"},
				{TemplateID: "t3", MatchedAt: "http://c.com", Severity: "medium"},
				{TemplateID: "t2", MatchedAt: "http://b.com", Severity: "low"},
				{TemplateID: "t1", MatchedAt: "http://a.com", Severity: "high"},
			},
			want: []sqlmapFinding{
				{TemplateID: "t3", MatchedAt: "http://c.com", Severity: "medium"},
				{TemplateID: "t1", MatchedAt: "http://a.com", Severity: "high"},
				{TemplateID: "t2", MatchedAt: "http://b.com", Severity: "low"},
			},
		},
		{
			name: "nil input",
			in:   nil,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dedupeSQLMapFindings(tt.in)
			if len(got) != len(tt.want) {
				t.Errorf("dedupeSQLMapFindings() returned %d items, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i].TemplateID != tt.want[i].TemplateID ||
					got[i].MatchedAt != tt.want[i].MatchedAt ||
					got[i].Severity != tt.want[i].Severity {
					t.Errorf("item[%d] = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

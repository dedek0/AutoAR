package exposure

import (
	"testing"
)

func TestFindingString(t *testing.T) {
	tests := []struct {
		name    string
		finding Finding
		want    string
	}{
		{
			name: "api-docs finding",
			finding: Finding{
				Host:       "api.example.com",
				Path:       "/swagger.json",
				Category:   "api-docs",
				StatusCode: 200,
				Evidence:   "swagger",
			},
			want: "[api-docs] api.example.com/swagger.json [HTTP 200] (matched: swagger)",
		},
		{
			name: "docker finding",
			finding: Finding{
				Host:       "registry.example.com",
				Path:       "/v2/",
				Category:   "docker",
				StatusCode: 401,
				Evidence:   "docker-distribution-api-version",
			},
			want: "[docker] registry.example.com/v2/ [HTTP 401] (matched: docker-distribution-api-version)",
		},
		{
			name: "no path",
			finding: Finding{
				Host:       "example.com",
				Path:       "",
				Category:   "api-docs",
				StatusCode: 200,
				Evidence:   "graphql",
			},
			want: "[api-docs] example.com [HTTP 200] (matched: graphql)",
		},
		{
			name: "empty evidence",
			finding: Finding{
				Host:       "test.com",
				Path:       "/admin",
				Category:   "sensitive",
				StatusCode: 403,
				Evidence:   "",
			},
			want: "[sensitive] test.com/admin [HTTP 403] (matched: )",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.finding.String()
			if got != tt.want {
				t.Errorf("Finding.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

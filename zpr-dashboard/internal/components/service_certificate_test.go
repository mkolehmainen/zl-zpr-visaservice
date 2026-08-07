package components

import (
	"testing"
	"time"
)

// TestFormatCertRemaining checks the bar label keeps padded days near term and
// rounds to the nearest year once the certificate is far out.
func TestFormatCertRemaining(t *testing.T) {
	const year = 365 * 24 * time.Hour

	now := time.Unix(1785604630, 0)

	cases := []struct {
		name   string
		offset time.Duration
		want   string
	}{
		{"days", 300 * 24 * time.Hour, " 300 days"},
		{"just under a year", year - time.Hour, " 364 days"},
		{"rounds up", year + year/2 + time.Hour, "2y"},
		{"rounds down", year + year/2 - time.Hour, "1y"},
		{"century sentinel", 100 * year, "100y"},
	}

	for _, c := range cases {
		expires := now.Add(c.offset).Unix()
		days := int(c.offset.Hours() / 24)
		if got := formatCertRemaining(expires, now, days); got != c.want {
			t.Errorf("formatCertRemaining(%s) = %q, want %q", c.name, got, c.want)
		}
	}
}

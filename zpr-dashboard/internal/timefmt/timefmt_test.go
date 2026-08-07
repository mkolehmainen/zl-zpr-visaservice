package timefmt

import (
	"math"
	"testing"
	"time"
)

// TestHelpers checks both helpers render a known epoch in the local zone (not
// UTC) and that each output matches the column width its layout is chosen for.
// Not parallel: time.Local is a process global.
func TestHelpers(t *testing.T) {
	saved := time.Local
	time.Local = time.FixedZone("TEST", 5*60*60+30*60)
	t.Cleanup(func() { time.Local = saved })

	const epoch = 1785604630 // 2026-08-01 17:17:10 UTC

	cases := []struct {
		name  string
		got   string
		want  string
		width int
	}{
		{"TimeOfDay", TimeOfDay(epoch), "22:47:10", 8},
		{"DateTime", DateTime(epoch), "08-01 22:47", 11},
	}

	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
		if len(c.got) != c.width {
			t.Errorf("%s width = %d, want %d", c.name, len(c.got), c.width)
		}
	}
}

// TestFarFuture pins the one-year threshold, the round-to-nearest boundary, and
// that a sentinel-sized timestamp is still reported (not saturated).
func TestFarFuture(t *testing.T) {
	const year = int64(yearSeconds)

	now := time.Unix(1785604630, 0)

	cases := []struct {
		name    string
		seconds int64
		want    string
	}{
		{"expired", now.Unix() - 1, ""},
		{"just under a year", now.Unix() + year - 1, ""},
		{"just over a year", now.Unix() + year + 1, "1y"},
		{"rounds up past half a year", now.Unix() + year + year/2 + 1, "2y"},
		{"rounds down under half a year", now.Unix() + year + year/2 - 1, "1y"},
		{"century sentinel", now.Unix() + 100*year, "100y"},
		{"max timestamp", math.MaxInt64, "292471208621y"},
	}

	for _, c := range cases {
		got, ok := FarFuture(c.seconds, now)
		if ok != (c.want != "") {
			t.Errorf("FarFuture(%s) ok = %v, want %v", c.name, ok, c.want != "")
		}
		if got != c.want {
			t.Errorf("FarFuture(%s) = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestExpiry checks the wrapper falls back to the date layout near term and
// switches to years past the threshold.
func TestExpiry(t *testing.T) {
	saved := time.Local
	time.Local = time.FixedZone("TEST", 5*60*60+30*60)
	t.Cleanup(func() { time.Local = saved })

	now := time.Unix(1785604630, 0) // 2026-08-01 22:47 in TEST

	if got, want := expiry(now.Unix()+3600, now), "08-01 23:47"; got != want {
		t.Errorf("expiry(near) = %q, want %q", got, want)
	}
	if got, want := expiry(now.Unix()+100*int64(yearSeconds), now), "100y"; got != want {
		t.Errorf("expiry(far) = %q, want %q", got, want)
	}
}

// Package timefmt holds the display layouts for timestamps shown in the TUI so
// the panes and the header cannot drift to per-pane formats.
package timefmt

import (
	"strconv"
	"time"
)

// Layouts for displayed timestamps, chosen by role.
const (
	LayoutTimeOfDay = "15:04:05"    // 8 cols: narrow table columns, header clock
	LayoutDateTime  = "01-02 15:04" // 11 cols: every display that needs a date
)

// TimeOfDay renders epoch seconds as local wall-clock time, no date.
func TimeOfDay(seconds int64) string {
	return time.Unix(seconds, 0).Format(LayoutTimeOfDay)
}

// DateTime renders epoch seconds as local month-day and time, no seconds.
func DateTime(seconds int64) string {
	return time.Unix(seconds, 0).Format(LayoutDateTime)
}

const yearSeconds uint64 = 365 * 24 * 60 * 60

// FarFuture renders epoch seconds as a rounded year count ("100y") when it is
// more than a year after now, so the service's "never expires" sentinel does not
// read as a real timestamp. Reports false otherwise, leaving callers their own
// near-term format.
//
// The interval is computed unsigned rather than with Time.Sub, which saturates
// at ~292 years and would misreport a larger sentinel.
func FarFuture(seconds int64, now time.Time) (string, bool) {
	if seconds <= now.Unix() {
		return "", false
	}

	remaining := uint64(seconds) - uint64(now.Unix())
	years, rem := remaining/yearSeconds, remaining%yearSeconds
	if years == 0 {
		return "", false
	}

	// Round to nearest. remaining overstates the true interval by the current
	// fractional second, so an exact half-year only rounds up on a whole second.
	if half := yearSeconds / 2; rem > half || (rem == half && now.Nanosecond() == 0) {
		years++
	}

	return strconv.FormatUint(years, 10) + "y", true
}

// Expiry renders an expiry timestamp as a date, or a rounded year count when it
// is more than a year out.
func Expiry(seconds int64) string {
	return expiry(seconds, time.Now())
}

// expiry is Expiry with an injectable clock so tests do not depend on time.Now.
func expiry(seconds int64, now time.Time) string {
	if years, ok := FarFuture(seconds, now); ok {
		return years
	}

	return DateTime(seconds)
}

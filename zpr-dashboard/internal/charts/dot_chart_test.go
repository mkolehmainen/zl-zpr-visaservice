package charts

import (
	"testing"

	"neboagency.com/zpr-dashborad/internal/styles"
)

// Samples above the canvas height used to map to negative braille pixels and
// panic in setPixel. Any panic here fails the test.
func TestDotChartOutOfRangeSamples(t *testing.T) {
	for _, data := range [][]int{
		{0, 90},          // full scale
		{1, 19},          // first value that used to overflow
		{90, 0},          // descending
		{-5, 200},        // outside [0, MAX_VALUE] both ends
		{50, 50, 50, 50}, // flat
	} {
		DotChart(60, 17, styles.ColorRed, data)
	}
}

// setPixel must drop off-canvas coordinates rather than index out of range.
func TestSetPixelOffCanvas(t *testing.T) {
	c := createDotCanvas(10, 5)
	for _, p := range [][2]int{{-1, -1}, {0, -1}, {-1, 0}, {0, -3}, {100, 0}, {0, 100}} {
		c.setPixel(p[0], p[1], styles.ColorRed)
	}
}

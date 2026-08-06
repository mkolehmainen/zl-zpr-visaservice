package charts

import (
	"fmt"
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"

	"neboagency.com/zpr-dashborad/internal/styles"
)

func revIAbs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

type DotCanvas struct {
	cells         [][]uint8
	colors        [][]color.Color
	width, height int
}

var dotBit = [2][4]uint8{
	{0x01, 0x02, 0x04, 0x40},
	{0x08, 0x10, 0x20, 0x80},
}

func createDotCanvas(width, height int) *DotCanvas {
	// Allocate pixels
	cells := make([][]uint8, height)
	cols := make([][]color.Color, height)

	// Draw and reset canvas
	for y := 0; y < height; y++ {
		cells[y] = make([]uint8, width)
		cols[y] = make([]color.Color, width)
		for x := 0; x < width; x++ {
			cols[y][x] = styles.ColorFg
		}
	}

	return &DotCanvas{
		cells:  cells,
		colors: cols,
		width:  width,
		height: height,
	}
}

// Set a single pixel on the canvas
func (c *DotCanvas) setPixel(px, py int, col color.Color) {
	cx, cy := px/2, py/4
	if cx < 0 || cy < 0 || cx >= c.width || cy >= c.height {
		return
	}
	c.cells[cy][cx] |= dotBit[px%2][py%4]
	c.colors[cy][cx] = col
}

func (c *DotCanvas) drawLine(x0, y0, x1, y1 int, col color.Color) {
	dx := revIAbs(x1 - x0)
	dy := revIAbs(y1 - y0)
	sx, sy := 1, 1
	if x0 > x1 {
		sx = -1
	}
	if y0 > y1 {
		sy = -1
	}
	err := dx - dy
	for {
		c.setPixel(x0, y0, col)
		if x0 == x1 && y0 == y1 {
			break
		}
		e2 := err * 2
		if e2 > -dy {
			err -= dy
			x0 += sx
		}
		if e2 < dx {
			err += dx
			y0 += sy
		}
	}
}

func (c DotCanvas) render() []string {
	rows := make([]string, c.height)

	// Render bits that need to be rendered
	for y := 0; y < c.height; y++ {
		var sb strings.Builder
		for x := 0; x < c.width; x++ {
			ch := string(rune(0x2800 + int(c.cells[y][x])))
			sb.WriteString(lipgloss.NewStyle().Foreground(c.colors[y][x]).Render(ch))
		}

		rows[y] = sb.String()
	}

	return rows
}

func DotChart(width int, height int, color color.Color, data []int) string {
	const MAX_VALUE = 90

	const yLabelW = 5
	canvasW := width - 4 - yLabelW // Space for values, remove borders
	canvasH := height - 7          // Space for label, remove borders

	if canvasW < 10 || canvasH < 2 || len(data) < 2 {
		return lipgloss.NewStyle().
			Width(width - 4).Height(height - 4).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(styles.ColorBorder).
			Render("\nNo data yet.")
	}

	// Calculate Y Range
	min := data[0]
	max := min
	for _, v := range data {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}

	if max <= min {
		max = min + 1
	}

	// Map X coodinates to actual coordinates on the chart space
	mapX := func(i int) int { return i * (canvasW*2 - 1) / (len(data) - 1) }
	mapY := func(v int) int {
		if v < 0 {
			v = 0
		}
		if v > MAX_VALUE {
			v = MAX_VALUE
		}
		return canvasH*4 - 1 - v*(canvasH*20-1)/MAX_VALUE
	}

	// Create and reset the braile canvas
	canvas := createDotCanvas(canvasW, canvasH)

	// Draw total revocations in blue first, then auto in green on top
	for i := 1; i < len(data); i++ {
		canvas.drawLine(
			mapX(i-1), mapY(data[i-1]),
			mapX(i), mapY(data[i]),
			color,
		)
	}

	rendered := canvas.render()

	var rows []string
	for i, line := range rendered {
		var label string
		switch {
		case i == 0:
			label = fmt.Sprintf("%3d │", max)
		case i == canvasH/2:
			label = fmt.Sprintf("%3d │", (min+max)/2)
		case i == canvasH-1:
			label = fmt.Sprintf("%3d │", min)
		default:
			label = "    │"
		}
		rows = append(rows, styles.ValueStyle.Foreground(styles.ColorDimmed).Render(label)+line)
	}

	rows = append(rows,
		styles.ValueStyle.
			Foreground(styles.ColorDimmed).
			PaddingLeft(4).
			Width(canvasW+5).
			Render("└"+strings.Repeat("─", canvasW)),
	)
	pad := canvasW - 6
	rows = append(rows, styles.ValueStyle.Foreground(styles.ColorDimmed).Render("    T-2m"+strings.Repeat(" ", pad)+"Now"))

	return strings.Join(rows, "\n")
}

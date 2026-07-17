//! Small widget/render helpers that do not need `Gui` state.

use ratatui::style::{Style, Stylize};
use ratatui::text::Line;
use ratatui::widgets::{Block, BorderType, Borders, TableState};

use super::Pane;

/// Minimum sparkline width (bars) when shown; below this the sparkline is dropped.
pub(super) const SPARK_MIN: usize = 8;
/// Maximum sparkline width (bars); history ring buffers hold this many samples.
pub(super) const SPARK_MAX: usize = 16;

/// Render `vals` as unicode bars scaled to the slice max; all-min when idle.
pub(super) fn sparkline(vals: &[u64]) -> String {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let max = vals.iter().copied().max().unwrap_or(0);
    if max == 0 {
        return "▁".repeat(vals.len());
    }
    vals.iter()
        .map(|&v| BARS[((v * 7) / max) as usize])
        .collect()
}

/// Clamp a scroll offset so the last content line can reach the pane bottom
/// but you can't scroll into empty space; 0 when content fits the viewport.
pub(super) fn clamp_scroll(offset: u16, content_h: u16, viewport_h: u16) -> u16 {
    offset.min(content_h.saturating_sub(viewport_h))
}

/// Next selection index given current index, list length, and direction.
/// Clamps at 0 and len-1; None only for an empty list.
pub(super) fn move_selection(current: Option<usize>, len: usize, down: bool) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let cur = current.unwrap_or(0);
    Some(if down {
        (cur + 1).min(len - 1)
    } else {
        cur.saturating_sub(1)
    })
}

/// One-line description of the entity feeding the details pane, e.g.
/// "visa 1001" or "actor (none selected)".
pub(super) fn detail_line(source: Pane, id: Option<String>) -> String {
    let label = match source {
        Pane::Actors => "actor",
        Pane::Services => "service",
        Pane::Visas => "visa",
        Pane::Details => return String::new(),
    };
    match id {
        Some(id) => format!("{label} {id}"),
        None => format!("{label} (none selected)"),
    }
}

/// Keep a stored selection in range after the row vec is rebuilt.
pub(super) fn clamp_state(state: &mut TableState, len: usize) {
    state.select(match (state.selected(), len) {
        (_, 0) => None,
        (Some(i), _) if i >= len => Some(len - 1),
        (None, _) => Some(0),
        (some, _) => some,
    });
}

/// Bordered block for a pane; thick bold border when selected, and the
/// hot-key letter of the title underlined+bold.
pub(super) fn pane_block<'a>(letter: &'a str, rest: &'a str, selected: bool) -> Block<'a> {
    let title = Line::from(vec![letter.underlined().bold(), rest.bold()]);
    let block = Block::default().borders(Borders::ALL).title(title);
    if selected {
        block
            .border_type(BorderType::Thick)
            .border_style(Style::default().bold())
    } else {
        block
    }
}

#[cfg(test)]
mod tests {
    use super::super::Pane;
    use super::{clamp_scroll, detail_line, move_selection, sparkline};

    /// move_selection clamps at both ends and handles the empty list.
    #[test]
    fn move_selection_clamps_and_steps() {
        assert_eq!(move_selection(None, 0, true), None);
        assert_eq!(move_selection(Some(0), 3, false), Some(0)); // clamp top
        assert_eq!(move_selection(Some(2), 3, true), Some(2)); // clamp bottom
        assert_eq!(move_selection(Some(0), 3, true), Some(1)); // step down
        assert_eq!(move_selection(Some(2), 3, false), Some(1)); // step up
    }

    /// detail_line formats "<entity> <id>" and falls back when nothing selected.
    #[test]
    fn detail_line_formats_and_falls_back() {
        assert_eq!(detail_line(Pane::Visas, Some("1001".into())), "visa 1001");
        assert_eq!(detail_line(Pane::Actors, None), "actor (none selected)");
    }

    /// clamp_scroll: fits-in-view clamps to 0; past-end clamps to the max;
    /// in-range is untouched.
    #[test]
    fn clamp_scroll_bounds() {
        // Content shorter than viewport → no scroll.
        assert_eq!(clamp_scroll(5, 10, 20), 0);
        // Offset past the end → content_h - viewport_h.
        assert_eq!(clamp_scroll(100, 30, 10), 20);
        // Offset within range → unchanged.
        assert_eq!(clamp_scroll(3, 30, 10), 3);
        // Exactly fits → 0.
        assert_eq!(clamp_scroll(4, 10, 10), 0);
    }

    /// sparkline: no activity is all-min; a monotonic rise maxes at the top bar.
    #[test]
    fn sparkline_idle_and_peak() {
        assert_eq!(sparkline(&[0, 0]), "▁▁");
        assert!(sparkline(&[1, 2, 3]).ends_with('█'));
    }
}

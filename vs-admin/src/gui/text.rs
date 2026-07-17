//! Text layout helpers: labeled detail rows and word wrapping.

use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Width of the label column in the visa Details view. 13 = longest label
/// ("last contact"/"connect reqs", 12 chars) plus a one-space gutter.
pub(super) const LABEL_W: u16 = 13;

/// Color for the labels/headings in the visa Details view (vs. plain values).
pub(super) const HEADING_STYLE: Style = Style::new().fg(Color::Cyan);

/// Attribute key / value colors (distinct from each other and the heading).
pub(super) const ATTR_KEY_STYLE: Style = Style::new().fg(Color::Yellow);
pub(super) const ATTR_VAL_STYLE: Style = Style::new().fg(Color::White);

/// A labeled row: `label` (heading color) in a fixed `LABEL_W` column, `value`
/// wrapped to the remaining width with continuation lines indented under the
/// value column.
pub(super) fn labeled(label: &str, value: &str, width: u16) -> Vec<Line<'static>> {
    let lw = LABEL_W as usize;
    // Column available for the value; keep at least 1 so we always progress.
    let vw = (width.saturating_sub(LABEL_W)).max(1) as usize;
    let wrapped = wrap_words(value, vw);
    let mut lines = Vec::with_capacity(wrapped.len().max(1));
    for (i, seg) in wrapped.iter().enumerate() {
        let label_span = if i == 0 {
            Span::from(format!("{label:<lw$}")).style(HEADING_STYLE)
        } else {
            Span::from(" ".repeat(lw))
        };
        lines.push(Line::from(vec![label_span, Span::from(seg.clone())]));
    }
    lines
}

/// Word-wrap `s` to `width` cols. Splits on spaces; a single word longer than
/// `width` is hard-split. Always returns at least one segment.
pub(super) fn wrap_words(s: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut out = Vec::new();
    let mut cur = String::new();
    for word in s.split_whitespace() {
        let word_w = UnicodeWidthStr::width(word);
        if word_w > width {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            let chunks = split_word_by_display_width(word, width);
            let last = chunks.len().saturating_sub(1);
            for (i, chunk) in chunks.into_iter().enumerate() {
                if i == last {
                    cur = chunk;
                } else {
                    out.push(chunk);
                }
            }
            continue;
        }
        if cur.is_empty() {
            cur = word.to_string();
        } else if UnicodeWidthStr::width(cur.as_str()) + 1 + word_w <= width {
            cur.push(' ');
            cur.push_str(word);
        } else {
            out.push(std::mem::take(&mut cur));
            cur = word.to_string();
        }
    }
    out.push(cur);
    out
}

/// Split one whitespace-free string into UTF-8-safe display-width chunks.
fn split_word_by_display_width(s: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut chunks = Vec::new();
    let mut cur = String::new();
    let mut cur_w = 0;

    for ch in s.chars() {
        let ch_w = UnicodeWidthChar::width(ch).unwrap_or(0).max(1);
        if cur_w > 0 && cur_w + ch_w > width {
            chunks.push(std::mem::take(&mut cur));
            cur_w = 0;
        }
        cur.push(ch);
        cur_w += ch_w;
    }

    if !cur.is_empty() {
        chunks.push(cur);
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::{LABEL_W, labeled, wrap_words};

    /// labeled wraps long values and indents continuation lines by LABEL_W.
    #[test]
    fn labeled_wraps_and_indents() {
        let lines = labeled("zpl", "alpha bravo charlie delta echo foxtrot", 24);
        assert!(lines.len() > 1, "expected wrapping");
        // Continuation line begins with LABEL_W spaces.
        let second = lines[1].to_string();
        assert!(second.starts_with(&" ".repeat(LABEL_W as usize)));
    }

    /// wrap_words hard-splits non-ASCII text without cutting UTF-8 bytes.
    #[test]
    fn wrap_words_handles_unicode_hard_split() {
        assert_eq!(wrap_words("éé", 1), vec!["é".to_string(), "é".to_string()]);
        assert_eq!(
            wrap_words("日本語", 2),
            vec!["日".to_string(), "本".to_string(), "語".to_string()]
        );
    }
}

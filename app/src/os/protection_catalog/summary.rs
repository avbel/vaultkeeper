//! The headline over the rows and their grouping into sections.

use super::{Group, Level, ProtectionRow, Tone};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub text: String,
    pub tone: Tone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// The whole line, for the accessible label and tests.
    pub text: String,
    pub segments: Vec<Segment>,
    /// The header badge: red if any row is red, else yellow if a counted row is, else green.
    pub tone: Tone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub label: String,
    pub rows: Vec<ProtectionRow>,
}

fn count(rows: &[&ProtectionRow], level: Level) -> usize {
    rows.iter().filter(|row| row.level == level).count()
}

/// `None` when no counted chain is present, which hides the header.
#[must_use]
pub fn summarize(rows: &[ProtectionRow]) -> Option<Summary> {
    let counted: Vec<&ProtectionRow> = rows.iter().filter(|row| row.counted()).collect();
    if counted.is_empty() {
        return None;
    }
    let total = counted.len();
    let active = count(&counted, Level::Active);
    let limited = count(&counted, Level::Limited);
    let off = count(&counted, Level::Off);
    let missing = count(&counted, Level::Missing);
    let noun = if total == 1 {
        "protection"
    } else {
        "protections"
    };
    let first = if active == total && total == 1 {
        format!("1 {noun} active")
    } else if active == total {
        format!("All {total} {noun} active")
    } else {
        format!("{active} of {total} {noun} active")
    };
    let mut segments = vec![Segment {
        text: first,
        tone: Tone::Neutral,
    }];
    let off_tone = if counted
        .iter()
        .any(|row| row.level == Level::Off && row.tone == Tone::Red)
    {
        Tone::Red
    } else {
        Tone::Yellow
    };
    for (n, word, tone) in [
        (limited, "limited", Tone::Yellow),
        (off, "off", off_tone),
        (missing, "missing", Tone::Red),
    ] {
        if n > 0 {
            segments.push(Segment {
                text: format!(" · {n} {word}"),
                tone,
            });
        }
    }
    let tone = if rows.iter().any(|row| row.tone == Tone::Red) {
        Tone::Red
    } else if counted.iter().any(|row| row.tone == Tone::Yellow) {
        Tone::Yellow
    } else {
        Tone::Green
    };
    let text = segments
        .iter()
        .map(|segment| segment.text.as_str())
        .collect();
    Some(Summary {
        text,
        segments,
        tone,
    })
}

const ATTENTION: &str = "NEEDS ATTENTION";

/// NEEDS ATTENTION first (Missing, then Limited, then Off, counted rows only), then each group
/// without the rows already shown there. Empty sections are dropped.
#[must_use]
pub fn sections(rows: &[ProtectionRow]) -> Vec<Section> {
    let needs = |row: &&ProtectionRow| row.counted() && row.level != Level::Active;
    let mut attention: Vec<ProtectionRow> = Vec::new();
    for level in [Level::Missing, Level::Limited, Level::Off] {
        attention.extend(
            rows.iter()
                .filter(needs)
                .filter(|row| row.level == level)
                .cloned(),
        );
    }
    let mut out = Vec::new();
    if !attention.is_empty() {
        out.push(Section {
            label: ATTENTION.to_owned(),
            rows: attention,
        });
    }
    for group in Group::ALL {
        let members: Vec<ProtectionRow> = rows
            .iter()
            .filter(|row| row.group == group && !needs(row))
            .cloned()
            .collect();
        if !members.is_empty() {
            out.push(Section {
                label: group.label().to_owned(),
                rows: members,
            });
        }
    }
    out
}

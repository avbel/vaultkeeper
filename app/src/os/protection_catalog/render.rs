//! The plain-text form of the rows, for `vaultkeeper security status` and Copy details.

use std::fmt::Write as _;

use super::{Group, Level, ProtectionRow, summarize};

const WIDTH: usize = 34;

/// The fix line under a row that is not Active: its steps, else its notes.
fn fix_line(row: &ProtectionRow) -> Option<String> {
    let parts = if row.steps.is_empty() {
        &row.notes
    } else {
        &row.steps
    };
    (!parts.is_empty()).then(|| format!("Fix: {}", parts.join(" ")))
}

fn write_row(out: &mut String, row: &ProtectionRow) {
    let _ = writeln!(
        out,
        "{:WIDTH$}{:9}{}",
        row.title,
        row.level.word(),
        row.technical
    );
    if row.level != Level::Active {
        let _ = writeln!(out, "    {}", row.detail);
        if let Some(fix) = fix_line(row) {
            let _ = writeln!(out, "    {fix}");
        }
    }
}

/// Headline, then the rows grouped, then the desktop rows under their own heading.
#[must_use]
pub fn plain_text(rows: &[ProtectionRow]) -> String {
    let mut out = String::new();
    if let Some(summary) = summarize(rows) {
        let _ = writeln!(out, "{}\n", summary.text);
    }
    for row in rows.iter().filter(|row| row.group != Group::Desktop) {
        write_row(&mut out, row);
    }
    let desktop: Vec<&ProtectionRow> = rows
        .iter()
        .filter(|row| row.group == Group::Desktop)
        .collect();
    if !desktop.is_empty() {
        out.push_str("Desktop integration (not counted)\n");
        for row in desktop {
            write_row(&mut out, row);
        }
    }
    out
}

/// The rows only the running app can report, which a separate CLI process never has.
const APP_ONLY: [(&str, &str); 4] = [
    ("sandbox", "App sandbox"),
    ("memory-read", "Memory reading by other programs"),
    ("hotkey", "Global shortcuts"),
    ("clipboard", "Copied passwords"),
];

/// What `security status` prints: the text plus a line naming the rows it cannot see.
#[must_use]
pub fn status_text(rows: &[ProtectionRow]) -> String {
    let mut out = plain_text(rows);
    let absent: Vec<&str> = APP_ONLY
        .iter()
        .filter(|(id, _)| !rows.iter().any(|row| row.id == *id))
        .map(|(_, title)| *title)
        .collect();
    if !absent.is_empty() {
        let verb = if absent.len() == 1 { "is" } else { "are" };
        let _ = writeln!(
            out,
            "\n{} {verb} reported by the running app: Settings → System protection.",
            absent.join(", ")
        );
    }
    out
}

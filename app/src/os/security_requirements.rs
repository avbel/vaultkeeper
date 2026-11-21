//! What Vaultkeeper needs from a Linux system, as one table (linux-plan.md 7d). `vaultkeeper
//! security requirements` prints it, and docs/solutions/linux-requirements.md is generated from
//! it: a test fails when the two differ. A row joins when its check is enforced at startup.

pub struct Requirement {
    pub item: &'static str,
    pub probe: &'static str,
    pub class: &'static str,
    pub missing: &'static str,
    pub ubuntu: &'static str,
    pub fedora: &'static str,
    pub omarchy: &'static str,
}

pub const REQUIREMENTS: &[Requirement] = &[
    Requirement {
        item: "Kernel 6.5 or newer with SO_PEERPIDFD; 6.13 or newer for PIDFD_GET_INFO",
        probe: "`SO_PEERPIDFD` on a socket pair, `PIDFD_GET_INFO` on a pidfd",
        class: "Refuse",
        missing: "peers cannot be identified; Vaultkeeper will not start",
        ubuntu: "stock kernel",
        fedora: "stock kernel",
        omarchy: "`linux-omarchy`, `linux` or `linux-lts`",
    },
    Requirement {
        item: "`XDG_RUNTIME_DIR` on tmpfs, owned by you, mode 0700",
        probe: "`stat` and `statfs` of the directory",
        class: "Refuse",
        missing: "nowhere private for the sockets; Vaultkeeper will not start",
        ubuntu: "provided by logind",
        fedora: "provided by logind",
        omarchy: "provided by logind (UWSM)",
    },
    Requirement {
        item: "Wayland session (daemon and windows; not the CLI)",
        probe: "`WAYLAND_DISPLAY` is set and its socket connects",
        class: "Refuse",
        missing: "no windows; X11 is not supported",
        ubuntu: "log in to the \"Ubuntu\" (Wayland) session",
        fedora: "stock",
        omarchy: "stock (Hyprland)",
    },
    Requirement {
        item: "Keys in memory: `memfd_secret`, else keyctl, else mlock",
        probe: "the key store reports the mechanism it obtained",
        class: "Refuse below mlock",
        missing: "keys could not be held in protected memory",
        ubuntu: "stock",
        fedora: "stock",
        omarchy: "stock; a custom kernel needs `CONFIG_SECRETMEM`",
    },
    Requirement {
        item: "Data directory owned by you, not a symbolic link; modes 0700 and 0600",
        probe: "`stat` through an `O_NOFOLLOW` descriptor",
        class: "Refuse (owner, link); modes are repaired",
        missing: "Vaultkeeper will not start",
        ubuntu: "`chown -R $USER ~/.local/share/vaultkeeper`",
        fedora: "same",
        omarchy: "same",
    },
];

const COLUMNS: [&str; 7] = [
    "Item",
    "Probe",
    "Class",
    "Missing →",
    "Fix: Ubuntu 26.10",
    "Fedora 45",
    "Omarchy (Arch)",
];

impl Requirement {
    const fn cells(&self) -> [&'static str; 7] {
        [
            self.item,
            self.probe,
            self.class,
            self.missing,
            self.ubuntu,
            self.fedora,
            self.omarchy,
        ]
    }
}

/// docs/solutions/linux-requirements.md, byte for byte.
#[must_use]
pub fn markdown() -> String {
    let mut text = String::from(
        "# Linux requirements\n\n\
         Generated from `app/src/os/security_requirements.rs`; `vaultkeeper security \
         requirements` prints the same table. On Ubuntu 26.10, Fedora 45 and Omarchy the stock \
         install meets every line. Any other Arch setup is unsupported and runs only when these \
         checks pass.\n\n",
    );
    let row = |cells: &[&str]| format!("| {} |\n", cells.join(" | "));
    text.push_str(&row(&COLUMNS));
    text.push_str(&row(&["---"; 7]));
    for requirement in REQUIREMENTS {
        text.push_str(&row(&requirement.cells()));
    }
    text
}

/// The terminal form: one block per item.
#[must_use]
pub fn table() -> String {
    REQUIREMENTS
        .iter()
        .map(|requirement| {
            let cells = requirement.cells();
            let lines: Vec<String> = COLUMNS
                .iter()
                .zip(cells)
                .skip(1)
                .map(|(column, cell)| format!("  {column}: {}", cell.replace('`', "")))
                .collect();
            format!("{}\n{}\n", cells[0].replace('`', ""), lines.join("\n"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `UPDATE_DOCS=1 cargo test -p vaultkeeper requirements_doc` rewrites the document.
    #[test]
    fn requirements_doc_matches_the_table() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../docs/solutions/linux-requirements.md"
        );
        if std::env::var_os("UPDATE_DOCS").is_some() {
            std::fs::write(path, markdown()).expect("write the document");
        }
        let committed =
            std::fs::read_to_string(path).expect("docs/solutions/linux-requirements.md");
        assert_eq!(
            committed,
            markdown(),
            "run UPDATE_DOCS=1 cargo test -p vaultkeeper requirements_doc"
        );
    }

    #[test]
    fn the_terminal_table_has_every_item_without_markup() {
        let table = table();
        assert_eq!(table.matches("  Class: ").count(), REQUIREMENTS.len());
        assert!(!table.contains('`'));
    }
}

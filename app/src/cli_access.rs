//! Read opted-in logins from the running desktop app without starting a GUI.

use std::io::{self, Write};

use anyhow::{Context, bail};
use serde::Serialize;
use vk_ipc::cli_access::{self, Request, Response};
use zeroize::Zeroizing;

use crate::{
    cli::USAGE,
    os::layout::{CLI_SOCKET, data_dir},
};

pub fn run(args: &[String]) -> anyhow::Result<()> {
    let request = match args {
        [command] if command == "list" => Request::ListKeys,
        [_, flag] if matches!(flag.as_str(), "--help" | "-h") => {
            writeln!(io::stdout(), "{USAGE}")?;
            return Ok(());
        }
        [command, key] if command == "get_fields" && valid_argument(key) => {
            Request::GetFields { key: key.clone() }
        }
        [command, key, field, flags @ ..]
            if command == "get"
                && valid_argument(key)
                && valid_argument(field)
                && (flags.is_empty() || flags == ["--allow-private"]) =>
        {
            Request::GetValue {
                key: key.clone(),
                field: field.clone(),
                allow_private: !flags.is_empty(),
            }
        }
        _ => bail!("Invalid CLI arguments. See vaultkeeper --help."),
    };
    let socket = data_dir()?.join(CLI_SOCKET);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    match runtime.block_on(cli_access::call(&socket, &request)) {
        Ok(Response::Keys(keys)) => write_json(&keys),
        Ok(Response::Fields(fields)) => write_json(&fields),
        Ok(Response::Value(value)) => write_output(value.as_bytes()),
        Ok(Response::Locked) => bail!("Vaultkeeper is locked. Unlock it in the app, then retry."),
        Ok(Response::LoggedOut) => bail!("Log in to Vaultkeeper and unlock the vault, then retry."),
        Ok(Response::NotFound) => {
            bail!("This login is unavailable to the CLI. Run vaultkeeper list.")
        }
        Ok(Response::NoSuchField) => {
            bail!("This field is missing or empty. Run vaultkeeper get_fields <key>.")
        }
        Ok(Response::PrivateField) => {
            bail!(
                "This field is private. Add --allow-private only when piping its value directly to the intended command in your shell script."
            )
        }
        Ok(Response::Unavailable) | Err(_) => {
            bail!(
                "Vaultkeeper CLI access is unavailable. Check that the app is running and CLI access is enabled."
            )
        }
    }
}

fn valid_argument(arg: &str) -> bool {
    !arg.is_empty() && !arg.starts_with('-') && arg.len() <= 256
}

fn write_json(value: &impl Serialize) -> anyhow::Result<()> {
    let mut output = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *output, value).context("encode Vaultkeeper CLI output")?;
    output.push(b'\n');
    write_output(&output)
}

fn write_output(output: &[u8]) -> anyhow::Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(output)?;
    stdout.flush()?;
    Ok(())
}

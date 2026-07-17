//! Same-directory atomic file replacement for operator-managed configuration
//! and secret material.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use anyhow::{Context, Result};
use rand::rngs::OsRng;
use rand::RngCore as _;

pub fn write(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("output path must have a UTF-8 file name")?;

    let mut random = [0u8; 8];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|err| anyhow::anyhow!("OS CSPRNG failed while creating temporary file: {err}"))?;
    let temporary = parent.join(format!(
        ".{name}.tmp-{}-{}",
        std::process::id(),
        hex::encode(random)
    ));

    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)
            .with_context(|| format!("creating temporary file {}", temporary.display()))?;
        file.write_all(contents)
            .with_context(|| format!("writing temporary file {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing temporary file {}", temporary.display()))?;
        drop(file);
        std::fs::rename(&temporary, path)
            .with_context(|| format!("atomically replacing {}", path.display()))?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

//! Atomic construction and publication of the attested node metadata file.

use std::path::Path;

use canary_core::node::NodeMetadata;

#[derive(Debug, thiserror::Error)]
pub enum MetadataError {
    #[error("metadata is invalid: {0}")]
    Invalid(#[from] canary_core::node::NodeError),
    #[error("could not canonicalize metadata: {0}")]
    Canonical(#[from] canary_core::canonical::CanonicalError),
    #[error("metadata filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Write strict metadata using a same-directory temporary file and rename.
/// Bootproofd observes either the previous complete document or this complete
/// document, never a partially written JSON value.
pub async fn write_metadata_atomic(
    path: &Path,
    metadata: &NodeMetadata,
) -> Result<(), MetadataError> {
    metadata.validate()?;
    let bytes = canary_core::canonical::canonicalize(metadata)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    tokio::fs::create_dir_all(parent).await?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("metadata"),
        std::process::id()
    ));
    tokio::fs::write(&temp, bytes).await?;
    tokio::fs::rename(&temp, path).await?;
    Ok(())
}

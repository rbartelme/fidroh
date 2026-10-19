//! This machine's iroh endpoint, with an identity that survives restarts.

use std::path::Path;

use anyhow::Result;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointId};

use crate::keys::load_or_create;

/// An iroh endpoint whose identity comes from <data-dir>/secret.key.
pub async fn bind_endpoint(data_dir: &Path) -> Result<Endpoint> {
    let key = load_or_create(&data_dir.join("secret.key"))?;
    Ok(Endpoint::builder(presets::N0)
        .secret_key(key)
        .bind()
        .await?)
}

/// This machine's endpoint id, without starting anything.
pub fn id(data_dir: &Path) -> Result<EndpointId> {
    Ok(load_or_create(&data_dir.join("secret.key"))?.public())
}

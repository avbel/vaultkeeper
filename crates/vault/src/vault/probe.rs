//! The login screen's server check: `/alive`, then the release from `/api/version`.

use std::time::Duration;

use bwl_api::Prober;
use url::Url;

use crate::{Result, model::ServerProbe};

pub(super) async fn probe(server: &Url, timeout: Duration) -> Result<ServerProbe> {
    let prober = Prober::new(server, timeout)?;
    prober.alive().await?;
    Ok(ServerProbe {
        version: prober.version().await,
    })
}

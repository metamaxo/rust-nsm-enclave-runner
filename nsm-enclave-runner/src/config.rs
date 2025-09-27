use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub log_level: Option<String>,

    #[serde(default = "def_public_addr")]
    pub public_addr: SocketAddr,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        tracing::debug!("fetching config");
        let _ = dotenvy::dotenv();
        let cfg: Self = envy::prefixed("RUNNER_").from_env()?;
        Ok(cfg)
    }

    pub fn dev() -> anyhow::Result<Self> {
        Ok(Config {
            log_level: Some("debug".to_string()),
            public_addr: def_public_addr(),
        })
    }

    pub fn info(&self) {
        tracing::info!(public_addr = %self.public_addr, "effective config");
        if self.public_addr.ip().is_unspecified() {
            tracing::warn!("binding to 0.0.0.0 — make sure this is intentional");
        }
    }
}

fn def_public_addr() -> SocketAddr {
    // Only the port is used for VSOCK (CID comes from VMADDR_CID_ANY); IP is ignored.
    "127.0.0.1:8443".parse().unwrap()
}

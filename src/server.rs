use crate::connection;
use anyhow::Result;
use tokio::net::TcpListener;
use tracing::{info, warn};

pub async fn start_listener() -> Result<TcpListener> {
    let listener = TcpListener::bind("0.0.0.0:0").await?;
    Ok(listener)
}

pub async fn accept_loop(listener: TcpListener) -> Result<()> {
    loop {
        let (socket, addr) = listener.accept().await?;
        info!("bağlantı: {}", addr);
        tokio::spawn(async move {
            if let Err(e) = connection::handle(socket, addr).await {
                warn!("bağlantı hatası ({}): {:?}", addr, e);
            }
        });
    }
}

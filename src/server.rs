use crate::connection;
use anyhow::Result;
use tokio::net::TcpListener;
use tracing::{info, warn};

/// Varsayılan TCP portu. Random port yerine sabit değer seçildi çünkü
/// Linux kullanıcıları UFW/firewalld ile tek sefer kural açıp unutmak ister.
/// `HEKADROP_PORT` ortam değişkeniyle override edilebilir.
const DEFAULT_PORT: u16 = 47893;

pub async fn start_listener() -> Result<TcpListener> {
    let wanted = std::env::var("HEKADROP_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT);

    // Sabit portu dene; kullanımdaysa OS'un seçeceği random port'a düş. Böylece
    // çift-instance çalıştırma durumu kilitlenme yerine düşüş davranışı verir.
    match TcpListener::bind(("0.0.0.0", wanted)).await {
        Ok(l) => {
            info!("TCP sabit portta dinleniyor: {}", wanted);
            Ok(l)
        }
        Err(e) => {
            warn!(
                "sabit port {} alınamadı ({}) — random port'a düşülüyor",
                wanted, e
            );
            Ok(TcpListener::bind("0.0.0.0:0").await?)
        }
    }
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

use crate::connection;
use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{info, warn};

/// Varsayılan TCP portu. Random port yerine sabit değer seçildi çünkü
/// Linux kullanıcıları UFW/firewalld ile tek sefer kural açıp unutmak ister.
/// `HEKADROP_PORT` ortam değişkeniyle override edilebilir.
const DEFAULT_PORT: u16 = 47893;

/// Aynı anda işlenebilecek maksimum gelen bağlantı sayısı.
///
/// **Neden:** Her bağlantı tokio task + payload buffer + crypto state +
/// pending destination path'leri tüketir. Limit yoksa saldırgan yüzlerce
/// TCP bağlantısı açıp kaynakları şişirerek DoS yapabilir (rate limiter
/// aynı IP için 10/60sn kural koyar ama farklı IP'lerden gelenleri
/// kaplamayı engellemez). 32 sınırı tipik ev kullanımı için fazlasıyla
/// yeterli; aşan bağlantılar semaphore'da bekletilmek yerine TCP RST ile
/// kısa sürede reddedilir.
const MAX_CONCURRENT_CONNECTIONS: usize = 32;

pub async fn start_listener() -> Result<TcpListener> {
    // `HEKADROP_PORT=0` özellikle filtrelenir: 0 "OS seçsin" anlamına gelir ama
    // "sabit port" semantiğini kırar, log'u yanıltır. 0 geçilirse default'a düşer.
    let wanted = std::env::var("HEKADROP_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|p| *p != 0)
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
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    loop {
        let (socket, addr) = listener.accept().await?;

        // PERF: Nagle algoritmasını devre dışı bırak. UKEY2 handshake küçük
        // (≤200 B) frame'lerden oluşuyor; default 200 ms Nagle bekleyişi her
        // frame'e gecikme ekler. Chunk frame'leri zaten 512 KB olduğundan
        // büyük transferlerde etkisi yok. Hata non-fatal — loglayıp devam.
        if let Err(e) = socket.set_nodelay(true) {
            warn!("set_nodelay başarısız ({}): {}", addr, e);
        }

        // `try_acquire_owned` — bloklamaz; doluysa bağlantıyı hemen kapat.
        let permit = match Arc::clone(&permits).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!(
                    "max concurrent ({}) aşıldı — {} reddedildi",
                    MAX_CONCURRENT_CONNECTIONS, addr
                );
                drop(socket);
                continue;
            }
        };

        info!("bağlantı: {}", addr);
        tokio::spawn(async move {
            if let Err(e) = connection::handle(socket, addr).await {
                warn!("bağlantı hatası ({}): {:?}", addr, e);
            }
            drop(permit); // connection bittiğinde permit geri döner
        });
    }
}

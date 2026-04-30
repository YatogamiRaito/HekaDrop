use crate::connection::{self, PlatformOps};
use crate::state::AppState;
use crate::ui_port::UiPort;
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
/// TCP bağlantısı açıp kaynakları şişirerek `DoS` yapabilir (rate limiter
/// aynı IP için 10/60sn kural koyar ama farklı IP'lerden gelenleri
/// kaplamayı engellemez). 32 sınırı tipik ev kullanımı için fazlasıyla
/// yeterli; aşan bağlantılar semaphore'da bekletilmek yerine TCP RST ile
/// kısa sürede reddedilir.
const MAX_CONCURRENT_CONNECTIONS: usize = 32;

/// TCP listener'ı `HEKADROP_PORT` veya default port'tan başlat (kullanımdaysa
/// random port'a düş).
///
/// # Errors
///
/// Returns `Err` if random fallback port'a bind dahi başarısız (privilege,
/// network stack arızası — tipik ev kullanımında tetiklenmez).
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

/// Listener'dan bağlantıları kabul et + her birini bounded semaphore altında
/// `connection::handle` task'ına ata.
///
/// # Errors
///
/// Returns `Err` if `listener.accept()` non-recoverable hata döndürürse
/// (network stack arızası, fd exhaustion). Per-connection hatalar task
/// içinde swallow edilir; loop devam eder.
pub async fn accept_loop(
    listener: TcpListener,
    ui: Arc<dyn UiPort>,
    state: Arc<AppState>,
    platform: Arc<dyn PlatformOps>,
) -> Result<()> {
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
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            warn!(
                "max concurrent ({}) aşıldı — {} reddedildi",
                MAX_CONCURRENT_CONNECTIONS, addr
            );
            drop(socket);
            continue;
        };

        info!("bağlantı: {}", addr);
        let ui_for_conn = Arc::clone(&ui);
        let state_for_conn = Arc::clone(&state);
        let platform_for_conn = Arc::clone(&platform);
        tokio::spawn(async move {
            if let Err(e) =
                connection::handle(socket, addr, ui_for_conn, state_for_conn, platform_for_conn)
                    .await
            {
                warn!("bağlantı hatası ({}): {:?}", addr, e);
            }
            drop(permit); // connection bittiğinde permit geri döner
        });
    }
}

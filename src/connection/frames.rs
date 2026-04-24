//! Frame builder / gönderim yardımcıları — `OfflineFrame` + `SharingFrame`
//! inşası, tek-atımlık `send_sharing_frame` / `send_disconnection` sarmalayıcıları.
//!
//! `sender.rs` da bu yardımcıları kullanır; yeniden-organizasyon sırasında
//! public yüzey aynı kalmak zorunda (bkz. `use crate::connection::...`).

use crate::frame;
use crate::location::nearby::connections::{
    os_info::OsType,
    payload_transfer_frame::{
        self as ptf, payload_header::PayloadType, PayloadChunk, PayloadHeader,
    },
    v1_frame, ConnectionResponseFrame, OfflineFrame, OsInfo, PayloadTransferFrame, V1Frame,
};
use crate::secure::SecureCtx;
use crate::sharing::nearby::{
    connection_response_frame::Status as ConsentStatus, frame::Version as ShVersion,
    paired_key_result_frame::Status as PkrStatus, v1_frame as sh_v1,
    ConnectionResponseFrame as ShConsent, Frame as SharingFrame, PairedKeyEncryptionFrame,
    PairedKeyResultFrame, V1Frame as ShV1Frame,
};
use crate::state;
use anyhow::Result;
use prost::Message;
use rand::RngCore;
use tokio::net::TcpStream;

pub(crate) fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut v);
    v
}

pub(crate) fn build_paired_key_encryption() -> SharingFrame {
    // Issue #17: `secret_id_hash` artık random değil — cihaz-kalıcı
    // `DeviceIdentity.long_term_key` üzerinden HKDF-SHA256 ile türetilir.
    // Peer bu değeri bizim "stabil kimlik"imiz olarak görür ve trusted
    // listesinde bu hash'e bağlı saklar.
    //
    // `signed_data` hâlâ random — v0.7'de pairing protokolüyle gerçek
    // ECDSA imza (long-term signing key) eklenecek. Şimdilik peer'lar
    // alanı doğrulamıyor (bizim tarafta da doğrulamıyoruz; bkz.
    // design 017 §5.5 / §9 answer #2).
    let hash = state::get().identity.secret_id_hash();
    SharingFrame {
        version: Some(ShVersion::V1 as i32),
        v1: Some(ShV1Frame {
            r#type: Some(sh_v1::FrameType::PairedKeyEncryption as i32),
            paired_key_encryption: Some(PairedKeyEncryptionFrame {
                secret_id_hash: Some(hash.to_vec().into()),
                // TODO(v0.7): signing_key() ile ECDSA imza + peer pubkey
                // doğrulaması pairing protokolüyle birlikte.
                signed_data: Some(random_bytes(72).into()),
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

pub(crate) fn build_paired_key_result() -> SharingFrame {
    SharingFrame {
        version: Some(ShVersion::V1 as i32),
        v1: Some(ShV1Frame {
            r#type: Some(sh_v1::FrameType::PairedKeyResult as i32),
            paired_key_result: Some(PairedKeyResultFrame {
                status: Some(PkrStatus::Unable as i32),
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

pub(crate) fn build_consent_accept() -> SharingFrame {
    build_consent(ConsentStatus::Accept)
}

pub(crate) fn build_consent_reject() -> SharingFrame {
    build_consent(ConsentStatus::Reject)
}

pub(crate) fn build_sharing_cancel() -> SharingFrame {
    SharingFrame {
        version: Some(ShVersion::V1 as i32),
        v1: Some(ShV1Frame {
            r#type: Some(sh_v1::FrameType::Cancel as i32),
            ..Default::default()
        }),
    }
}

fn build_consent(status: ConsentStatus) -> SharingFrame {
    SharingFrame {
        version: Some(ShVersion::V1 as i32),
        v1: Some(ShV1Frame {
            r#type: Some(sh_v1::FrameType::Response as i32),
            connection_response: Some(ShConsent {
                status: Some(status as i32),
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

pub(crate) async fn send_sharing_frame(
    socket: &mut TcpStream,
    ctx: &mut SecureCtx,
    sharing: &SharingFrame,
) -> Result<()> {
    let body = sharing.encode_to_vec();
    let payload_id: i64 = (rand::thread_rng().next_u64() >> 1) as i64;
    let total = body.len() as i64;

    // İlk chunk: tam gövde, offset=0, flags=0
    let first = wrap_payload_transfer(payload_id, total, 0, 0, body.clone());
    let enc1 = ctx.encrypt(&first.encode_to_vec())?;
    frame::write_frame(socket, &enc1).await?;

    // Son chunk: boş gövde, flags=1 (last)
    let last = wrap_payload_transfer(payload_id, total, total, 1, Vec::new());
    let enc2 = ctx.encrypt(&last.encode_to_vec())?;
    frame::write_frame(socket, &enc2).await?;
    Ok(())
}

pub(crate) fn wrap_payload_transfer(
    id: i64,
    total_size: i64,
    offset: i64,
    flags: i32,
    body: Vec<u8>,
) -> OfflineFrame {
    OfflineFrame {
        version: Some(1),
        v1: Some(V1Frame {
            r#type: Some(v1_frame::FrameType::PayloadTransfer as i32),
            payload_transfer: Some(PayloadTransferFrame {
                packet_type: Some(ptf::PacketType::Data as i32),
                payload_header: Some(PayloadHeader {
                    id: Some(id),
                    r#type: Some(PayloadType::Bytes as i32),
                    total_size: Some(total_size),
                    is_sensitive: Some(false),
                    ..Default::default()
                }),
                payload_chunk: Some(PayloadChunk {
                    offset: Some(offset),
                    flags: Some(flags),
                    body: Some(body.into()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

pub(crate) fn build_connection_response_accept() -> OfflineFrame {
    OfflineFrame {
        version: Some(1),
        v1: Some(V1Frame {
            r#type: Some(v1_frame::FrameType::ConnectionResponse as i32),
            connection_response: Some(ConnectionResponseFrame {
                response: Some(1),
                os_info: Some(OsInfo {
                    r#type: Some(OsType::Apple as i32),
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

pub(crate) async fn send_disconnection(socket: &mut TcpStream, ctx: &mut SecureCtx) -> Result<()> {
    let f = OfflineFrame {
        version: Some(1),
        v1: Some(V1Frame {
            r#type: Some(v1_frame::FrameType::Disconnection as i32),
            disconnection: Some(Default::default()),
            ..Default::default()
        }),
    };
    let enc = ctx.encrypt(&f.encode_to_vec())?;
    frame::write_frame(socket, &enc).await?;
    Ok(())
}

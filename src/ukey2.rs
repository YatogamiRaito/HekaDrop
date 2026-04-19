//! UKEY2 handshake — Quick Share'in P-256 + HKDF tabanlı anahtar değişim protokolü.
//!
//! Akış (receiver/server rolü):
//!   1) İstemci → ConnectionRequest (offline_wire_formats)
//!   2) İstemci → Ukey2ClientInit  (bu modül ele alır)
//!   3) Biz    → Ukey2ServerInit   (P-256 public key ile)
//!   4) İstemci → Ukey2ClientFinished (cipher commitment ile doğrulanır)
//!   5) ECDH → HKDF ile 4 anahtar + 4-haneli PIN

use crate::crypto;
use crate::frame;
use crate::securegcm::{
    ukey2_client_init, Ukey2ClientFinished, Ukey2ClientInit, Ukey2HandshakeCipher, Ukey2Message,
    Ukey2ServerInit,
};
use crate::securemessage::{EcP256PublicKey, GenericPublicKey, PublicKeyType};
use anyhow::{anyhow, bail, Result};
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{ecdh::diffie_hellman, EncodedPoint, PublicKey, SecretKey};
use prost::Message;
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::net::TcpStream;

pub struct DerivedKeys {
    /// Receiver tarafı: şifre çözme (istemciden gelen)
    pub decrypt_key: [u8; 32],
    /// Receiver tarafı: HMAC doğrulama (istemciden gelen)
    pub recv_hmac_key: [u8; 32],
    /// Receiver tarafı: şifreleme (sunucudan giden)
    pub encrypt_key: [u8; 32],
    /// Receiver tarafı: HMAC imzalama (sunucudan giden)
    pub send_hmac_key: [u8; 32],
    #[allow(dead_code)]
    pub auth_key: [u8; 32],
    pub pin_code: String,
}

/// Gönderici (client) rolünde tam UKEY2 handshake.
/// Socket üzerinde: biz ClientInit → peer ServerInit → biz ClientFinished → ECDH + HKDF.
///
/// Döndürülen DerivedKeys **client perspektifinde** doldurulur:
///   encrypt/send_hmac = client_* (bizden peer'a), decrypt/recv_hmac = server_* (peer'den bize)
pub async fn client_handshake(socket: &mut TcpStream) -> Result<DerivedKeys> {
    use sha2::{Digest, Sha512};

    // 1) P-256 anahtar çifti üret
    let secret_key = SecretKey::random(&mut OsRng);
    let public_key = secret_key.public_key();
    let encoded = public_key.to_encoded_point(false);
    let xy = encoded.as_bytes();
    let x = to_signed_bytes(&xy[1..33]);
    let y = to_signed_bytes(&xy[33..65]);

    let generic_pk = GenericPublicKey {
        r#type: PublicKeyType::EcP256 as i32,
        ec_p256_public_key: Some(EcP256PublicKey { x, y }),
        ..Default::default()
    };
    let generic_pk_bytes = generic_pk.encode_to_vec();

    // 2) ClientFinished mesajını önceden hazırla — commitment için SHA512'si alınacak
    let client_finished = Ukey2ClientFinished {
        public_key: Some(generic_pk_bytes),
    };
    let client_finished_msg = Ukey2Message {
        message_type: Some(4), // CLIENT_FINISH
        message_data: Some(client_finished.encode_to_vec()),
    };
    let client_finished_bytes = client_finished_msg.encode_to_vec();

    let commitment: Vec<u8> = {
        let mut s = Sha512::new();
        s.update(&client_finished_bytes);
        s.finalize().to_vec()
    };

    // 3) ClientInit inşa et
    let mut random = [0u8; 32];
    OsRng.fill_bytes(&mut random);

    let client_init = Ukey2ClientInit {
        version: Some(1),
        random: Some(random.to_vec()),
        cipher_commitments: vec![ukey2_client_init::CipherCommitment {
            handshake_cipher: Some(Ukey2HandshakeCipher::P256Sha512 as i32),
            commitment: Some(commitment),
        }],
        next_protocol: Some("AES_256_CBC-HMAC_SHA256".to_string()),
    };
    let client_init_msg = Ukey2Message {
        message_type: Some(2), // CLIENT_INIT
        message_data: Some(client_init.encode_to_vec()),
    };
    let client_init_bytes = client_init_msg.encode_to_vec();

    frame::write_frame(socket, &client_init_bytes).await?;

    // 4) ServerInit al
    let server_init_raw = frame::read_frame(socket).await?;
    let server_init_msg = Ukey2Message::decode(server_init_raw.as_ref())?;
    if server_init_msg.message_type != Some(3) {
        bail!(
            "beklenen SERVER_INIT, alınan message_type={:?}",
            server_init_msg.message_type
        );
    }
    let server_init_data = server_init_msg
        .message_data
        .ok_or_else(|| anyhow!("server_init.data yok"))?;
    let server_init = Ukey2ServerInit::decode(&server_init_data[..])?;

    // SECURITY (downgrade koruması): Peer'ın seçtiği cipher bizim öne
    // sürdüğümüz P256_SHA512 olmalı. Aksi halde tanımsız/zayıf cipher'a
    // yönlendirme saldırısına maruz kalırız. ClientInit sadece
    // P256_SHA512 önerdi — ServerInit farklı değer dönerse reddet.
    if server_init.handshake_cipher != Some(Ukey2HandshakeCipher::P256Sha512 as i32) {
        bail!(
            "ServerInit cipher downgrade reddedildi: {:?} (beklenen P256_SHA512)",
            server_init.handshake_cipher
        );
    }
    // Protocol version kontrolü — V1 dışında bir şey bekleme.
    if server_init.version != Some(1) {
        bail!(
            "ServerInit version={:?} — yalnız V1 destekleniyor",
            server_init.version
        );
    }

    // 5) ClientFinished gönder
    frame::write_frame(socket, &client_finished_bytes).await?;

    // 6) Peer public key'i parse et
    let peer_pk_bytes = server_init
        .public_key
        .ok_or_else(|| anyhow!("server_init.public_key yok"))?;
    let peer_generic = GenericPublicKey::decode(&peer_pk_bytes[..])?;
    let peer_ec = peer_generic
        .ec_p256_public_key
        .ok_or_else(|| anyhow!("peer ecP256 yok"))?;
    let peer_x = normalize_32(peer_ec.x);
    let peer_y = normalize_32(peer_ec.y);

    let mut uncompressed = vec![0x04u8];
    uncompressed.extend_from_slice(&peer_x);
    uncompressed.extend_from_slice(&peer_y);
    let encoded =
        EncodedPoint::from_bytes(&uncompressed).map_err(|e| anyhow!("peer pubkey parse: {}", e))?;
    let peer_pk = PublicKey::from_encoded_point(&encoded);
    let peer_pk = Option::<PublicKey>::from(peer_pk)
        .ok_or_else(|| anyhow!("peer pubkey geçersiz eğri noktası"))?;

    // 7) ECDH + HKDF
    let shared = diffie_hellman(secret_key.to_nonzero_scalar(), peer_pk.as_affine());
    let dhs_x = shared.raw_secret_bytes().to_vec();
    let derived_secret = crypto::sha256(&dhs_x);

    let mut ukey_info = Vec::with_capacity(client_init_bytes.len() + server_init_raw.len());
    ukey_info.extend_from_slice(&client_init_bytes);
    ukey_info.extend_from_slice(&server_init_raw);

    let auth_key = crypto::hkdf_sha256(&derived_secret, b"UKEY2 v1 auth", &ukey_info, 32);
    let next_secret = crypto::hkdf_sha256(&derived_secret, b"UKEY2 v1 next", &ukey_info, 32);
    let pin_code = crypto::pin_code_from_auth_key(&auth_key);

    let d2d_client_key = crypto::hkdf_sha256(&next_secret, &crypto::D2D_SALT, b"client", 32);
    let d2d_server_key = crypto::hkdf_sha256(&next_secret, &crypto::D2D_SALT, b"server", 32);
    let smsg_salt = crypto::secure_message_salt();

    let client_aes = crypto::hkdf_sha256(&d2d_client_key, &smsg_salt, b"ENC:2", 32);
    let client_hmac = crypto::hkdf_sha256(&d2d_client_key, &smsg_salt, b"SIG:1", 32);
    let server_aes = crypto::hkdf_sha256(&d2d_server_key, &smsg_salt, b"ENC:2", 32);
    let server_hmac = crypto::hkdf_sha256(&d2d_server_key, &smsg_salt, b"SIG:1", 32);

    let into_32 = |v: Vec<u8>| -> [u8; 32] {
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    };

    // Client rolü: encrypt/send = client_*, decrypt/recv = server_*  (server rolün tersi)
    Ok(DerivedKeys {
        encrypt_key: into_32(client_aes),
        send_hmac_key: into_32(client_hmac),
        decrypt_key: into_32(server_aes),
        recv_hmac_key: into_32(server_hmac),
        auth_key: into_32(auth_key),
        pin_code,
    })
}

fn normalize_32(v: Vec<u8>) -> Vec<u8> {
    if v.len() > 32 {
        v[v.len() - 32..].to_vec()
    } else if v.len() < 32 {
        let mut p = vec![0u8; 32 - v.len()];
        p.extend_from_slice(&v);
        p
    } else {
        v
    }
}

/// Java `BigInteger.toByteArray()` ile uyumlu: MSB ≥ 0x80 ise başına 0x00 ekler.
/// Aksi halde peer Java tarafında değeri negatif yorumlar ve ServerInit'i reddeder.
fn to_signed_bytes(v: &[u8]) -> Vec<u8> {
    if !v.is_empty() && v[0] >= 0x80 {
        let mut out = Vec::with_capacity(v.len() + 1);
        out.push(0x00);
        out.extend_from_slice(v);
        out
    } else {
        v.to_vec()
    }
}

pub struct ServerInitResult {
    pub server_init_bytes: Vec<u8>,
    pub secret_key: SecretKey,
    pub cipher_commitment: Vec<u8>,
    pub client_init_bytes: Vec<u8>,
}

/// `Ukey2ClientInit` mesajını doğrular, `Ukey2ServerInit` üretir ve handshake state'i döner.
pub fn process_client_init(client_init_frame: &[u8]) -> Result<ServerInitResult> {
    let msg = Ukey2Message::decode(client_init_frame)?;
    let message_type = msg.message_type.ok_or_else(|| anyhow!("mesaj tipi yok"))?;
    let message_data = msg
        .message_data
        .ok_or_else(|| anyhow!("mesaj verisi yok"))?;

    // 2 = CLIENT_INIT
    if message_type != 2 {
        bail!("beklenen CLIENT_INIT, alınan {}", message_type);
    }

    let ci = Ukey2ClientInit::decode(&message_data[..])?;
    if ci.version() != 1 {
        bail!("UKEY2 sürümü desteklenmiyor: {}", ci.version());
    }
    if ci.random().len() != 32 {
        bail!("random alanı 32 byte olmalı, {} geldi", ci.random().len());
    }
    let next_protocol = ci.next_protocol();
    if next_protocol != "AES_256_CBC-HMAC_SHA256" {
        bail!("desteklenmeyen next_protocol: {}", next_protocol);
    }

    tracing::debug!(
        "ClientInit: version={}, random={} bayt, {} commitment, next_protocol={}",
        ci.version(),
        ci.random().len(),
        ci.cipher_commitments.len(),
        next_protocol
    );
    for (idx, c) in ci.cipher_commitments.iter().enumerate() {
        tracing::debug!(
            "  commitment[{}]: cipher={:?}, len={}",
            idx,
            c.handshake_cipher,
            c.commitment.as_ref().map(|v| v.len()).unwrap_or(0)
        );
    }

    let commitment = ci
        .cipher_commitments
        .iter()
        .find(|c| c.handshake_cipher == Some(Ukey2HandshakeCipher::P256Sha512 as i32))
        .ok_or_else(|| anyhow!("P256_SHA512 cipher commitment yok"))?
        .commitment
        .clone()
        .ok_or_else(|| anyhow!("commitment boş"))?;

    // P-256 anahtar çifti üret
    let secret_key = SecretKey::random(&mut OsRng);
    let public_key = secret_key.public_key();
    let encoded = public_key.to_encoded_point(false); // uncompressed: 04 || X(32) || Y(32)
    let xy = encoded.as_bytes();
    // Java BigInteger-uyumlu: MSB >= 0x80 ise başa 0x00 ekle (signed representation).
    // Android tarafı Java BigInteger ile parse ettiği için zorunlu.
    let x = to_signed_bytes(&xy[1..33]);
    let y = to_signed_bytes(&xy[33..65]);

    let generic_pk = GenericPublicKey {
        r#type: PublicKeyType::EcP256 as i32,
        ec_p256_public_key: Some(EcP256PublicKey { x, y }),
        ..Default::default()
    };
    let generic_pk_bytes = generic_pk.encode_to_vec();

    let mut random = [0u8; 32];
    use rand::RngCore;
    OsRng.fill_bytes(&mut random);

    let server_init = Ukey2ServerInit {
        version: Some(1),
        random: Some(random.to_vec()),
        handshake_cipher: Some(Ukey2HandshakeCipher::P256Sha512 as i32),
        public_key: Some(generic_pk_bytes),
    };

    let server_init_msg = Ukey2Message {
        message_type: Some(3), // SERVER_INIT
        message_data: Some(server_init.encode_to_vec()),
    };
    let server_init_bytes = server_init_msg.encode_to_vec();

    Ok(ServerInitResult {
        server_init_bytes,
        secret_key,
        cipher_commitment: commitment,
        client_init_bytes: client_init_frame.to_vec(),
    })
}

/// İstemciden gelen `Ukey2ClientFinished`'i doğrular, ECDH + HKDF ile anahtarları türetir.
pub fn process_client_finish(raw_frame: &[u8], state: &ServerInitResult) -> Result<DerivedKeys> {
    // Önce mesaj tipini kontrol et (peer Alert gönderdiyse anlamsız bir byte dizisi
    // ClientFinished sanılmasın)
    let peek = Ukey2Message::decode(raw_frame).ok();
    let peek_type = peek.as_ref().and_then(|m| m.message_type);
    tracing::debug!(
        "ClientFinished candidate: {} bayt, message_type={:?}, ilk 16 bayt=[{}]",
        raw_frame.len(),
        peek_type,
        hex::encode(&raw_frame[..raw_frame.len().min(16)])
    );

    // Commitment doğrulama: SHA512(raw Ukey2Message bytes) == cipher_commitment
    use sha2::{Digest, Sha512};
    let mut sha = Sha512::new();
    sha.update(raw_frame);
    let digest = sha.finalize();
    if digest.as_slice() != state.cipher_commitment.as_slice() {
        tracing::debug!(
            "commitment mismatch: beklenen={}, hesaplanan={}",
            hex::encode(&state.cipher_commitment),
            hex::encode(digest.as_slice())
        );
        bail!("cipher commitment uyuşmadı");
    }

    let msg = Ukey2Message::decode(raw_frame)?;
    let message_type = msg.message_type.ok_or_else(|| anyhow!("mesaj tipi yok"))?;
    let message_data = msg
        .message_data
        .ok_or_else(|| anyhow!("mesaj verisi yok"))?;
    if message_type != 4 {
        bail!("beklenen CLIENT_FINISH, alınan {}", message_type);
    }

    let cf = Ukey2ClientFinished::decode(&message_data[..])?;
    let peer_generic_pk_bytes = cf.public_key.ok_or_else(|| anyhow!("publicKey yok"))?;
    let peer_generic = GenericPublicKey::decode(&peer_generic_pk_bytes[..])?;
    let peer_ec = peer_generic
        .ec_p256_public_key
        .ok_or_else(|| anyhow!("ecP256PublicKey yok"))?;

    let mut peer_x = peer_ec.x;
    let mut peer_y = peer_ec.y;
    // Android tarafı bazen 33 bayt (işaret biti 0x00 prefix) gönderir → son 32'yi al.
    if peer_x.len() > 32 {
        peer_x = peer_x[peer_x.len() - 32..].to_vec();
    } else if peer_x.len() < 32 {
        let mut p = vec![0u8; 32 - peer_x.len()];
        p.extend_from_slice(&peer_x);
        peer_x = p;
    }
    if peer_y.len() > 32 {
        peer_y = peer_y[peer_y.len() - 32..].to_vec();
    } else if peer_y.len() < 32 {
        let mut p = vec![0u8; 32 - peer_y.len()];
        p.extend_from_slice(&peer_y);
        peer_y = p;
    }

    let mut uncompressed = vec![0x04u8];
    uncompressed.extend_from_slice(&peer_x);
    uncompressed.extend_from_slice(&peer_y);
    let encoded =
        EncodedPoint::from_bytes(&uncompressed).map_err(|e| anyhow!("peer pubkey parse: {}", e))?;
    let peer_pk = PublicKey::from_encoded_point(&encoded);
    let peer_pk = Option::<PublicKey>::from(peer_pk)
        .ok_or_else(|| anyhow!("peer pubkey geçersiz eğri noktası"))?;

    let shared = diffie_hellman(state.secret_key.to_nonzero_scalar(), peer_pk.as_affine());
    let dhs_x = shared.raw_secret_bytes().to_vec();
    let derived_secret = crypto::sha256(&dhs_x);

    // ukey_info = clientInit || serverInit (TAM çerçeveler, yani Ukey2Message'ın serialize edilmiş hali)
    let mut ukey_info =
        Vec::with_capacity(state.client_init_bytes.len() + state.server_init_bytes.len());
    ukey_info.extend_from_slice(&state.client_init_bytes);
    ukey_info.extend_from_slice(&state.server_init_bytes);

    let auth_key = crypto::hkdf_sha256(&derived_secret, b"UKEY2 v1 auth", &ukey_info, 32);
    let next_secret = crypto::hkdf_sha256(&derived_secret, b"UKEY2 v1 next", &ukey_info, 32);
    let pin_code = crypto::pin_code_from_auth_key(&auth_key);

    let d2d_client_key = crypto::hkdf_sha256(&next_secret, &crypto::D2D_SALT, b"client", 32);
    let d2d_server_key = crypto::hkdf_sha256(&next_secret, &crypto::D2D_SALT, b"server", 32);

    let smsg_salt = crypto::secure_message_salt();

    let client_aes = crypto::hkdf_sha256(&d2d_client_key, &smsg_salt, b"ENC:2", 32);
    let client_hmac = crypto::hkdf_sha256(&d2d_client_key, &smsg_salt, b"SIG:1", 32);
    let server_aes = crypto::hkdf_sha256(&d2d_server_key, &smsg_salt, b"ENC:2", 32);
    let server_hmac = crypto::hkdf_sha256(&d2d_server_key, &smsg_salt, b"SIG:1", 32);

    let into_32 = |v: Vec<u8>| -> [u8; 32] {
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    };

    Ok(DerivedKeys {
        decrypt_key: into_32(client_aes),
        recv_hmac_key: into_32(client_hmac),
        encrypt_key: into_32(server_aes),
        send_hmac_key: into_32(server_hmac),
        auth_key: into_32(auth_key),
        pin_code,
    })
}

#[cfg(test)]
mod tests {
    use super::to_signed_bytes;

    #[test]
    fn signed_bytes_msb_yuksekken_00_eklenir() {
        let v = [0x80, 0xAB, 0xCD];
        assert_eq!(to_signed_bytes(&v), vec![0x00, 0x80, 0xAB, 0xCD]);
    }

    #[test]
    fn signed_bytes_msb_dusukken_degismez() {
        let v = [0x7F, 0xAB, 0xCD];
        assert_eq!(to_signed_bytes(&v), vec![0x7F, 0xAB, 0xCD]);
    }

    #[test]
    fn signed_bytes_bos_slice_bos_donmeli() {
        let v: [u8; 0] = [];
        assert!(to_signed_bytes(&v).is_empty());
    }

    #[test]
    fn signed_bytes_tam_sinir() {
        // 0x80 sınır değer — pozitif görünmesi için 0x00 eklenmeli
        assert_eq!(to_signed_bytes(&[0x80]), vec![0x00, 0x80]);
        // 0x7F en yüksek pozitif — dokunulmaz
        assert_eq!(to_signed_bytes(&[0x7F]), vec![0x7F]);
    }
}

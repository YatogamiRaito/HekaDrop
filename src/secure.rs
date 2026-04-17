//! Secure message katmanı — UKEY2 sonrası tüm trafik bu sarmalayıcıdan geçer.
//!
//! Akış (outbound):
//!   plaintext (OfflineFrame veya NearbyFrame bytes)
//!     → DeviceToDeviceMessage{ seq, message=plaintext }
//!     → AES-256-CBC-PKCS7(encrypt_key, random_iv, d2d_bytes)
//!     → HeaderAndBody{ header{iv, schemes, meta}, body=ciphertext }
//!     → SecureMessage{ header_and_body, signature=HMAC-SHA256(send_hmac, hb) }
//!
//! Inbound aynı sırayla tersine.

use crate::crypto;
use crate::securegcm::{DeviceToDeviceMessage, GcmMetadata, Type as GcmType};
use crate::securemessage::{
    EncScheme, Header, HeaderAndBody, SecureMessage, SigScheme,
};
use anyhow::{anyhow, bail, Result};
use prost::Message;
use rand::RngCore;

pub struct SecureCtx {
    pub encrypt_key: [u8; 32],
    pub decrypt_key: [u8; 32],
    pub send_hmac_key: [u8; 32],
    pub recv_hmac_key: [u8; 32],
    pub server_seq: i32,
    pub client_seq: i32,
}

impl SecureCtx {
    pub fn from_keys(keys: &crate::ukey2::DerivedKeys) -> Self {
        Self {
            encrypt_key: keys.encrypt_key,
            decrypt_key: keys.decrypt_key,
            send_hmac_key: keys.send_hmac_key,
            recv_hmac_key: keys.recv_hmac_key,
            server_seq: 0,
            client_seq: 0,
        }
    }

    pub fn encrypt(&mut self, inner_plaintext: &[u8]) -> Vec<u8> {
        self.server_seq += 1;
        let d2d = DeviceToDeviceMessage {
            sequence_number: Some(self.server_seq),
            message: Some(inner_plaintext.to_vec()),
        };
        let d2d_bytes = d2d.encode_to_vec();

        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);
        let ciphertext = crypto::aes256_cbc_encrypt(&self.encrypt_key, &iv, &d2d_bytes);

        let gcm_meta = GcmMetadata {
            r#type: GcmType::DeviceToDeviceMessage as i32,
            version: Some(1),
        };
        let header = Header {
            encryption_scheme: EncScheme::Aes256Cbc as i32,
            signature_scheme: SigScheme::HmacSha256 as i32,
            iv: Some(iv.to_vec()),
            public_metadata: Some(gcm_meta.encode_to_vec()),
            ..Default::default()
        };
        let hb = HeaderAndBody {
            header,
            body: ciphertext,
        };
        let hb_bytes = hb.encode_to_vec();

        let sig = crypto::hmac_sha256(&self.send_hmac_key, &hb_bytes);
        let smsg = SecureMessage {
            header_and_body: hb_bytes,
            signature: sig.to_vec(),
        };
        smsg.encode_to_vec()
    }

    #[cfg(test)]
    pub fn new_with_keys(
        encrypt_key: [u8; 32],
        decrypt_key: [u8; 32],
        send_hmac_key: [u8; 32],
        recv_hmac_key: [u8; 32],
    ) -> Self {
        Self {
            encrypt_key,
            decrypt_key,
            send_hmac_key,
            recv_hmac_key,
            server_seq: 0,
            client_seq: 0,
        }
    }

    pub fn decrypt(&mut self, frame_bytes: &[u8]) -> Result<Vec<u8>> {
        let smsg = SecureMessage::decode(frame_bytes)?;
        if !crypto::hmac_sha256_verify(
            &self.recv_hmac_key,
            &smsg.header_and_body,
            &smsg.signature,
        ) {
            bail!("HMAC eşleşmedi");
        }
        let hb = HeaderAndBody::decode(&smsg.header_and_body[..])?;
        let iv_vec = hb.header.iv.ok_or_else(|| anyhow!("IV yok"))?;
        if iv_vec.len() != 16 {
            bail!("IV boyu 16 olmalı, {}", iv_vec.len());
        }
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&iv_vec);

        let plaintext = crypto::aes256_cbc_decrypt(&self.decrypt_key, &iv, &hb.body)
            .map_err(|e| anyhow!("AES decrypt: {:?}", e))?;

        let d2d = DeviceToDeviceMessage::decode(&plaintext[..])?;
        let seq = d2d.sequence_number.ok_or_else(|| anyhow!("sequence yok"))?;
        let expected = self.client_seq + 1;
        if seq != expected {
            // State'i bozma — başarısız decrypt sonrası counter artmamalı,
            // aksi halde sıralı bir retry'ı bir daha reddederdik.
            bail!(
                "sıra numarası uyuşmadı: beklenen {}, alınan {}",
                expected,
                seq
            );
        }
        self.client_seq = expected;
        d2d.message.ok_or_else(|| anyhow!("D2D.message yok"))
    }
}

#[cfg(test)]
mod tests {
    use super::SecureCtx;

    fn make_pair() -> (SecureCtx, SecureCtx) {
        // İki yönlü kurulum: A → B ve B → A simülasyonu.
        let k_a_enc = [11u8; 32];
        let k_a_sig = [22u8; 32];
        let k_b_enc = [33u8; 32];
        let k_b_sig = [44u8; 32];
        // A'nın enc/sig anahtarları, B'nin dec/recv anahtarları ile eşleşir.
        let a = SecureCtx::new_with_keys(k_a_enc, k_b_enc, k_a_sig, k_b_sig);
        let b = SecureCtx::new_with_keys(k_b_enc, k_a_enc, k_b_sig, k_a_sig);
        (a, b)
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (mut a, mut b) = make_pair();
        let plaintext = b"merhaba dunya! gizli mesaj".to_vec();
        let encrypted = a.encrypt(&plaintext);
        let decrypted = b.decrypt(&encrypted).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn sequence_number_artar() {
        let (mut a, mut b) = make_pair();
        for i in 1..=5 {
            let msg = format!("mesaj {}", i);
            let enc = a.encrypt(msg.as_bytes());
            let dec = b.decrypt(&enc).expect("decrypt");
            assert_eq!(dec, msg.as_bytes());
        }
        assert_eq!(a.server_seq, 5);
        assert_eq!(b.client_seq, 5);
    }

    #[test]
    fn yanlis_sira_reddedilir() {
        let (mut a, mut b) = make_pair();
        let e1 = a.encrypt(b"first");
        let e2 = a.encrypt(b"second");
        // İkinciyi önce decode etmeye çalış → sequence uyumsuzluğu
        assert!(b.decrypt(&e2).is_err());
        // Birinciyi yine alabiliriz (client_seq = 0 hâlâ → 1 bekler)
        assert!(b.decrypt(&e1).is_ok());
    }

    #[test]
    fn bozulmus_hmac_reddedilir() {
        let (mut a, mut b) = make_pair();
        let mut enc = a.encrypt(b"secret");
        // Son baytı bozup HMAC doğrulamasını patlat
        let last = enc.len() - 1;
        enc[last] ^= 0xFF;
        assert!(b.decrypt(&enc).is_err());
    }
}

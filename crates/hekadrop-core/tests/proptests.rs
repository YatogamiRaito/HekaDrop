#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::redundant_clone,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::cast_abs_to_unsigned,
    clippy::ignored_unit_patterns
)]

use hekadrop_core::chunk_hmac::{compute_tag, derive_chunk_hmac_key, verify_tag};
use hekadrop_core::crypto::{aes256_cbc_decrypt, aes256_cbc_encrypt};
use hekadrop_core::secure::SecureCtx;
use hekadrop_core::state::RateLimiter;
use hekadrop_proto::hekadrop_ext::ChunkIntegrity;
use proptest::prelude::*;
use std::net::{IpAddr, Ipv4Addr};

proptest! {
    /// 1. Chunk HMAC Sign & Verify Roundtrip Testi
    /// Herhangi geçerli girdi ile üretilen tag, her zaman başarıyla doğrulanmalıdır.
    #[test]
    fn test_chunk_hmac_roundtrip(
        key_seed in prop::collection::vec(any::<u8>(), 32),
        payload_id in any::<i64>(),
        chunk_index in any::<i64>(),
        offset in any::<i64>(),
        body in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_seed);

        let hmac_key = derive_chunk_hmac_key(&key);
        let tag = compute_tag(&hmac_key, payload_id, chunk_index, offset, &body).unwrap();

        let expected = ChunkIntegrity {
            payload_id,
            chunk_index,
            offset,
            body_len: body.len() as u32,
            tag: tag.to_vec().into(),
        };

        let result = verify_tag(&hmac_key, &expected, &body);
        prop_assert!(result.is_ok());
    }

    /// 2. Chunk HMAC Tahrifat (Tampering) Tespiti Testi
    /// Girdilerden herhangi birinde tahrifat yapıldığında doğrulama başarısız olmalıdır.
    #[test]
    fn test_chunk_hmac_tampering(
        key_seed in prop::collection::vec(any::<u8>(), 32),
        payload_id in any::<i64>(),
        chunk_index in any::<i64>(),
        offset in any::<i64>(),
        body in prop::collection::vec(any::<u8>(), 1..4096),
        tamper_op in 0..6, // Hangi alanda tahrifat yapılacağını belirler
        bit_mask in 1u8..255,
    ) {
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_seed);

        let hmac_key = derive_chunk_hmac_key(&key);
        let tag = compute_tag(&hmac_key, payload_id, chunk_index, offset, &body).unwrap();

        let mut expected = ChunkIntegrity {
            payload_id,
            chunk_index,
            offset,
            body_len: body.len() as u32,
            tag: tag.to_vec().into(),
        };

        let mut t_body = body.clone();
        let mut t_key = hmac_key;

        match tamper_op {
            0 => {
                // Payload ID tahrif et
                expected.payload_id ^= 1;
            }
            1 => {
                // Chunk Index tahrif et
                expected.chunk_index ^= 1;
            }
            2 => {
                // Offset tahrif et
                expected.offset ^= 1;
            }
            3 => {
                // Body Length tahrif et
                expected.body_len = expected.body_len.wrapping_add(1);
            }
            4 => {
                // Body içeriğini tahrif et
                let idx = (offset.abs() as usize) % t_body.len();
                t_body[idx] ^= bit_mask;
            }
            5 => {
                // Anahtarı tahrif et
                let idx = (offset.abs() as usize) % 32;
                t_key[idx] ^= bit_mask;
            }
            _ => unreachable!(),
        }

        let result = verify_tag(&t_key, &expected, &t_body);
        prop_assert!(result.is_err());
    }

    /// 3. AES-256-CBC Şifreleme/Çözme Roundtrip Testi
    #[test]
    fn test_aes256_cbc_roundtrip(
        key in prop::collection::vec(any::<u8>(), 32),
        iv in prop::collection::vec(any::<u8>(), 16),
        plaintext in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        let mut k = [0u8; 32];
        k.copy_from_slice(&key);
        let mut i = [0u8; 16];
        i.copy_from_slice(&iv);

        let ciphertext = aes256_cbc_encrypt(&k, &i, &plaintext);
        let decrypted = aes256_cbc_decrypt(&k, &i, &ciphertext);

        prop_assert!(decrypted.is_ok());
        prop_assert_eq!(decrypted.unwrap(), plaintext);
    }

    /// 4. SecureCtx Şifreleme/Çözme & Sıra (Sequence) Takip Testi
    #[test]
    fn test_secure_ctx_roundtrip(
        k_a_enc in prop::collection::vec(any::<u8>(), 32),
        k_a_sig in prop::collection::vec(any::<u8>(), 32),
        k_b_enc in prop::collection::vec(any::<u8>(), 32),
        k_b_sig in prop::collection::vec(any::<u8>(), 32),
        plaintext in prop::collection::vec(any::<u8>(), 1..2048),
        num_messages in 1i32..20i32,
    ) {
        let mut k_ae = [0u8; 32]; k_ae.copy_from_slice(&k_a_enc);
        let mut k_as = [0u8; 32]; k_as.copy_from_slice(&k_a_sig);
        let mut k_be = [0u8; 32]; k_be.copy_from_slice(&k_b_enc);
        let mut k_bs = [0u8; 32]; k_bs.copy_from_slice(&k_b_sig);

        // İki yönlü oturum bağlamı oluştur
        let mut alice = SecureCtx {
            encrypt_key: k_ae,
            decrypt_key: k_be,
            send_hmac_key: k_as,
            recv_hmac_key: k_bs,
            server_seq: 0,
            client_seq: 0,
        };
        let mut bob = SecureCtx {
            encrypt_key: k_be,
            decrypt_key: k_ae,
            send_hmac_key: k_bs,
            recv_hmac_key: k_as,
            server_seq: 0,
            client_seq: 0,
        };

        for i in 1i32..=num_messages {
            let mut pt = plaintext.clone();
            pt.extend_from_slice(&i.to_be_bytes()); // Mesajı benzersiz kıl

            let encrypted = alice.encrypt(&pt).unwrap();
            let decrypted = bob.decrypt(&encrypted).unwrap();

            prop_assert_eq!(decrypted.as_ref(), pt.as_slice());
            prop_assert_eq!(alice.server_seq, i);
            prop_assert_eq!(bob.client_seq, i);
        }
    }

    /// 5. SecureCtx Tahrifat Tespiti Testi
    #[test]
    fn test_secure_ctx_tampering(
        k_a_enc in prop::collection::vec(any::<u8>(), 32),
        k_a_sig in prop::collection::vec(any::<u8>(), 32),
        k_b_enc in prop::collection::vec(any::<u8>(), 32),
        k_b_sig in prop::collection::vec(any::<u8>(), 32),
        plaintext in prop::collection::vec(any::<u8>(), 1..2048),
        bit_mask in 1u8..255,
    ) {
        let mut k_ae = [0u8; 32]; k_ae.copy_from_slice(&k_a_enc);
        let mut k_as = [0u8; 32]; k_as.copy_from_slice(&k_a_sig);
        let mut k_be = [0u8; 32]; k_be.copy_from_slice(&k_b_enc);
        let mut k_bs = [0u8; 32]; k_bs.copy_from_slice(&k_b_sig);

        let mut alice = SecureCtx {
            encrypt_key: k_ae,
            decrypt_key: k_be,
            send_hmac_key: k_as,
            recv_hmac_key: k_bs,
            server_seq: 0,
            client_seq: 0,
        };
        let mut bob = SecureCtx {
            encrypt_key: k_be,
            decrypt_key: k_ae,
            send_hmac_key: k_bs,
            recv_hmac_key: k_as,
            server_seq: 0,
            client_seq: 0,
        };

        let mut encrypted = alice.encrypt(&plaintext).unwrap();

        // Şifreli verinin rastgele bir baytını tahrif et
        let idx = (bit_mask as usize) % encrypted.len();
        encrypted[idx] ^= bit_mask;

        let result = bob.decrypt(&encrypted);
        prop_assert!(result.is_err());
    }

    /// 6. Rate Limiter Sınır ve Davranış Testi
    #[test]
    fn test_rate_limiter_behavior(
        ip_octets in prop::collection::vec(any::<u8>(), 4),
        request_count in 1..30,
    ) {
        let ip = IpAddr::V4(Ipv4Addr::new(ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3]));
        let limiter = RateLimiter::new();

        for i in 1..=request_count {
            let is_blocked = limiter.check_and_record(ip);
            if i <= 10 {
                prop_assert!(!is_blocked, "İlk 10 istek bloke edilmemeli. İstek: {}", i);
            } else {
                prop_assert!(is_blocked, "10'dan sonraki istekler bloke edilmeli. İstek: {}", i);
            }
        }
    }

    /// 7. HekaDropFrame Capabilities Roundtrip Testi
    #[test]
    fn test_capabilities_frame_roundtrip(
        version in any::<u32>(),
        features in any::<u64>(),
    ) {
        use prost::Message;
        use hekadrop_proto::hekadrop_ext::heka_drop_frame::Payload;
        use hekadrop_proto::hekadrop_ext::{HekaDropFrame, Capabilities};

        let frame = HekaDropFrame {
            version: 1,
            payload: Some(Payload::Capabilities(Capabilities {
                version,
                features,
            })),
        };

        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();

        let decoded = HekaDropFrame::decode(&buf[..]).unwrap();
        prop_assert_eq!(decoded.version, 1);
        match decoded.payload {
            Some(Payload::Capabilities(caps)) => {
                prop_assert_eq!(caps.version, version);
                prop_assert_eq!(caps.features, features);
            }
            other => {
                panic!("Capabilities expected, got {other:?}");
            }
        }
    }

    /// 8. HekaDropFrame ResumeHint Roundtrip Testi
    #[test]
    fn test_resume_hint_frame_roundtrip(
        session_id in any::<i64>(),
        payload_id in any::<i64>(),
        offset in any::<i64>(),
        partial_hash in prop::collection::vec(any::<u8>(), 32),
        capabilities_version in any::<u32>(),
        last_chunk_tag in prop::collection::vec(any::<u8>(), 32),
    ) {
        use prost::Message;
        use hekadrop_proto::hekadrop_ext::heka_drop_frame::Payload;
        use hekadrop_proto::hekadrop_ext::{HekaDropFrame, ResumeHint};

        let frame = HekaDropFrame {
            version: 1,
            payload: Some(Payload::ResumeHint(ResumeHint {
                session_id,
                payload_id,
                offset,
                partial_hash: partial_hash.clone().into(),
                capabilities_version,
                last_chunk_tag: last_chunk_tag.clone().into(),
            })),
        };

        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();

        let decoded = HekaDropFrame::decode(&buf[..]).unwrap();
        prop_assert_eq!(decoded.version, 1);
        match decoded.payload {
            Some(Payload::ResumeHint(hint)) => {
                prop_assert_eq!(hint.session_id, session_id);
                prop_assert_eq!(hint.payload_id, payload_id);
                prop_assert_eq!(hint.offset, offset);
                prop_assert_eq!(hint.partial_hash.as_ref(), partial_hash.as_slice());
                prop_assert_eq!(hint.capabilities_version, capabilities_version);
                prop_assert_eq!(hint.last_chunk_tag.as_ref(), last_chunk_tag.as_slice());
            }
            other => {
                panic!("ResumeHint expected, got {other:?}");
            }
        }
    }

    /// 9. HekaDropFrame ResumeReject Roundtrip Testi
    #[test]
    fn test_resume_reject_frame_roundtrip(
        payload_id in any::<i64>(),
        reason in 0i32..6i32,
    ) {
        use prost::Message;
        use hekadrop_proto::hekadrop_ext::heka_drop_frame::Payload;
        use hekadrop_proto::hekadrop_ext::{HekaDropFrame, ResumeReject};

        let frame = HekaDropFrame {
            version: 1,
            payload: Some(Payload::ResumeReject(ResumeReject {
                payload_id,
                reason,
            })),
        };

        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();

        let decoded = HekaDropFrame::decode(&buf[..]).unwrap();
        prop_assert_eq!(decoded.version, 1);
        match decoded.payload {
            Some(Payload::ResumeReject(reject)) => {
                prop_assert_eq!(reject.payload_id, payload_id);
                prop_assert_eq!(reject.reason, reason);
            }
            other => {
                panic!("ResumeReject expected, got {other:?}");
            }
        }
    }

    /// 10. HekaDropFrame FolderManifest Roundtrip Testi
    #[test]
    fn test_folder_manifest_frame_roundtrip(
        version in any::<u32>(),
    ) {
        use prost::Message;
        use hekadrop_proto::hekadrop_ext::heka_drop_frame::Payload;
        use hekadrop_proto::hekadrop_ext::{HekaDropFrame, FolderManifest};

        let frame = HekaDropFrame {
            version,
            payload: Some(Payload::FolderMft(FolderManifest {})),
        };

        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();

        let decoded = HekaDropFrame::decode(&buf[..]).unwrap();
        prop_assert_eq!(decoded.version, version);
        match decoded.payload {
            Some(Payload::FolderMft(FolderManifest {})) => {}
            other => {
                panic!("FolderMft expected, got {other:?}");
            }
        }
    }

    /// 11. Frame Wrap and Dispatch Roundtrip Testi
    #[test]
    fn test_wrap_and_dispatch_roundtrip(
        protobuf_bytes in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        use hekadrop_core::frame::{dispatch_frame_body, wrap_hekadrop_frame, FrameKind};

        let wrapped = wrap_hekadrop_frame(&protobuf_bytes);
        match dispatch_frame_body(&wrapped) {
            FrameKind::HekaDrop { inner } => {
                prop_assert_eq!(inner, protobuf_bytes.as_slice());
            }
            FrameKind::Offline { .. } => {
                panic!("HekaDrop FrameKind expected");
            }
        }
    }

    /// 12. Arbitrary Frame Dispatch Behavior Test
    #[test]
    fn test_arbitrary_dispatch_behavior(
        bytes in prop::collection::vec(any::<u8>(), 0..1024),
    ) {
        use hekadrop_core::frame::{dispatch_frame_body, FrameKind, HEKADROP_MAGIC_BE};

        let has_magic = bytes.len() >= 4 && bytes[..4] == HEKADROP_MAGIC_BE;
        match dispatch_frame_body(&bytes) {
            FrameKind::HekaDrop { inner } => {
                prop_assert!(has_magic);
                prop_assert_eq!(inner, &bytes[4..]);
            }
            FrameKind::Offline { body } => {
                prop_assert!(!has_magic);
                prop_assert_eq!(body, bytes.as_slice());
            }
        }
    }

    /// 13. UKEY2 validate_server_init Testi
    #[test]
    fn test_validate_server_init(
        handshake_cipher in any::<Option<i32>>(),
        version in any::<Option<i32>>(),
    ) {
        use hekadrop_proto::securegcm::{Ukey2ServerInit, Ukey2HandshakeCipher};
        use hekadrop_core::ukey2::validate_server_init;

        let s = Ukey2ServerInit {
            version,
            random: None,
            handshake_cipher,
            public_key: None,
        };

        let result = validate_server_init(&s);
        let expected_ok = handshake_cipher == Some(Ukey2HandshakeCipher::P256Sha512 as i32) && version == Some(1);
        prop_assert_eq!(result.is_ok(), expected_ok);
    }

    /// 14. Payload Reassembly Roundtrip Testi
    #[test]
    fn test_payload_reassembly_roundtrip(
        id in any::<i64>(),
        data in prop::collection::vec(any::<u8>(), 1..65536),
        chunk_sizes in prop::collection::vec(1..4096usize, 1..32),
    ) {
        use hekadrop_core::payload::{PayloadAssembler, CompletedPayload};
        use hekadrop_proto::location::nearby::connections::payload_transfer_frame::{
            PayloadChunk, PayloadHeader,
        };
        use hekadrop_proto::location::nearby::connections::PayloadTransferFrame;
        use hekadrop_proto::location::nearby::connections::payload_transfer_frame::payload_header::PayloadType;

        let mut assembler = PayloadAssembler::new();
        let mut offset = 0;
        let total_size = data.len();

        let mut chunks = Vec::new();
        let mut size_iter = chunk_sizes.iter().cycle();

        while offset < total_size {
            let chunk_size = *size_iter.next().unwrap();
            let end = (offset + chunk_size).min(total_size);
            chunks.push(&data[offset..end]);
            offset = end;
        }

        let num_chunks = chunks.len();
        for (idx, chunk_data) in chunks.iter().enumerate() {
            let last = idx == num_chunks - 1;

            let frame = PayloadTransferFrame {
                packet_type: None,
                payload_header: Some(PayloadHeader {
                    id: Some(id),
                    r#type: Some(PayloadType::Bytes as i32),
                    total_size: Some(total_size as i64),
                    is_sensitive: None,
                    file_name: None,
                    parent_folder: None,
                    last_modified_timestamp_millis: None,
                }),
                payload_chunk: Some(PayloadChunk {
                    flags: Some(i32::from(last)),
                    offset: Some(0),
                    body: Some(chunk_data.to_vec().into()),
                    index: None,
                }),
                control_message: None,
            };

            let result = assembler.ingest(&frame);
            prop_assert!(result.is_ok());
            let completed = result.unwrap();

            if last {
                prop_assert!(completed.is_some());
                match completed.unwrap() {
                    CompletedPayload::Bytes { id: completed_id, data: completed_data } => {
                        prop_assert_eq!(completed_id, id);
                        prop_assert_eq!(&completed_data, &data);
                    }
                    CompletedPayload::File { .. } => {
                        panic!("CompletedPayload::File expected, got File");
                    }
                }
            } else {
                prop_assert!(completed.is_none());
            }
        }
    }
}

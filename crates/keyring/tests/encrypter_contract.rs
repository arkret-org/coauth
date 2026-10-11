use base64ct::{Base64, Encoding};
use coauth_keyring::{DecryptError, Encrypter};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/encrypted_secrets.json")).unwrap()
}

#[test]
fn fixed_legacy_ciphertexts_and_frames_remain_exact() {
    let encrypter = Encrypter::new(&[0x42; 32]);
    for case in fixture()["cases"].as_array().unwrap() {
        let plaintext = case["plaintext"].as_str().unwrap().as_bytes();
        let ciphertext = encrypter.encrypt(&[7; 12], plaintext).unwrap();
        assert_eq!(
            Base64::encode_string(&ciphertext),
            case["ciphertext_base64"]
        );
        assert_eq!(
            Base64::encode_string(&[&[7; 12][..], &ciphertext].concat()),
            case["frame_base64"]
        );
        assert_eq!(
            encrypter
                .decrypt_string(case["frame_base64"].as_str().unwrap())
                .unwrap(),
            plaintext
        );
    }
}

#[test]
fn new_writes_round_trip_empty_binary_and_long_payloads() {
    let encrypter = Encrypter::new(&[0x42; 32]);
    for plaintext in [Vec::new(), (0..=255).collect(), vec![0x81; 65536]] {
        let first = encrypter.encrypt_to_string(&plaintext).unwrap();
        let second = encrypter.encrypt_to_string(&plaintext).unwrap();
        let raw = Base64::decode_vec(&first).unwrap();
        assert_eq!(raw.len(), 12 + plaintext.len() + 16);
        assert_ne!(first, second);
        assert_eq!(encrypter.decrypt_string(&first).unwrap(), plaintext);
        assert_eq!(encrypter.decrypt_string(&second).unwrap(), plaintext);
    }
}

#[test]
fn wrong_keys_nonces_tampering_and_truncation_fail_closed() {
    let encrypter = Encrypter::new(&[0x42; 32]);
    let fixture = fixture();
    let frame = fixture["cases"][0]["frame_base64"].as_str().unwrap();
    let bytes = Base64::decode_vec(frame).unwrap();
    assert!(Encrypter::new(&[0x43; 32]).decrypt_string(frame).is_err());
    assert!(encrypter.decrypt(&[8; 12], &bytes[12..]).is_err());
    for position in 0..bytes.len() {
        let mut altered = bytes.clone();
        altered[position] ^= 1;
        assert!(
            encrypter
                .decrypt_string(&Base64::encode_string(&altered))
                .is_err(),
            "accepted altered byte {position}"
        );
    }
    for length in 0..bytes.len() {
        assert!(
            encrypter
                .decrypt_string(&Base64::encode_string(&bytes[..length]))
                .is_err(),
            "accepted truncated frame {length}"
        );
    }
    assert!(matches!(
        encrypter.decrypt_string("!not-base64"),
        Err(DecryptError::Base64(_))
    ));
    assert!(matches!(
        encrypter.decrypt_string(""),
        Err(DecryptError::Shape)
    ));
}

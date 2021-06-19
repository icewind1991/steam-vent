use aes::cipher::generic_array::GenericArray;
use aes::{Aes256, BlockDecrypt, BlockEncrypt, NewBlockCipher};
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use hmac::{Hmac, Mac, NewMac};
use once_cell::sync::Lazy;
use rand::{random, Rng};
use rsa::{padding::PaddingScheme, PublicKey, RSAPublicKey};
use sha1::Sha1;
use std::convert::TryInto;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptError {
    #[error("Malformed signature: {0}")]
    MalformedSignature(RSAError),
    #[error("Malformed message")]
    MalformedMessage,
    #[error("Invalid HMAC")]
    InvalidHmac,
}

pub type Result<T> = std::result::Result<T, CryptError>;

#[derive(Debug, Error)]
#[error("{0}")]
pub struct RSAError(rsa::errors::Error);

const SYSTEM_PUBLIC_KEY_BYTES: &str = include_str!("../system.pem");

static SYSTEM_PUBLIC_KEY: Lazy<RSAPublicKey> = Lazy::new(|| {
    let der_encoded = SYSTEM_PUBLIC_KEY_BYTES
        .split('\n')
        .filter(|line| !line.starts_with("-"))
        .fold(String::new(), |mut data, line| {
            data.push_str(line);
            data
        });
    let der_bytes = base64::decode(&der_encoded).expect("failed to decode base64 content");
    RSAPublicKey::from_pkcs8(&der_bytes).expect("Failed to parse public key")
});

/// Verify sha1 signature using the steam "system" public key
pub fn verify_signature(data: &[u8], signature: &[u8]) -> Result<bool> {
    match SYSTEM_PUBLIC_KEY.verify(PaddingScheme::new_oaep::<Sha1>(), data, signature) {
        Ok(_) => Ok(true),
        Err(rsa::errors::Error::Verification) => Ok(false),
        Err(err) => Err(CryptError::MalformedSignature(RSAError(err))),
    }
}

pub struct SessionKeys {
    pub plain: [u8; 32],
    pub encrypted: Vec<u8>,
}

pub fn generate_session_key(nonce: Option<&[u8; 16]>) -> SessionKeys {
    let mut rng = rand::thread_rng();
    let plain: [u8; 32] = rng.gen();

    let encrypted = match nonce {
        Some(nonce) => {
            let mut data = [0; 48];
            data[0..32].copy_from_slice(&plain);
            data[32..48].copy_from_slice(nonce);
            SYSTEM_PUBLIC_KEY.encrypt(&mut rng, PaddingScheme::new_oaep::<Sha1>(), &data)
        }
        None => SYSTEM_PUBLIC_KEY.encrypt(&mut rng, PaddingScheme::new_oaep::<Sha1>(), &plain),
    }
    .expect("Invalid crypt setup");

    SessionKeys { plain, encrypted }
}

/// Decrypt an Initialization Vector with AES 256 ECB.
fn encrypt_iv(iv: [u8; 16], key: &[u8; 32]) -> [u8; 16] {
    let iv_crypter = Aes256::new(GenericArray::from_slice(key));
    let mut iv_block = GenericArray::from(iv);
    iv_crypter.encrypt_block(&mut iv_block);
    iv_block.into()
}

/// Encrypt an Initialization Vector with AES 256 ECB.
fn decrypt_iv(iv: [u8; 16], key: &[u8; 32]) -> [u8; 16] {
    let iv_crypter = Aes256::new(GenericArray::from_slice(key));
    let mut iv_block = GenericArray::from(iv);
    iv_crypter.decrypt_block(&mut iv_block);
    iv_block.into()
}

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

fn encrypt_message(mut message: Vec<u8>, key: &[u8; 32], plain_iv: &[u8; 16]) -> Result<Vec<u8>> {
    let cipher = Aes256Cbc::new_fix(
        GenericArray::from_slice(key),
        GenericArray::from_slice(plain_iv),
    );
    let length = message.len();
    message.resize(length + 16, 0);
    cipher
        .encrypt(&mut message, length)
        .map_err(|_| CryptError::MalformedMessage)?;

    while message.last() == Some(&0) {
        message.truncate(message.len() - 1);
    }

    Ok(message)
}

fn decrypt_message(mut message: Vec<u8>, key: &[u8; 32], plain_iv: &[u8; 16]) -> Result<Vec<u8>> {
    let cipher = Aes256Cbc::new_fix(
        GenericArray::from_slice(key),
        GenericArray::from_slice(plain_iv),
    );
    cipher
        .decrypt(&mut message)
        .map_err(|_| CryptError::MalformedMessage)?;
    Ok(message)
}

fn symmetric_encrypt_with_iv(
    message: Vec<u8>,
    key: &[u8; 32],
    plain_iv: [u8; 16],
) -> Result<Vec<u8>> {
    let encrypted_iv = encrypt_iv(plain_iv, key);
    let encrypted_message = encrypt_message(message, key, &plain_iv)?;

    let mut output = encrypted_iv.to_vec();
    output.extend(encrypted_message.into_iter());
    Ok(output)
}

type HmacSha1 = Hmac<Sha1>;

/// Generate a random IV and encrypt `input` with it and `key`.
pub fn symmetric_encrypt(input: Vec<u8>, key: &[u8; 32]) -> Result<Vec<u8>> {
    let hmac_random: [u8; 3] = random();

    let mut hmac_key = [0; 64];
    hmac_key[0..16].copy_from_slice(&key[0..16]);

    let mut hmac = HmacSha1::new(GenericArray::from_slice(&hmac_key));
    hmac.update(&hmac_random);
    hmac.update(&input);

    let hmac: [u8; 20] = hmac.finalize().into_bytes().into();

    let mut iv = [0; 16];
    iv[0..13].copy_from_slice(&hmac[0..13]);
    iv[13..].copy_from_slice(&hmac_random);

    symmetric_encrypt_with_iv(input, key, iv)
}

/// Decrypt the IV stored in the first 16 bytes of `input`
/// and use it to decrypt the remaining bytes.
pub fn symmetric_decrypt(input: Vec<u8>, key: &[u8; 32]) -> Result<Vec<u8>> {
    let encrypted_iv = input
        .get(0..16)
        .ok_or(CryptError::MalformedMessage)?
        .try_into()
        .unwrap();
    let plain_iv = decrypt_iv(encrypted_iv, key);

    let message = input[16..].to_vec();
    let mut message = decrypt_message(message, key, &plain_iv)?;
    let padding = *message.last().unwrap();
    message.resize(message.len() - padding as usize, 0);

    let hmac_random = &plain_iv[13..];

    let mut hmac_key = [0; 64];
    hmac_key[0..16].copy_from_slice(&key[0..16]);

    let mut hmac = HmacSha1::new(GenericArray::from_slice(&hmac_key));
    hmac.update(&hmac_random);
    hmac.update(&message);

    let hmac: [u8; 20] = hmac.finalize().into_bytes().into();

    if hmac[0..13] != plain_iv[0..13] {
        return Err(CryptError::InvalidHmac);
    }

    Ok(message)
}

#[test]
fn roundtrip_test() {
    let key = random();

    let input = vec![55; 16];

    let encrypted = symmetric_encrypt(input.clone(), &key).unwrap();

    let decrypted = symmetric_decrypt(encrypted, &key).unwrap();

    assert_eq!(input, decrypted);
}

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, KeyIvInit};
use aes::Aes256;
use bytes::BytesMut;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut};
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use rand::{random, Rng};
use rsa::{BigUint, Oaep, Pkcs1v15Encrypt, Pss, RsaPublicKey};
use sha1::Sha1;
use std::convert::TryInto;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptError {
    #[error("Malformed signature: {0}")]
    MalformedSignature(#[from] RsaError),
    #[error("Malformed message")]
    MalformedMessage,
    #[error("Invalid HMAC")]
    InvalidHmac,
}

pub type Result<T> = std::result::Result<T, CryptError>;

#[derive(Debug, Error)]
#[error("{0}")]
pub struct RsaError(rsa::errors::Error);

mod system_key {
    include!(concat!(env!("OUT_DIR"), "/system_key.rs"));
}

static SYSTEM_PUBLIC_KEY: Lazy<RsaPublicKey> = Lazy::new(|| {
    RsaPublicKey::new(
        BigUint::from_bytes_le(system_key::N),
        BigUint::from_bytes_le(system_key::E),
    )
    .expect("Failed to parse public key")
});

/// Verify sha1 signature using the steam "system" public key
pub fn verify_signature(data: &[u8], signature: &[u8]) -> Result<bool> {
    match SYSTEM_PUBLIC_KEY.verify(Pss::new::<Sha1>(), data, signature) {
        Ok(_) => Ok(true),
        Err(rsa::errors::Error::Verification) => Ok(false),
        Err(err) => Err(CryptError::MalformedSignature(RsaError(err))),
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
            encrypt_with_key(&SYSTEM_PUBLIC_KEY, &data)
        }
        None => encrypt_with_key(&SYSTEM_PUBLIC_KEY, &plain),
    }
    .expect("Invalid crypt setup");

    SessionKeys { plain, encrypted }
}

pub fn encrypt_with_key(key: &RsaPublicKey, data: &[u8]) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();
    Ok(key
        .encrypt(&mut rng, Oaep::new::<Sha1>(), data)
        .map_err(RsaError)?)
}

pub fn encrypt_with_key_pkcs1(key: &RsaPublicKey, data: &[u8]) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();
    Ok(key
        .encrypt(&mut rng, Pkcs1v15Encrypt, data)
        .map_err(RsaError)?)
}

#[test]
fn test_gen_session_key() {
    assert!(!generate_session_key(None).encrypted.is_empty());
    assert!(!generate_session_key(Some(&[
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    ]))
    .encrypted
    .is_empty(),);
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

#[test]
fn test_iv_encryption_round_trip() {
    let iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let key = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
        12, 13, 14, 15, 16,
    ];
    let encrypted = encrypt_iv(iv, &key);
    assert_eq!(iv, decrypt_iv(encrypted, &key));
}

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

fn encrypt_message(mut message: BytesMut, key: &[u8; 32], plain_iv: &[u8; 16]) -> BytesMut {
    let cipher = <Aes256CbcEnc as KeyIvInit>::new(
        GenericArray::from_slice(key),
        GenericArray::from_slice(plain_iv),
    );
    let length = message.len();
    message.resize(length + 16, 0);
    let len = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut message, length)
        .expect("not enough padding")
        .len();

    message.truncate(len);
    message
}

fn decrypt_message(mut message: BytesMut, key: &[u8; 32], plain_iv: &[u8; 16]) -> Result<BytesMut> {
    let cipher = Aes256CbcDec::new(
        GenericArray::from_slice(key),
        GenericArray::from_slice(plain_iv),
    );
    let len = cipher
        .decrypt_padded_mut::<Pkcs7>(message.as_mut())
        .map_err(|_| CryptError::MalformedMessage)?
        .len();
    message.truncate(len);
    Ok(message)
}

#[test]
fn test_encryption_round_trip() {
    let iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let key = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
        12, 13, 14, 15, 16,
    ];
    let msg = "some test message to encrypt";
    let plain = BytesMut::from(msg);
    let encrypted = encrypt_message(plain.clone(), &key, &iv);
    assert_eq!(plain, decrypt_message(encrypted, &key, &iv).unwrap());
}

fn symmetric_encrypt_with_iv(
    mut iv_buff: BytesMut,
    message: BytesMut,
    key: &[u8; 32],
    plain_iv: [u8; 16],
) -> BytesMut {
    let encrypted_iv = encrypt_iv(plain_iv, key);
    iv_buff[0..16].copy_from_slice(&encrypted_iv);
    let encrypted_message = encrypt_message(message, key, &plain_iv);

    iv_buff.unsplit(encrypted_message);
    iv_buff
}

type HmacSha1 = Hmac<Sha1>;

/// Generate a random IV and encrypt `input` with it and `key` with a buffer for storing the iv.
///
/// The `iv_buff` has to be 16 bytes large should come from a split slice in front of the input buffer
pub fn symmetric_encrypt_with_iv_buffer(
    iv_buff: BytesMut,
    input: BytesMut,
    key: &[u8; 32],
) -> BytesMut {
    let hmac_random: [u8; 3] = random();

    let mut hmac_key = [0; 64];
    hmac_key[0..16].copy_from_slice(&key[0..16]);

    let mut hmac = <HmacSha1 as Mac>::new(GenericArray::from_slice(&hmac_key));
    hmac.update(&hmac_random);
    hmac.update(&input);

    let hmac: [u8; 20] = hmac.finalize().into_bytes().into();

    let mut iv = [0; 16];
    iv[0..13].copy_from_slice(&hmac[0..13]);
    iv[13..].copy_from_slice(&hmac_random);

    symmetric_encrypt_with_iv(iv_buff, input, key, iv)
}

/// Generate a random IV and encrypt `input` with it and `key`.
pub fn symmetric_encrypt(input: BytesMut, key: &[u8; 32]) -> BytesMut {
    symmetric_encrypt_with_iv_buffer(BytesMut::from(&[0; 16][..]), input, key)
}

fn symmetric_decrypt_impl(mut input: BytesMut, key: &[u8; 32]) -> Result<([u8; 16], BytesMut)> {
    let message = input.split_off(16);
    let encrypted_iv = input.as_ref().try_into().unwrap();
    let plain_iv = decrypt_iv(encrypted_iv, key);

    let message = decrypt_message(message, key, &plain_iv)?;

    Ok((plain_iv, message))
}

/// Decrypt the IV stored in the first 16 bytes of `input`
/// and use it to decrypt the remaining bytes, skipping HMAC validation.
pub fn symmetric_decrypt_without_hmac(input: BytesMut, key: &[u8; 32]) -> Result<BytesMut> {
    let (_, message) = symmetric_decrypt_impl(input, key)?;
    Ok(message)
}

/// Decrypt the IV stored in the first 16 bytes of `input`
/// and use it to decrypt the remaining bytes.
pub fn symmetric_decrypt(input: BytesMut, key: &[u8; 32]) -> Result<BytesMut> {
    let (plain_iv, message) = symmetric_decrypt_impl(input, key)?;
    // let padding = *message.last().unwrap();
    // message.resize(message.len() - padding as usize, 0);

    let hmac_random = &plain_iv[13..];

    let mut hmac_key = [0; 64];
    hmac_key[0..16].copy_from_slice(&key[0..16]);

    let mut hmac = <HmacSha1 as Mac>::new(GenericArray::from_slice(&hmac_key));
    hmac.update(hmac_random);
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

    let input = BytesMut::from(&[55; 16][..]);

    let encrypted = symmetric_encrypt(input.clone(), &key);

    let decrypted = symmetric_decrypt(encrypted, &key).unwrap();

    assert_eq!(input, decrypted);
}

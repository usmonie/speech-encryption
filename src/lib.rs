pub mod models;

use aes::Aes256;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::cipher::generic_array::GenericArray;
use async_trait::async_trait;
use e521_curve::{generate_private_key, generate_public_key};
use e521_curve::e521::e521::{get_e521_point, Point};
use num_bigint::BigInt;
use speech_backend_common::ApiResult;
use speech_backend_common::domain::UseCase;
use crate::models::requests::{GenerateKeyPairRequest, GenerateSecretKeyRequest};
use crate::models::result::{GenerateKeyPairResult, GenerateSecretKeyResult};

pub fn generate_random_key(size: u64) -> Vec<u8> {
    (0..size).map(|_| { rand::random::<u8>() }).collect()
}

pub struct GenerateKeyPairUseCase {}

#[async_trait]
impl UseCase<GenerateKeyPairRequest, GenerateKeyPairResult> for GenerateKeyPairUseCase {
    async fn execute(&self, request: GenerateKeyPairRequest) -> ApiResult<GenerateKeyPairResult> {
        let (private_key, public_key) = GenerateKeyPairUseCase::create_public_key();

        let point = get_e521_point(request.x, request.y);
        let secret_key = GenerateKeyPairUseCase::create_secret_key(
            &private_key,
            &point,
        );

        ApiResult::Ok(GenerateKeyPairResult::from(public_key, secret_key))
    }
}

impl GenerateKeyPairUseCase {
    pub fn new() -> Self {
        Self {}
    }

    pub fn create_secret_key(private_key: &BigInt, public_key: &Point) -> Vec<u8> {
        let point = e521_curve::diffie_hellman(private_key, public_key);
        e521_curve::generate_secret_key(point)
    }

    pub fn create_public_key() -> (BigInt, Point) {
        let private_key: BigInt = generate_private_key();
        let public_key_point: Point = generate_public_key(&private_key);
        (private_key, public_key_point)
    }
}

pub struct GenerateSecretKeyUseCase {}

#[async_trait]
impl UseCase<GenerateSecretKeyRequest, GenerateSecretKeyResult> for GenerateSecretKeyUseCase {
    async fn execute(&self, request: GenerateSecretKeyRequest) -> ApiResult<GenerateSecretKeyResult> {
        let secret_key = GenerateKeyPairUseCase::create_secret_key(
            &request.private_key,
            &request.public_key,
        );

        ApiResult::Ok(GenerateSecretKeyResult::from(secret_key))
    }
}


impl GenerateSecretKeyUseCase {
    pub fn new() -> Self {
        Self {}
    }

    pub fn create_secret_key(private_key: &BigInt, public_key: &Point) -> Vec<u8> {
        let point = e521_curve::diffie_hellman(private_key, public_key);
        e521_curve::generate_secret_key(point)
    }
}

pub struct Aes256Cipher {
    aes: Aes256
}

impl Aes256Cipher {
    pub fn new(key: Vec<u8>) -> Self {
        Self { aes: Aes256::new_from_slice(key.as_slice()).unwrap() }
    }

    pub fn decrypt(&self, encrypted_data: Vec<u8>) -> Vec<u8> {
        let encrypted_data = &mut *encrypted_data.clone();
        let mut decrypted_data = GenericArray::from_mut_slice(encrypted_data);
        self.aes.decrypt_block(&mut decrypted_data);

        decrypted_data.to_vec()
    }

    pub fn encrypt(&self, data: Vec<u8>) -> Vec<u8> {
        let data = &mut *data.clone();
        let encrypted_data = GenericArray::from_mut_slice(data);
        self.aes.decrypt_block(encrypted_data);

        encrypted_data.to_vec()
    }
}

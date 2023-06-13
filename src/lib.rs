pub mod models;

use async_trait::async_trait;
use e521_curve::e521::Point;
use e521_curve::{generate_private_key, generate_public_key};
use num_bigint_dig::BigInt;
use speech_backend_common::ApiResult;
use speech_backend_common::domain::UseCase;
use crate::models::requests::GenerateKeyPairRequest;
use crate::models::result::GenerateKeyPairResult;

pub struct GenerateKeyPairUseCase {}

#[async_trait]
impl UseCase<GenerateKeyPairRequest, GenerateKeyPairResult> for GenerateKeyPairUseCase {
    async fn execute(&self, request: GenerateKeyPairRequest) -> ApiResult<GenerateKeyPairResult> {
        let (private_key, public_key) = self.create_public_key();

        let secret_key = self.create_secret_key(
            &private_key,
            &Point {
                x: request.x,
                y: request.y,
            },
        );

        ApiResult::Ok(GenerateKeyPairResult::from(public_key, secret_key))
    }
}

impl GenerateKeyPairUseCase {
    pub fn new() -> Self {
        Self {}
    }

    fn create_secret_key(&self, private_key: &BigInt, public_key: &Point) -> Vec<u8> {
        let point = e521_curve::diffie_hellman(private_key, public_key);
        e521_curve::generate_secret_key(point)
    }

    fn create_public_key(&self) -> (BigInt, Point) {
        let private_key: BigInt = generate_private_key();
        let public_key_point: Point = generate_public_key(&private_key);
        (private_key, public_key_point)
    }
}

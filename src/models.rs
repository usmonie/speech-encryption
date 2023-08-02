pub mod requests {
    use e521_curve::e521::e521::Point;
    use num_bigint::BigInt;

    pub struct GenerateKeyPairRequest {
        pub x: BigInt,
        pub y: BigInt,
    }

    pub struct GenerateSecretKeyRequest {
        pub public_key: Point,
        pub private_key: BigInt
    }
}

pub mod result {
    use e521_curve::e521::e521::Point;

    pub struct GenerateKeyPairResult {
        pub public_key: Point,
        pub secret_key: Vec<u8>,
    }

    pub struct GenerateSecretKeyResult {
        pub secret_key: Vec<u8>,
    }

    impl GenerateKeyPairResult {
        pub fn from(public_key: Point, secret_key: Vec<u8>) -> Self {
            Self {
                public_key,
                secret_key,
            }
        }
    }
    impl GenerateSecretKeyResult {
        pub fn from(secret_key: Vec<u8>) -> Self {
            Self { secret_key }
        }
    }
}
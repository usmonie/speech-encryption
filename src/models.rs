pub mod requests {
    use num_bigint_dig::BigInt;

    pub struct GenerateKeyPairRequest {
        pub x: BigInt,
        pub y: BigInt,
    }
}

pub mod result {
    use e521_curve::e521::Point;
    use num_bigint_dig::BigInt;

    pub struct GenerateKeyPairResult {
        pub x: BigInt,
        pub y: BigInt,

        pub private_key: Vec<u8>
    }

    impl GenerateKeyPairResult {
        pub fn from(public_point: Point, private_key: Vec<u8>) -> Self {
            Self {
                x: public_point.x,
                y: public_point.y,

                private_key,
            }
        }
    }
}
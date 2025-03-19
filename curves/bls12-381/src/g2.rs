pub use bytemuck_derive::{Pod, Zeroable};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodBlsG2(pub [u8; 96]);

#[cfg(not(target_os = "solana"))]
mod target_arch {
    use {
        super::*,
        crate::{errors::Bls12381Error, scalar::PodScalar},
        blst::{
            blst_hash_to_g2, blst_p2, blst_p2_add, blst_p2_affine, blst_p2_cneg, blst_p2_compress,
            blst_p2_mult,
        },
        solana_curve_traits::{GroupOperations, HashToCurve},
    };

    impl HashToCurve for PodBlsG2 {
        type Point = Self;

        fn hash_to_curve(bytes: &[u8], dst: &[u8], aug: &[u8]) -> Self::Point {
            let mut result_bytes = [0u8; 96];
            let result_bytes_ptr = &mut result_bytes as *mut u8;

            let mut resulting_point = blst_p2::default();
            let resulting_point_ptr = &mut resulting_point as *mut blst_p2;

            unsafe {
                blst_hash_to_g2(
                    resulting_point_ptr,
                    bytes.as_ptr(),
                    bytes.len(),
                    dst.as_ptr(),
                    dst.len(),
                    aug.as_ptr(),
                    aug.len(),
                );
                blst_p2_compress(result_bytes_ptr, resulting_point_ptr);
            }

            Self(result_bytes)
        }
    }

    unsafe fn blst_decompress(compressed: &PodBlsG2) -> Result<blst_p2, Bls12381Error> {
        let point_ptr = &compressed.0 as *const u8;

        let mut point_affine = blst_p2_affine::default();
        let point_affine_ptr = &mut point_affine as *mut blst_p2_affine;
        blst::blst_p2_uncompress(point_affine_ptr, point_ptr);

        let mut point_full = blst_p2::default();
        let point_full_ptr = &mut point_full as *mut blst_p2;
        blst::blst_p2_from_affine(point_full_ptr, point_affine_ptr);

        Ok(point_full)
    }

    impl GroupOperations for PodBlsG2 {
        type Scalar = PodScalar;
        type Point = Self;

        fn add(left_point: &Self, right_point: &Self) -> Option<Self> {
            let mut result_bytes = [0u8; 96];
            let result_bytes_ptr = &mut result_bytes as *mut u8;

            let mut resulting_point = blst_p2::default();
            let resulting_point_ptr = &mut resulting_point as *mut blst_p2;

            unsafe {
                let left_point_decompressed = blst_decompress(left_point).ok()?;
                let right_point_decompressed = blst_decompress(right_point).ok()?;

                blst_p2_add(
                    resulting_point_ptr,
                    &left_point_decompressed as *const blst_p2,
                    &right_point_decompressed as *const blst_p2,
                );
                blst_p2_compress(result_bytes_ptr, resulting_point_ptr);
            }

            Some(Self(result_bytes))
        }

        fn subtract(left_point: &Self, right_point: &Self) -> Option<Self> {
            let mut result_bytes = [0u8; 96];
            let result_bytes_ptr = &mut result_bytes as *mut u8;

            let mut resulting_point = blst_p2::default();
            let resulting_point_ptr = &mut resulting_point as *mut blst_p2;

            unsafe {
                let left_point_decompressed = blst_decompress(left_point).ok()?;
                let mut right_point_decompressed = blst_decompress(right_point).ok()?;

                blst_p2_cneg(&mut right_point_decompressed as *mut blst_p2, true);
                blst_p2_add(
                    resulting_point_ptr,
                    &left_point_decompressed as *const blst_p2,
                    &right_point_decompressed as *const blst_p2,
                );
                blst_p2_compress(result_bytes_ptr, resulting_point_ptr);
            }

            Some(Self(result_bytes))
        }

        fn multiply(scalar: &PodScalar, point: &Self) -> Option<Self> {
            let mut result_bytes = [0u8; 96];
            let result_bytes_ptr = &mut result_bytes as *mut u8;

            let mut resulting_point = blst_p2::default();
            let resulting_point_ptr = &mut resulting_point as *mut blst_p2;

            unsafe {
                let point_decompressed = blst_decompress(point).ok()?;

                blst_p2_mult(
                    resulting_point_ptr,
                    &point_decompressed as *const blst_p2,
                    scalar.0.as_ptr(),
                    256,
                );
                blst_p2_compress(result_bytes_ptr, resulting_point_ptr);
            }

            Some(Self(result_bytes))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalar::PodScalar;
    use solana_curve_traits::GroupOperations;

    #[test]
    fn test_add_subtract_bls_12_381() {
        // associativity
        let identity = PodBlsG2([
            192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);

        let point_a = PodBlsG2([
            164, 206, 80, 113, 43, 158, 131, 37, 93, 106, 231, 75, 147, 161, 185, 106, 81, 151, 33,
            215, 119, 212, 236, 144, 255, 79, 164, 84, 156, 164, 121, 86, 19, 207, 42, 161, 95, 32,
            22, 141, 21, 250, 100, 154, 134, 50, 186, 209, 12, 208, 242, 49, 189, 146, 166, 202,
            120, 136, 221, 182, 244, 18, 95, 15, 95, 85, 3, 216, 6, 37, 199, 101, 109, 31, 213, 20,
            68, 69, 19, 79, 126, 19, 60, 71, 114, 17, 78, 220, 142, 37, 33, 157, 252, 2, 18, 182,
        ]);

        let point_b = PodBlsG2([
            183, 42, 8, 225, 237, 101, 184, 130, 73, 9, 104, 128, 181, 122, 114, 248, 38, 145, 28,
            175, 76, 168, 219, 102, 168, 17, 1, 163, 145, 33, 127, 101, 159, 1, 108, 7, 56, 68,
            142, 7, 151, 2, 220, 149, 227, 134, 194, 231, 9, 6, 86, 227, 163, 72, 228, 151, 235,
            97, 51, 218, 156, 244, 234, 108, 157, 71, 90, 247, 143, 215, 224, 44, 68, 20, 155, 178,
            155, 29, 183, 167, 10, 244, 56, 19, 49, 169, 90, 8, 100, 86, 172, 14, 119, 200, 205,
            193,
        ]);

        let point_c = PodBlsG2([
            139, 35, 111, 111, 138, 15, 121, 99, 87, 180, 83, 67, 5, 100, 162, 78, 79, 114, 138,
            150, 244, 249, 138, 213, 44, 122, 179, 155, 36, 156, 121, 98, 76, 57, 109, 116, 219,
            227, 54, 177, 90, 19, 147, 215, 145, 4, 231, 175, 1, 144, 102, 168, 64, 217, 60, 234,
            32, 38, 115, 250, 43, 47, 227, 138, 249, 195, 141, 231, 226, 207, 122, 246, 147, 50,
            72, 230, 22, 215, 146, 161, 209, 111, 221, 185, 53, 103, 4, 224, 151, 54, 60, 94, 65,
            34, 66, 247,
        ]);

        // identity
        assert_eq!(PodBlsG2::add(&point_a, &identity).unwrap(), point_a,);

        // associativity
        assert_eq!(
            PodBlsG2::add(&PodBlsG2::add(&point_a, &point_b).unwrap(), &point_c).unwrap(),
            PodBlsG2::add(&point_a, &PodBlsG2::add(&point_b, &point_c).unwrap()).unwrap(),
        );

        assert_eq!(
            PodBlsG2::subtract(&PodBlsG2::subtract(&point_a, &point_b).unwrap(), &point_c).unwrap(),
            PodBlsG2::subtract(&point_a, &PodBlsG2::add(&point_b, &point_c).unwrap()).unwrap(),
        );

        // commutativity
        assert_eq!(
            PodBlsG2::add(&point_a, &point_b).unwrap(),
            PodBlsG2::add(&point_b, &point_a).unwrap()
        );

        // subtraction
        assert_eq!(PodBlsG2::subtract(&point_a, &point_a).unwrap(), identity);
    }

    #[test]
    fn test_multiply_bls12_381() {
        let scalar = PodScalar([
            107, 15, 13, 77, 216, 207, 117, 144, 252, 166, 162, 81, 107, 12, 249, 164, 242, 212,
            76, 68, 144, 198, 72, 233, 76, 116, 60, 179, 0, 32, 86, 93,
        ]);

        let point_a = PodBlsG2([
            164, 206, 80, 113, 43, 158, 131, 37, 93, 106, 231, 75, 147, 161, 185, 106, 81, 151, 33,
            215, 119, 212, 236, 144, 255, 79, 164, 84, 156, 164, 121, 86, 19, 207, 42, 161, 95, 32,
            22, 141, 21, 250, 100, 154, 134, 50, 186, 209, 12, 208, 242, 49, 189, 146, 166, 202,
            120, 136, 221, 182, 244, 18, 95, 15, 95, 85, 3, 216, 6, 37, 199, 101, 109, 31, 213, 20,
            68, 69, 19, 79, 126, 19, 60, 71, 114, 17, 78, 220, 142, 37, 33, 157, 252, 2, 18, 182,
        ]);

        let point_b = PodBlsG2([
            183, 42, 8, 225, 237, 101, 184, 130, 73, 9, 104, 128, 181, 122, 114, 248, 38, 145, 28,
            175, 76, 168, 219, 102, 168, 17, 1, 163, 145, 33, 127, 101, 159, 1, 108, 7, 56, 68,
            142, 7, 151, 2, 220, 149, 227, 134, 194, 231, 9, 6, 86, 227, 163, 72, 228, 151, 235,
            97, 51, 218, 156, 244, 234, 108, 157, 71, 90, 247, 143, 215, 224, 44, 68, 20, 155, 178,
            155, 29, 183, 167, 10, 244, 56, 19, 49, 169, 90, 8, 100, 86, 172, 14, 119, 200, 205,
            193,
        ]);

        let ax = PodBlsG2::multiply(&scalar, &point_a).unwrap();
        let bx = PodBlsG2::multiply(&scalar, &point_b).unwrap();

        assert_eq!(
            PodBlsG2::add(&ax, &bx).unwrap(),
            PodBlsG2::multiply(&scalar, &PodBlsG2::add(&point_a, &point_b).unwrap()).unwrap(),
        );
    }
}

pub use bytemuck_derive::{Pod, Zeroable};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodBlsG1(pub [u8; 48]);

#[cfg(not(target_os = "solana"))]
mod target_arch {
    use {
        super::*,
        crate::{errors::Bls12381Error, scalar::PodScalar},
        blst::{
            blst_hash_to_g1, blst_p1, blst_p1_add, blst_p1_affine, blst_p1_cneg, blst_p1_compress,
            blst_p1_mult,
        },
        solana_curve_traits::{GroupOperations, HashToCurve},
    };

    impl HashToCurve for PodBlsG1 {
        type Point = Self;

        fn hash_to_curve(bytes: &[u8], dst: &[u8], aug: &[u8]) -> Self::Point {
            let mut result_bytes = [0u8; 48];
            let result_bytes_ptr = &mut result_bytes as *mut u8;

            let mut resulting_point = blst_p1::default();
            let resulting_point_ptr = &mut resulting_point as *mut blst_p1;

            unsafe {
                blst_hash_to_g1(
                    resulting_point_ptr,
                    bytes.as_ptr(),
                    bytes.len(),
                    dst.as_ptr(),
                    dst.len(),
                    aug.as_ptr(),
                    aug.len(),
                );
                blst_p1_compress(result_bytes_ptr, resulting_point_ptr);
            }

            Self(result_bytes)
        }
    }

    unsafe fn blst_decompress(compressed: &PodBlsG1) -> Result<blst_p1, Bls12381Error> {
        let point_ptr = &compressed.0 as *const u8;

        let mut point_affine = blst_p1_affine::default();
        let point_affine_ptr = &mut point_affine as *mut blst_p1_affine;
        blst::blst_p1_uncompress(point_affine_ptr, point_ptr);

        let mut point_full = blst_p1::default();
        let point_full_ptr = &mut point_full as *mut blst_p1;
        blst::blst_p1_from_affine(point_full_ptr, point_affine_ptr);

        Ok(point_full)
    }

    impl GroupOperations for PodBlsG1 {
        type Scalar = PodScalar;
        type Point = Self;

        fn add(left_point: &Self, right_point: &Self) -> Option<Self> {
            let mut result_bytes = [0u8; 48];
            let result_bytes_ptr = &mut result_bytes as *mut u8;

            let mut resulting_point = blst_p1::default();
            let resulting_point_ptr = &mut resulting_point as *mut blst_p1;

            unsafe {
                let left_point_decompressed = blst_decompress(left_point).ok()?;
                let right_point_decompressed = blst_decompress(right_point).ok()?;

                blst_p1_add(
                    resulting_point_ptr,
                    &left_point_decompressed as *const blst_p1,
                    &right_point_decompressed as *const blst_p1,
                );
                blst_p1_compress(result_bytes_ptr, resulting_point_ptr);
            }

            Some(Self(result_bytes))
        }

        fn subtract(left_point: &Self, right_point: &Self) -> Option<Self> {
            let mut result_bytes = [0u8; 48];
            let result_bytes_ptr = &mut result_bytes as *mut u8;

            let mut resulting_point = blst_p1::default();
            let resulting_point_ptr = &mut resulting_point as *mut blst_p1;

            unsafe {
                let left_point_decompressed = blst_decompress(left_point).ok()?;
                let mut right_point_decompressed = blst_decompress(right_point).ok()?;

                blst_p1_cneg(&mut right_point_decompressed as *mut blst_p1, true);
                blst_p1_add(
                    resulting_point_ptr,
                    &left_point_decompressed as *const blst_p1,
                    &right_point_decompressed as *const blst_p1,
                );
                blst_p1_compress(result_bytes_ptr, resulting_point_ptr);
            }

            Some(Self(result_bytes))
        }

        fn multiply(scalar: &PodScalar, point: &Self) -> Option<Self> {
            let mut result_bytes = [0u8; 48];
            let result_bytes_ptr = &mut result_bytes as *mut u8;

            let mut resulting_point = blst_p1::default();
            let resulting_point_ptr = &mut resulting_point as *mut blst_p1;

            unsafe {
                let point_decompressed = blst_decompress(point).ok()?;

                blst_p1_mult(
                    resulting_point_ptr,
                    &point_decompressed as *const blst_p1,
                    scalar.0.as_ptr(),
                    256,
                );
                blst_p1_compress(result_bytes_ptr, resulting_point_ptr);
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
        let identity = PodBlsG1([
            192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);

        let point_a = PodBlsG1([
            140, 112, 74, 2, 254, 123, 212, 72, 73, 122, 106, 93, 64, 7, 172, 236, 36, 227, 96,
            130, 121, 240, 41, 205, 62, 7, 207, 15, 94, 159, 7, 91, 99, 57, 241, 162, 136, 81, 90,
            5, 179, 98, 6, 98, 41, 146, 195, 14,
        ]);

        let point_b = PodBlsG1([
            149, 247, 195, 10, 243, 121, 148, 92, 212, 118, 110, 34, 133, 35, 193, 161, 225, 85,
            122, 150, 192, 175, 136, 69, 63, 0, 146, 159, 103, 117, 89, 145, 171, 184, 105, 135,
            75, 231, 97, 247, 162, 101, 208, 175, 198, 222, 35, 102,
        ]);

        let point_c = PodBlsG1([
            137, 46, 171, 236, 48, 64, 85, 76, 96, 91, 201, 87, 53, 133, 184, 211, 4, 113, 227,
            145, 17, 134, 71, 182, 72, 39, 55, 230, 145, 29, 216, 20, 52, 247, 57, 191, 255, 53,
            57, 150, 221, 59, 52, 78, 171, 240, 129, 39,
        ]);

        // identity
        assert_eq!(PodBlsG1::add(&point_a, &identity).unwrap(), point_a,);

        // associativity
        assert_eq!(
            PodBlsG1::add(&PodBlsG1::add(&point_a, &point_b).unwrap(), &point_c).unwrap(),
            PodBlsG1::add(&point_a, &PodBlsG1::add(&point_b, &point_c).unwrap()).unwrap(),
        );

        assert_eq!(
            PodBlsG1::subtract(&PodBlsG1::subtract(&point_a, &point_b).unwrap(), &point_c).unwrap(),
            PodBlsG1::subtract(&point_a, &PodBlsG1::add(&point_b, &point_c).unwrap()).unwrap(),
        );

        // commutativity
        assert_eq!(
            PodBlsG1::add(&point_a, &point_b).unwrap(),
            PodBlsG1::add(&point_b, &point_a).unwrap()
        );

        // subtraction
        assert_eq!(PodBlsG1::subtract(&point_a, &point_a).unwrap(), identity);
    }

    #[test]
    fn test_multiply_bls12_381() {
        let scalar = PodScalar([
            107, 15, 13, 77, 216, 207, 117, 144, 252, 166, 162, 81, 107, 12, 249, 164, 242, 212,
            76, 68, 144, 198, 72, 233, 76, 116, 60, 179, 0, 32, 86, 93,
        ]);

        let point_a = PodBlsG1([
            140, 112, 74, 2, 254, 123, 212, 72, 73, 122, 106, 93, 64, 7, 172, 236, 36, 227, 96,
            130, 121, 240, 41, 205, 62, 7, 207, 15, 94, 159, 7, 91, 99, 57, 241, 162, 136, 81, 90,
            5, 179, 98, 6, 98, 41, 146, 195, 14,
        ]);

        let point_b = PodBlsG1([
            149, 247, 195, 10, 243, 121, 148, 92, 212, 118, 110, 34, 133, 35, 193, 161, 225, 85,
            122, 150, 192, 175, 136, 69, 63, 0, 146, 159, 103, 117, 89, 145, 171, 184, 105, 135,
            75, 231, 97, 247, 162, 101, 208, 175, 198, 222, 35, 102,
        ]);

        let ax = PodBlsG1::multiply(&scalar, &point_a).unwrap();
        let bx = PodBlsG1::multiply(&scalar, &point_b).unwrap();

        assert_eq!(
            PodBlsG1::add(&ax, &bx).unwrap(),
            PodBlsG1::multiply(&scalar, &PodBlsG1::add(&point_a, &point_b).unwrap()).unwrap(),
        );
    }
}

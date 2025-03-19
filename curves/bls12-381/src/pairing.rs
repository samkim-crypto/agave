pub use bytemuck::{Pod, Zeroable};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct PodBlsGT(pub [u8; 576]);

unsafe impl Zeroable for PodBlsGT {}
unsafe impl Pod for PodBlsGT {}

#[cfg(not(target_os = "solana"))]
mod target_arch {
    use {
        super::*,
        crate::{g1::PodBlsG1, g2::PodBlsG2},
        blst::{
            blst_bendian_from_fp12, blst_fp12, blst_miller_loop_n, blst_p1_affine, blst_p2_affine,
        },
        solana_curve_traits::Pairing,
    };

    unsafe fn decompress_p1(compressed_points: &[PodBlsG1]) -> Option<Vec<blst_p1_affine>> {
        compressed_points
            .iter()
            .map(|point| {
                let point_ptr = &point.0 as *const u8;
                let mut point_affine = blst_p1_affine::default();
                let point_affine_ptr = &mut point_affine as *mut blst_p1_affine;
                blst::blst_p1_uncompress(point_affine_ptr, point_ptr);
                Some(point_affine)
            })
            .collect::<Option<Vec<_>>>()
    }

    unsafe fn decompress_p2(compressed_points: &[PodBlsG2]) -> Option<Vec<blst_p2_affine>> {
        compressed_points
            .iter()
            .map(|point| {
                let point_ptr = &point.0 as *const u8;
                let mut point_affine = blst_p2_affine::default();
                let point_affine_ptr = &mut point_affine as *mut blst_p2_affine;
                blst::blst_p2_uncompress(point_affine_ptr, point_ptr);
                Some(point_affine)
            })
            .collect::<Option<Vec<_>>>()
    }

    impl Pairing for PodBlsGT {
        type G1Point = PodBlsG1;
        type G2Point = PodBlsG2;
        type GTPoint = PodBlsGT;

        fn pairing_map(
            g1_points: &[PodBlsG1],
            g2_points: &[PodBlsG2],
            n: usize,
        ) -> Option<Self::GTPoint> {
            if g1_points.len() != n || g2_points.len() != n {
                return None;
            }

            let mut result_bytes = [0u8; 576];
            let result_bytes_ptr = &mut result_bytes as *mut u8;

            let mut result_point = blst_fp12::default();
            let result_point_ptr = &mut result_point as *mut blst_fp12;

            unsafe {
                let g1_affine_points = decompress_p1(g1_points)?;
                let g2_affine_points = decompress_p2(g2_points)?;

                let g1_affine_points_pointers = g1_affine_points
                    .iter()
                    .map(|point| point as *const blst_p1_affine)
                    .collect::<Vec<_>>();

                let g2_affine_points_pointers = g2_affine_points
                    .iter()
                    .map(|point| point as *const blst_p2_affine)
                    .collect::<Vec<_>>();

                blst_miller_loop_n(
                    result_point_ptr,
                    g2_affine_points_pointers.as_ptr(),
                    g1_affine_points_pointers.as_ptr(),
                    n,
                );
                blst_bendian_from_fp12(result_bytes_ptr, result_point_ptr);
            }

            Some(Self(result_bytes))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{g1::PodBlsG1, g2::PodBlsG2};
    use solana_curve_traits::Pairing;

    #[test]
    fn test_pairing_bls_12_381() {
        let point_g1 = PodBlsG1([
            140, 112, 74, 2, 254, 123, 212, 72, 73, 122, 106, 93, 64, 7, 172, 236, 36, 227, 96,
            130, 121, 240, 41, 205, 62, 7, 207, 15, 94, 159, 7, 91, 99, 57, 241, 162, 136, 81, 90,
            5, 179, 98, 6, 98, 41, 146, 195, 14,
        ]);

        let point_g2 = PodBlsG2([
            164, 206, 80, 113, 43, 158, 131, 37, 93, 106, 231, 75, 147, 161, 185, 106, 81, 151, 33,
            215, 119, 212, 236, 144, 255, 79, 164, 84, 156, 164, 121, 86, 19, 207, 42, 161, 95, 32,
            22, 141, 21, 250, 100, 154, 134, 50, 186, 209, 12, 208, 242, 49, 189, 146, 166, 202,
            120, 136, 221, 182, 244, 18, 95, 15, 95, 85, 3, 216, 6, 37, 199, 101, 109, 31, 213, 20,
            68, 69, 19, 79, 126, 19, 60, 71, 114, 17, 78, 220, 142, 37, 33, 157, 252, 2, 18, 182,
        ]);

        let point_gt = PodBlsGT([
            4, 136, 100, 94, 239, 152, 12, 25, 34, 183, 170, 64, 38, 164, 117, 188, 149, 25, 240,
            78, 185, 117, 167, 38, 145, 168, 59, 104, 166, 183, 110, 243, 102, 133, 12, 68, 171,
            119, 38, 247, 220, 227, 97, 54, 195, 94, 144, 65, 19, 158, 88, 48, 132, 156, 131, 200,
            216, 111, 98, 254, 79, 127, 229, 252, 40, 221, 25, 136, 201, 239, 138, 33, 60, 218,
            221, 165, 253, 3, 172, 224, 255, 185, 91, 25, 229, 69, 231, 253, 185, 183, 203, 119,
            75, 183, 136, 138, 25, 91, 1, 59, 49, 80, 166, 12, 65, 54, 37, 253, 31, 0, 51, 251, 61,
            144, 164, 135, 29, 241, 34, 17, 56, 133, 245, 79, 150, 190, 121, 67, 193, 130, 96, 189,
            112, 4, 186, 49, 0, 118, 60, 171, 45, 28, 238, 22, 24, 55, 188, 192, 84, 130, 250, 24,
            185, 159, 184, 138, 115, 185, 91, 154, 6, 8, 111, 11, 196, 138, 99, 239, 30, 104, 117,
            10, 76, 115, 167, 57, 155, 116, 156, 254, 54, 109, 246, 217, 148, 47, 253, 48, 184,
            134, 115, 135, 13, 116, 54, 174, 88, 133, 161, 205, 190, 113, 120, 196, 79, 129, 17,
            197, 188, 187, 174, 222, 118, 231, 202, 215, 180, 97, 81, 19, 60, 71, 223, 107, 46,
            190, 203, 200, 56, 115, 189, 204, 162, 194, 26, 59, 136, 10, 92, 24, 11, 141, 87, 6,
            177, 234, 134, 80, 220, 23, 210, 12, 120, 48, 46, 151, 155, 125, 95, 96, 230, 84, 119,
            92, 232, 146, 95, 117, 48, 64, 245, 0, 84, 205, 15, 199, 174, 22, 226, 234, 60, 196,
            213, 250, 86, 177, 112, 25, 0, 136, 2, 188, 88, 8, 173, 211, 158, 81, 231, 151, 144,
            73, 30, 22, 62, 57, 58, 26, 179, 155, 163, 150, 226, 76, 79, 156, 73, 158, 209, 116,
            115, 3, 1, 190, 186, 151, 171, 14, 118, 7, 72, 185, 94, 187, 189, 143, 18, 92, 108,
            245, 9, 8, 17, 175, 116, 177, 222, 36, 135, 183, 105, 117, 21, 161, 212, 90, 242, 63,
            127, 238, 95, 28, 237, 178, 174, 108, 172, 231, 12, 188, 22, 102, 76, 43, 212, 41, 152,
            77, 232, 151, 143, 18, 158, 19, 25, 38, 100, 220, 225, 5, 186, 165, 196, 156, 190, 169,
            236, 238, 181, 159, 233, 164, 185, 218, 9, 98, 83, 157, 100, 105, 231, 185, 73, 25,
            226, 83, 238, 160, 182, 226, 164, 25, 93, 19, 214, 242, 249, 52, 22, 24, 142, 136, 16,
            122, 105, 66, 139, 53, 75, 181, 14, 56, 113, 200, 146, 200, 222, 43, 142, 133, 77, 132,
            123, 178, 195, 9, 131, 27, 214, 249, 193, 214, 218, 227, 97, 57, 113, 105, 94, 236,
            158, 101, 40, 241, 217, 64, 32, 109, 16, 170, 8, 182, 100, 54, 4, 182, 26, 5, 79, 32,
            86, 60, 86, 158, 22, 105, 4, 102, 109, 113, 188, 123, 48, 206, 179, 168, 162, 214, 156,
            25, 185, 151, 155, 164, 69, 230, 202, 4, 137, 129, 69, 217, 157, 81, 87, 244, 16, 144,
            0, 100, 99, 11, 54, 68, 181, 105, 255, 67, 61, 161, 56, 115, 220, 238, 202, 149, 198,
            121, 15, 1, 90, 238, 103, 107, 120, 160, 88, 116, 109, 53, 100, 15, 93, 145, 200, 16,
            246, 137, 165, 15, 7, 98, 187, 141, 30, 89,
        ]);

        assert_eq!(
            PodBlsGT::pairing_map(&[point_g1], &[point_g2], 1).unwrap(),
            point_gt,
        );
    }
}

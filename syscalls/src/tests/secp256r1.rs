use {
    super::*,
    solana_define_syscall::curve_constants::{
        GROUP_OP_ADD, GROUP_OP_MUL, GROUP_OP_SUB, SECP256R1_BE, SECP256R1_LE,
    },
    solana_sbpf::vm::ContextObject,
    test_case::test_case,
};

// Fixed P-256 vectors keep the expected encodings independent of the library's serializers.
const GENERATOR: [u8; 64] = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];
const DOUBLE_GENERATOR: [u8; 64] = [
    0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e, 0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5, 0x1a, 0xc3,
    0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35, 0xa6, 0x0b, 0x48, 0xfc, 0x47, 0x66, 0x99, 0x78,
    0x07, 0x77, 0x55, 0x10, 0xdb, 0x8e, 0xd0, 0x40, 0x29, 0x3d, 0x9a, 0xc6, 0x9f, 0x74, 0x30, 0xdb,
    0xba, 0x7d, 0xad, 0xe6, 0x3c, 0xe9, 0x82, 0x29, 0x9e, 0x04, 0xb7, 0x9d, 0x22, 0x78, 0x73, 0xd1,
];
const SCALAR_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

fn encode<const N: usize>(mut bytes: [u8; N], curve_id: u64) -> [u8; N] {
    if curve_id == SECP256R1_LE {
        for coordinate in bytes.as_chunks_mut::<32>().0 {
            coordinate.reverse();
        }
    }
    bytes
}

#[test_case(SECP256R1_BE; "big_endian")]
#[test_case(SECP256R1_LE; "little_endian")]
fn test_validation(curve_id: u64) {
    let feature_set = &SVMFeatureSet {
        secp256r1_syscall_enabled: true,
        ..Default::default()
    };
    prepare_mock_with_feature_set!(invoke_context, program_id, bpf_loader::id(), feature_set);
    let cost = invoke_context.get_execution_cost().secp256r1_validate_cost;
    let config = Config::default();

    for (point, expected) in [(GENERATOR, 0), ([0; 64], 0), ([1; 64], 1), ([0xff; 64], 1)] {
        let point = encode(point, curve_id);
        let mapping = unsafe {
            MemoryMapping::new(
                vec![MemoryRegion::new(&raw const point, 0x100000000)],
                &config,
                SBPFVersion::V3,
            )
            .unwrap()
        };
        invoke_context
            .memory_contexts
            .mock_set_mapping_abi_v1(mapping);
        invoke_context.compute_meter.mock_set_remaining(cost);
        assert_eq!(
            SyscallCurvePointValidation::rust(&mut invoke_context, curve_id, 0x100000000, 0, 0, 0)
                .unwrap(),
            expected
        );
        assert_eq!(invoke_context.get_remaining(), 0);
    }
}

#[test_case(SECP256R1_BE; "big_endian")]
#[test_case(SECP256R1_LE; "little_endian")]
fn test_decompression(curve_id: u64) {
    let feature_set = &SVMFeatureSet {
        secp256r1_syscall_enabled: true,
        ..Default::default()
    };
    prepare_mock_with_feature_set!(invoke_context, program_id, bpf_loader::id(), feature_set);
    let cost = invoke_context
        .get_execution_cost()
        .secp256r1_decompress_cost;
    let config = Config::default();
    let expected = encode(GENERATOR, curve_id);
    let mut compressed = [0; 33];
    compressed[0] = 3; // The generator has an odd Y-coordinate in either byte order.
    compressed[1..].copy_from_slice(&expected[..32]);
    let mut invalid_prefix = compressed;
    invalid_prefix[0] = 4;
    let mut noncanonical_x = [0xff; 33];
    noncanonical_x[0] = 3;

    for (input, valid) in [
        (compressed, true),
        (invalid_prefix, false),
        (noncanonical_x, false),
        ([0; 33], false), // The identity has no compressed representation.
    ] {
        let mut output = [0xa5; 64];
        let mapping = unsafe {
            MemoryMapping::new(
                vec![
                    MemoryRegion::new(&raw const input, 0x100000000),
                    MemoryRegion::new(&raw mut output, 0x200000000),
                ],
                &config,
                SBPFVersion::V3,
            )
            .unwrap()
        };
        invoke_context
            .memory_contexts
            .mock_set_mapping_abi_v1(mapping);
        invoke_context.compute_meter.mock_set_remaining(cost);
        assert_eq!(
            SyscallCurveDecompress::rust(
                &mut invoke_context,
                curve_id,
                0x100000000,
                0x200000000,
                0,
                0,
            )
            .unwrap(),
            u64::from(!valid)
        );
        assert_eq!(output, if valid { expected } else { [0xa5; 64] });
        assert_eq!(invoke_context.get_remaining(), 0);
    }
}

#[test_case(SECP256R1_BE; "big_endian")]
#[test_case(SECP256R1_LE; "little_endian")]
fn test_group_ops(curve_id: u64) {
    let feature_set = &SVMFeatureSet {
        secp256r1_syscall_enabled: true,
        ..Default::default()
    };
    prepare_mock_with_feature_set!(invoke_context, program_id, bpf_loader::id(), feature_set);
    let costs = invoke_context.get_execution_cost();
    let add_cost = costs.secp256r1_add_cost;
    let sub_cost = costs.secp256r1_subtract_cost;
    let mul_cost = costs.secp256r1_multiply_cost;
    let config = Config::default();
    let generator = encode(GENERATOR, curve_id);
    let double_generator = encode(DOUBLE_GENERATOR, curve_id);
    let mut two = [0; 32];
    two[31] = 2;
    let two = encode(two, curve_id);
    let scalar_order = encode(SCALAR_ORDER, curve_id);

    for (op, left, right, expected) in [
        (
            GROUP_OP_ADD,
            generator.as_slice(),
            generator,
            Some(double_generator),
        ),
        (
            GROUP_OP_SUB,
            double_generator.as_slice(),
            generator,
            Some(generator),
        ),
        (GROUP_OP_SUB, generator.as_slice(), generator, Some([0; 64])),
        (GROUP_OP_ADD, [0; 64].as_slice(), generator, Some(generator)),
        (
            GROUP_OP_MUL,
            two.as_slice(),
            generator,
            Some(double_generator),
        ),
        (GROUP_OP_MUL, [0; 32].as_slice(), generator, Some([0; 64])),
        (GROUP_OP_MUL, two.as_slice(), [0; 64], Some([0; 64])),
        (GROUP_OP_ADD, generator.as_slice(), [0xff; 64], None),
        (GROUP_OP_SUB, [1; 64].as_slice(), generator, None),
        (GROUP_OP_MUL, two.as_slice(), [1; 64], None),
        (GROUP_OP_MUL, scalar_order.as_slice(), generator, None),
        (GROUP_OP_MUL, [0xff; 32].as_slice(), generator, None),
    ] {
        let mut output = [0xa5; 64];
        let mapping = unsafe {
            MemoryMapping::new(
                vec![
                    MemoryRegion::new(&raw const *left, 0x100000000),
                    MemoryRegion::new(&raw const right, 0x200000000),
                    MemoryRegion::new(&raw mut output, 0x300000000),
                ],
                &config,
                SBPFVersion::V3,
            )
            .unwrap()
        };
        invoke_context
            .memory_contexts
            .mock_set_mapping_abi_v1(mapping);
        invoke_context.compute_meter.mock_set_remaining(match op {
            GROUP_OP_ADD => add_cost,
            GROUP_OP_SUB => sub_cost,
            GROUP_OP_MUL => mul_cost,
            _ => unreachable!(),
        });
        assert_eq!(
            SyscallCurveGroupOps::rust(
                &mut invoke_context,
                curve_id,
                op,
                0x100000000,
                0x200000000,
                0x300000000,
            )
            .unwrap(),
            u64::from(expected.is_none())
        );
        assert_eq!(output, expected.unwrap_or([0xa5; 64]));
        assert_eq!(invoke_context.get_remaining(), 0);
    }
}

#[test_case(SECP256R1_BE; "big_endian")]
#[test_case(SECP256R1_LE; "little_endian")]
fn test_multiscalar_multiplication(curve_id: u64) {
    let feature_set = &SVMFeatureSet {
        secp256r1_syscall_enabled: true,
        ..Default::default()
    };
    prepare_mock_with_feature_set!(invoke_context, program_id, bpf_loader::id(), feature_set);
    let costs = invoke_context.get_execution_cost();
    let base_cost = costs.secp256r1_msm_base_cost;
    let incremental_cost = costs.secp256r1_msm_incremental_cost;
    let config = Config::default();
    let generator = encode(GENERATOR, curve_id);
    let mut one = [0; 32];
    one[31] = 1;
    let one = encode(one, curve_id);
    let scalar_order = encode(SCALAR_ORDER, curve_id);

    for (scalars, points, expected) in [
        (vec![], vec![], Some([0; 64])),
        (vec![one], vec![generator], Some(generator)),
        (
            vec![one; 2],
            vec![generator; 2],
            Some(encode(DOUBLE_GENERATOR, curve_id)),
        ),
        (vec![one; 512], vec![[0; 64]; 512], Some([0; 64])),
        (vec![scalar_order], vec![generator], None),
        (vec![[0; 32]], vec![[1; 64]], None),
    ] {
        let mut output = [0xa5; 64];
        let mapping = unsafe {
            MemoryMapping::new(
                vec![
                    MemoryRegion::new(&raw const *scalars.as_flattened(), 0x100000000),
                    MemoryRegion::new(&raw const *points.as_flattened(), 0x200000000),
                    MemoryRegion::new(&raw mut output, 0x300000000),
                ],
                &config,
                SBPFVersion::V3,
            )
            .unwrap()
        };
        invoke_context
            .memory_contexts
            .mock_set_mapping_abi_v1(mapping);
        let points_len = points.len() as u64;
        let cost = base_cost + incremental_cost * points_len.saturating_sub(1);
        invoke_context.compute_meter.mock_set_remaining(cost);
        assert_eq!(
            SyscallCurveMultiscalarMultiplication::rust(
                &mut invoke_context,
                curve_id,
                0x100000000,
                0x200000000,
                points_len,
                0x300000000,
            )
            .unwrap(),
            u64::from(expected.is_none())
        );
        assert_eq!(output, expected.unwrap_or([0xa5; 64]));
        assert_eq!(invoke_context.get_remaining(), 0);
    }

    let result =
        SyscallCurveMultiscalarMultiplication::rust(&mut invoke_context, curve_id, 0, 0, 513, 0);
    assert_matches!(result, Err(error) if error.downcast_ref::<SyscallError>() == Some(&SyscallError::InvalidLength));
}

#[test_case(SECP256R1_BE; "big_endian")]
#[test_case(SECP256R1_LE; "little_endian")]
fn test_feature_disabled(curve_id: u64) {
    let feature_set = &SVMFeatureSet::default();
    prepare_mock_with_feature_set!(invoke_context, program_id, bpf_loader::id(), feature_set);
    let remaining = invoke_context.get_remaining();
    for result in [
        SyscallCurvePointValidation::rust(&mut invoke_context, curve_id, 0, 0, 0, 0),
        SyscallCurveDecompress::rust(&mut invoke_context, curve_id, 0, 0, 0, 0),
        SyscallCurveGroupOps::rust(&mut invoke_context, curve_id, GROUP_OP_ADD, 0, 0, 0),
        SyscallCurveMultiscalarMultiplication::rust(&mut invoke_context, curve_id, 0, 0, 0, 0),
    ] {
        assert_matches!(result, Err(error) if error.downcast_ref::<SyscallError>() == Some(&SyscallError::InvalidAttribute));
    }
    assert_eq!(invoke_context.get_remaining(), remaining);
}

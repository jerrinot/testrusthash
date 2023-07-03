use jni::sys::jint;
use jni::{objects::JClass, JNIEnv};
use ring::rand::SystemRandom;
use ring::{digest, pbkdf2, signature};
use signature::{ECDSA_P256_SHA256_ASN1, EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use std::num::NonZeroU32;

static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
const HASH_SIZE: usize = digest::SHA256_OUTPUT_LEN;
const HASH_ITERATION_COUNT: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(100_000) };
const EC_PUBLIC_KEY_SIZE: usize = 65;
const P1363_SIGNATURE_SIZE: usize = 64; // r and s values are 32 bytes long, P1363 is just concatenation of r and s values

// DER tag constants
const DER_SEQUENCE_TAG_ID: u8 = 0x30;
const DER_INTEGER_TAG: u8 = 0x02;

// 1 byte for sequence tag
// 1 byte for total length
// 1 byte for r tag
// 1 byte for r length
// *optionally* 1 byte for r value sign - only when the highest bit is set in r value (see DER spec)
// up to 32 bytes for r value
// 1 byte for s tag
// 1 byte for s length
// *optionally* 1 byte for s value sign - only when the highest bit is set in s value (see DER spec)
// up to 32 bytes for s value
// in total: up to 72 bytes
const DER_MAX_SIGNATURE_SIZE: usize = 72;

// DER FORMAT offsets
const DER_SEQUENCE_TAG_OFFSET: usize = 0;
const DER_TOTAL_LENGTH_OFFSET: usize = DER_SEQUENCE_TAG_OFFSET + 1;
const DER_R_TAG_OFFSET: usize = DER_TOTAL_LENGTH_OFFSET + 1;
const DER_R_LEN_OFFSET: usize = DER_R_TAG_OFFSET + 1;
const DER_R_VALUE_OFFSET: usize = DER_R_LEN_OFFSET + 1;

#[no_mangle]
pub extern "system" fn Java_info_jerrinot_sandbox_rustyhashes_RustyCrypto_hash(
    _env: JNIEnv,
    _class: JClass,
    password_ptr: *const u8,
    password_len: jint,
    salt_ptr: *const u8,
    salt_len: jint,
    out_ptr: *mut u8,
) {
    assert!(!password_ptr.is_null());
    assert!(!salt_ptr.is_null());
    assert!(!out_ptr.is_null());
    let (password, salt, hash) = unsafe {
        (
            std::slice::from_raw_parts(password_ptr, password_len as usize),
            std::slice::from_raw_parts(salt_ptr, salt_len as usize),
            std::slice::from_raw_parts_mut(out_ptr, HASH_SIZE),
        )
    };

    pbkdf2::derive(PBKDF2_ALG, HASH_ITERATION_COUNT, &salt, password, hash);
}

#[no_mangle]
pub extern "system" fn Java_info_jerrinot_sandbox_rustyhashes_RustyCrypto_genkey(
    _env: JNIEnv,
    _class: JClass,
    private_key_ptr: *mut u8,
    public_key_ptr: *mut u8,
) {
    let rng = SystemRandom::new();
    let key_pair = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();

    let key_bytes = key_pair.as_ref();
    assert_eq!(key_bytes.len(), 138);

    unsafe {
        // copy private key to private_key_ptr
        key_bytes[36..68]
            .as_ptr()
            .copy_to_nonoverlapping(private_key_ptr, 32);
        // copy public key to public_key_ptr
        key_bytes[73..138]
            .as_ptr()
            .copy_to_nonoverlapping(public_key_ptr, 65);
    }
}

fn is_highest_bit_set(value: u8) -> bool {
    value & 0x80 != 0
}

fn copy_p1363_int_value_to_der(value: &[u8], destination: &mut [u8]) -> usize {
    let source_value_len = value.len();

    // skip the leading zero bytes
    // leading zero are present in the P1363 format, because it uses fixed-size encoding for both r and s values
    // on the other hand, the DER format is variable-size length: it uses the minimal number of bytes to represent integer values
    let source_start_index = value.iter().position(|&x| x != 0).unwrap_or_else(|| source_value_len - 1);

    let mut dest_start_index = 0;
    if is_highest_bit_set(value[source_start_index]) {
        // P1363 format uses unsigned integers while the DER format uses two's complement.
        // So if the highest bit in P1363 value is set we need to add an extra zero byte to indicate it's a positive number.
        // see the DER spec for more details
        destination[0] = 0;
        dest_start_index = 1;
    }
    let unsigned_len = source_value_len - source_start_index;
    let dest_end_offset = dest_start_index + unsigned_len;
    destination[dest_start_index..dest_end_offset].copy_from_slice(&value[source_start_index..]);
    return dest_end_offset;
}

fn convert_p1363_to_der(
    p1363_signature: &[u8],
    der_signature: &mut [u8],
) -> Result<usize, &'static str> {
    // P1363 signature format:
    // [r_value] [s_value]
    // in our case, both r and s are 32 bytes long - that's the property of the ECDSA P-256 curve
    //
    // DER signature format:
    // 0x30 [total_length] 0x02 [r_length] [r_value] 0x02 [s_length] [s_value]
    // where
    // 0x30 is the tag for the SEQUENCE.
    // total_length is the total length of the rest of the data (in bytes).
    // 0x02 is the tag for INTEGER.
    // r_length and s_length are the lengths of the r and s values (in bytes).
    // r_value and s_value are the r and s values.
    //
    // r_value and s_value are encoded as big-endian. If the highest bit of r_value or s_value is set,
    // we need to add an extra zero byte - that's the indication that the value is positive.

    assert_eq!(p1363_signature.len(), P1363_SIGNATURE_SIZE);

    let r = &p1363_signature[0..32];
    let s = &p1363_signature[32..64];

    let r_size = copy_p1363_int_value_to_der(r, &mut der_signature[DER_R_VALUE_OFFSET..]);
    let s_value_offset = DER_R_VALUE_OFFSET + r_size + 2; // why 2? 1 byte for s_tag and 1 byte for s_length
    let s_size = copy_p1363_int_value_to_der(s, &mut der_signature[s_value_offset..]);
    let s_tag_offset = DER_R_VALUE_OFFSET + r_size;
    let s_len_offset = s_tag_offset + 1;
    let total_size = s_value_offset + s_size;

    der_signature[DER_SEQUENCE_TAG_OFFSET] = DER_SEQUENCE_TAG_ID;
    der_signature[DER_TOTAL_LENGTH_OFFSET] = (total_size - 2) as u8; // total length, excluding the first two bytes
    der_signature[DER_R_TAG_OFFSET] = DER_INTEGER_TAG;
    der_signature[DER_R_LEN_OFFSET] = r_size as u8;
    der_signature[s_tag_offset] = DER_INTEGER_TAG;
    der_signature[s_len_offset] = s_size as u8;

    // println!("DER signature size: {}", total_size);
    // println!("DER signature: \n{}", der_signature[..total_size].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(", "));
    Ok(total_size)
}

fn verify_der_signature(public_key: &[u8], payload: &[u8], signature: &[u8]) -> bool {
    return signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .verify(payload, signature)
        .is_ok();
}

#[no_mangle]
pub extern "system" fn Java_info_jerrinot_sandbox_rustyhashes_RustyCrypto_verify(
    _env: JNIEnv,
    _class: JClass,
    public_key_ptr: *const u8,
    payload_ptr: *const u8,
    payload_len: jint,
    signature_ptr: *const u8,
    signature_len: jint,
) -> bool {
    let (public_key, payload, signature) = unsafe {
        (
            std::slice::from_raw_parts(public_key_ptr, EC_PUBLIC_KEY_SIZE),
            std::slice::from_raw_parts(payload_ptr, payload_len as usize),
            std::slice::from_raw_parts(signature_ptr, signature_len as usize),
        )
    };

    match signature.len() {
        P1363_SIGNATURE_SIZE => {
            let mut sig_der = [0u8; DER_MAX_SIGNATURE_SIZE];
            convert_p1363_to_der(&signature, &mut sig_der)
                .map(|size| verify_der_signature(public_key, payload, &sig_der[..size]))
                .unwrap_or(false)
        }
        _ => {
            // assume DER. DER has a variable size so we cannot match on it
            verify_der_signature(public_key, payload, signature)
        }
    }
}

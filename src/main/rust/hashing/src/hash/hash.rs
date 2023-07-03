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
const DER_TOTAL_LENGTH_OFFSET: usize = 1;
const DER_R_TAG_OFFSET: usize = 2;
const DER_R_LEN_OFFSET: usize = 3;

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

fn _copy_p1363_value_der(value: &[u8], destination: &mut [u8]) -> usize {
    let mut sign_len: usize = 0;
    let mut start_index = 0;

    // skip the leading zero bytes
    // leading zero are present in the P1363 format, because it uses fixed-size for both r and s values
    // on the other hand, the DER format is variable-size length: it uses the minimal number of bytes to represent the r and s values
    while value[start_index] == 0 {
        start_index += 1;
    }
    if value[start_index] & 0x80 != 0 {
        // if the highest bit is set, we need to add an extra zero byte, see the DER spec
        destination[0] = 0; // Add a zero byte before `r` value
        sign_len = 1;
    }
    let unsigned_len = value.len() - start_index;
    let value_end_offset = sign_len + unsigned_len;
    destination[sign_len..value_end_offset].copy_from_slice(&value[start_index..]);
    return value_end_offset;
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

    // set the r value into the resulting DER signature
    let mut r_sign_len: usize = 0;
    let mut r_unsigned_value_start_offset = DER_R_LEN_OFFSET + 1;
    let mut r_start_index = 0;

    // skip the leading zero bytes
    // leading zero are present in the P1363 format, because it uses fixed-size for both r and s values
    // on the other hand, the DER format is variable-size length: it uses the minimal number of bytes to represent the r and s values
    while r[r_start_index] == 0 {
        r_start_index += 1;
    }
    if r[r_start_index] & 0x80 != 0 {
        // if the highest bit is set, we need to add an extra zero byte, see the DER spec
        der_signature[r_unsigned_value_start_offset] = 0; // Add a zero byte before `r` value
        r_sign_len = 1;
    }
    r_unsigned_value_start_offset = r_unsigned_value_start_offset + r_sign_len;
    let unsigned_r_len = s.len() - r_start_index;
    let r_value_end_offset = r_unsigned_value_start_offset + unsigned_r_len;
    der_signature[r_unsigned_value_start_offset..r_value_end_offset].copy_from_slice(&r[r_start_index..]);

    let mut s_start_index = 0;
    while s[s_start_index] == 0 {
        s_start_index += 1;
    }
    let mut s_sign_len = 0;
    let s_len_offset = r_value_end_offset + 1;
    let mut s_unsigned_value_start_offset = s_len_offset + 1;
    if s[s_start_index] & 0x80 != 0 {
        der_signature[s_unsigned_value_start_offset] = 0; // Add a zero byte before `s` value
        s_sign_len = 1;
    }
    s_unsigned_value_start_offset = s_unsigned_value_start_offset + s_sign_len;
    let unsigned_s_len = s.len() - s_start_index;
    let s_value_end_offset = s_unsigned_value_start_offset + unsigned_s_len;
    der_signature[s_unsigned_value_start_offset..s_value_end_offset].copy_from_slice(&s[s_start_index..]);

    // add DER metadata
    let total_size = s_value_end_offset;
    let signed_r_len = unsigned_r_len + r_sign_len;
    der_signature[DER_SEQUENCE_TAG_OFFSET] = DER_SEQUENCE_TAG_ID;
    der_signature[DER_TOTAL_LENGTH_OFFSET] = (total_size - 2) as u8; // total length, excluding the first two bytes
    der_signature[DER_R_TAG_OFFSET] = DER_INTEGER_TAG;
    der_signature[DER_R_LEN_OFFSET] = signed_r_len as u8;
    // now follows the actual r_value - this was already set above
    let s_tag_offset = r_value_end_offset;
    let s_len_offset = s_tag_offset + 1;
    let signed_s_len = unsigned_s_len + s_sign_len;
    der_signature[s_tag_offset] = DER_INTEGER_TAG;
    der_signature[s_len_offset] = signed_s_len as u8;
    // now follows the actual s_value - this was already set above

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

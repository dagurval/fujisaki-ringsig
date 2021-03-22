use key;
use sig;
use trace;
use std::convert::TryInto;

/// For data structures that we cannot export. This hides it behind a void
/// pointer.
#[repr(C)]
pub struct OpaquePtr(*mut std::ffi::c_void);

#[no_mangle]
pub extern fn generate_keypair() -> OpaquePtr {
    OpaquePtr(Box::into_raw(Box::new(key::KeyPair::generate())) as *mut _)
}

#[no_mangle]
pub extern fn generate_keypair_from_bits(bits: *const u8) -> OpaquePtr {
    let bits = raw_to_vector(bits, 32);
    OpaquePtr(Box::into_raw(Box::new(key::KeyPair::generate_from_bits(bits.try_into().unwrap()))) as *mut _)
}

#[no_mangle]
/// Get the public key from a keypair. Returns false on error.
pub extern fn get_pubkey(keypair: &OpaquePtr, pubkey_out: &mut [u8; 32]) -> bool {
    let ptr = keypair.0 as *mut key::KeyPair;
    unsafe {
        match ptr.as_mut() {
            Some(keypair) => {
                (*pubkey_out)[..].clone_from_slice(&keypair.pubkey.as_bytes());
                true
            }
            None => false
        }
    }
}

#[no_mangle]
/// Get the private key from a keypair. Returns false on error.
pub extern fn get_privkey(keypair: &OpaquePtr, privkey_out: &mut [u8; 64]) -> bool {
    let ptr = keypair.0 as *mut key::KeyPair;
    unsafe {
        match ptr.as_mut() {
            Some(keypair) => {
                let privkey = (*keypair).privkey.as_bytes();
                (*privkey_out)[..].clone_from_slice(&privkey);
                true
            }
            None => false
        }
    }
}

fn raw_to_vector(raw: *const u8, n: usize) -> Vec<u8> {
    let mut as_vec = Vec::new();
    as_vec.reserve(n);
    for i in 0..n {
        unsafe { as_vec.push(*(raw.offset(i as isize))) }
    }
    as_vec
}

#[no_mangle]
/// Initialize a `Tag` with an issue and no public keys.
pub extern fn init_tag(issue: *const u8, n: usize) -> OpaquePtr {
    let tag = sig::Tag {
        issue: raw_to_vector(issue, n),
        pubkeys: vec![],
    };
    OpaquePtr(Box::into_raw(Box::new(tag)) as *mut _)
}

#[no_mangle]
/// Add a public key to a tag.
pub extern fn tag_add_pubkey(tag: &OpaquePtr, pubkey: *const u8) -> bool {
    let pubkey = key::PublicKey::from_bytes(&raw_to_vector(pubkey, 32))
            .expect("pubkey from bytes");

    let ptr = tag.0 as *mut sig::Tag;
    return unsafe {
        match ptr.as_mut() {
            Some(tag) => {
                tag.pubkeys.push(pubkey);
                true
            },
            None => false,
        }
    }
}

#[no_mangle]
pub extern fn sign(
    msg: *const u8, nmsg: usize,
    tag: &OpaquePtr,
    privkey: *const u8,
    out_signature: &mut [u8; 1024]) -> usize
{
    let tag_ptr = tag.0 as *mut sig::Tag;

    let privkey = match key::PrivateKey::from_bytes(&raw_to_vector(privkey, 64)) {
        Some(p) => p,
        None => return 0
    };

    unsafe {
        match tag_ptr.as_mut() {
            Some(tag) => {
                let signature = sig::sign(&raw_to_vector(msg, nmsg), tag, &privkey);
                let encoded = bincode::serialize(&signature).expect("encode signature");
                let siglen = encoded.len();
                (*out_signature)[..siglen].clone_from_slice(&encoded);
                siglen
            }
            None => 0
        }
    }
}

#[no_mangle]
pub extern fn verify(
    msg: *const u8, nmsg: usize,
    tag: &OpaquePtr,
    sig: *const u8, nsig: usize) -> bool {

    let tag_ptr = tag.0 as *mut sig::Tag;
    let sig = bincode::deserialize(&raw_to_vector(sig, nsig))
        .expect("deserialize sig");
    let msg = raw_to_vector(msg, nmsg);

    // println!("msg {:?}, sig {:?}", msg, sig);

    unsafe {
        match tag_ptr.as_mut() {
            Some(tag) => {
                sig::verify(&msg , &tag, &sig)
            },
            None => false,
        }
    }

}

// Maps trace::Trace, but without PublicKey as part of the enum.
#[repr(C)]
/// Encodes the relationship of two signatures
pub enum TraceResult {
    /// `Indep` indicates that the two given signatures were constructed with different private
    /// keys.
    Indep,

    /// `Linked` indicates that the same private key was used to sign the same message under the
    /// same tag. This does not reveal which key performed the double-signature.
    Linked,

    /// The same key was used to sign distinct messages under the same tag. `pubkey_out` reveales
    /// that pubkey.
    Revealed,

    // We can also add error conditions
    InputErrorSig1,
    InputErrorSig2,
    InputErrorTag,
}

#[no_mangle]
pub extern fn do_trace(
    msg1: *const u8, nmsg1: usize,
    sig1: *const u8, nsig1: usize,
    msg2: *const u8, nmsg2: usize,
    sig2: *const u8, nsig2: usize,
    tag: &OpaquePtr,
    pubkey_out: &mut [u8; 32],
    ) ->  TraceResult {

    let tag_ptr = tag.0 as *mut sig::Tag;
    let sig1 = match bincode::deserialize(&raw_to_vector(sig1, nsig1)) {
        Ok(s) => s,
        Err(_) => return TraceResult::InputErrorSig1
    };
    let sig2 = match bincode::deserialize(&raw_to_vector(sig2, nsig2)) {
        Ok(s) => s,
        Err(_) => return TraceResult::InputErrorSig2
    };

    let tag = unsafe {
         match tag_ptr.as_mut() {
            Some(t) => t,
            None => return TraceResult::InputErrorTag,
        }
    };
    match trace::trace(
            &raw_to_vector(msg1, nmsg1), &sig1,
            &raw_to_vector(msg2, nmsg2), &sig2,
            tag) {
        trace::Trace::Indep => TraceResult::Indep,
        trace::Trace::Linked => TraceResult::Linked,
        trace::Trace::Revealed(pubkey) => {
            (*pubkey_out)[..].clone_from_slice(&pubkey.as_bytes());
            TraceResult::Revealed
        }
    }
}

#[no_mangle]
pub extern fn free_tag(ptr: OpaquePtr) {
    unsafe { Box::from_raw(ptr.0 as *mut sig::Tag); }
}

#[no_mangle]
pub extern fn free_keypair(ptr: OpaquePtr) {
    unsafe { Box::from_raw(ptr.0 as *mut key::KeyPair); }
}

pub mod aes;
pub mod argon2;
pub mod base64;
pub mod deku;
pub mod io;
pub mod kem;
mod types;

use std::ptr;

// AI-generated (LGTM)
fn zeroize_string(s: &mut String) {
    unsafe {
        let ptr = s.as_mut_ptr();
        let len = s.len();
        // Write zeros to each byte
        for i in 0..len {
            ptr::write_volatile(ptr.add(i), 0u8);
        }
        // Set length to 0 (capacity remains unchanged)
        s.clear();
    }
}

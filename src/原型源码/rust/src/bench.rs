use std::time::Instant;
fn main() {
    let pw = "Master5678!xyz";
    let salt = [0u8; 16];
    for _ in 0..3 {
        let t = Instant::now();
        let mut k = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pw.as_bytes(), &salt, 600_000, &mut k);
        println!("  PBKDF2-600k(Rust): {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);
    }
    use argon2::{Algorithm, Argon2, Params, Version};
    for _ in 0..3 {
        let t = Instant::now();
        let p = Params::new(65536, 2, 1, Some(32)).unwrap();
        let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
        let mut out = [0u8; 32];
        a2.hash_password_into(pw.as_bytes(), &salt, &mut out).unwrap();
        println!("  Argon2id(m=64M,t=2,Rust): {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);
    }
}

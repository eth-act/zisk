//! Live round-trip for the streaming `write_output` public-output transfer.
//!
//! A real guest ELF (the `echo-output` guest in zisk-eth-client) writes a known payload in
//! several chunks via the standard `write_output` interface. ZisK commits `sha256(payload)` into
//! the public outputs at `OUTPUT_ADDR`. This test checks that:
//!   1. the host captures the plaintext — the per-chunk `EmuTrace.public_output`, concatenated in
//!      global chunk order (exercised here with small chunks across several threads), and
//!   2. `sha256(captured)` equals the committed digest, via `PublicValues::verify_public_output`
//!      (the exact binding the proof verifier performs).
//!
//! Ignored by default — it needs the prebuilt guest ELF. Build and run with:
//!   (cd ../zisk-eth-client/bin/guests/echo-output && cargo-zisk build --release)
//!   cargo test -p ziskemu --test public_output_roundtrip -- --ignored --nocapture

use zisk_common::{concat_public_output, EmuTrace, PublicValues, PROGRAM_VK_LEN, ZISK_PUBLICS};
use zisk_core::Riscv2zisk;
use ziskemu::{Emu, EmuOptions, ZiskEmulator};

const ELF_PATH: &str = "/projects/EF/zisk-repos/zisk-eth-client/bin/guests/echo-output/target/elf/riscv64ima-zisk-zkvm-elf/release/echo-output";

/// Must match the payload the `echo-output` guest writes (its chunks concatenated).
const EXPECTED: &[u8] =
    b"Hello, ZisK standard public output! Streaming write_output round-trip test. 0123456789ABCDEF";

#[test]
#[ignore = "requires the prebuilt echo-output guest ELF (build with cargo-zisk)"]
fn write_output_plaintext_round_trips_and_matches_digest() {
    let elf = std::fs::read(ELF_PATH)
        .unwrap_or_else(|e| panic!("read echo-output ELF at {ELF_PATH}: {e}"));
    let rom = Riscv2zisk::new(&elf).run().expect("transpile ELF -> ZiskRom");

    // 1) Capture the plaintext via the chunked minimal-trace path. Small chunks across multiple
    //    threads exercise the per-chunk drain (recorded blocks) / discard (others) and the
    //    ordered concatenation.
    let mut opts = EmuOptions { chunk_size: Some(64), ..Default::default() };
    let traces = ZiskEmulator::compute_minimal_traces(&rom, &[], &opts, 4)
        .expect("compute minimal traces");
    let plaintext = concat_public_output(&traces);
    assert_eq!(
        plaintext, EXPECTED,
        "captured public output must equal the guest payload (got {} bytes)",
        plaintext.len()
    );

    // 2) Read the digest the guest committed to OUTPUT_ADDR, via a full single-threaded run.
    opts.chunk_size = None;
    let mut emu = Emu::new(&rom);
    emu.run(Vec::new(), &opts, None::<Box<dyn Fn(EmuTrace)>>);
    assert!(emu.terminated(), "emulation must complete");
    let out32 = emu.get_output_32();

    // 3) Bind: sha256(plaintext) must equal the committed digest in public slots 0..8 — the same
    //    check the proof verifier runs.
    let mut words = vec![0u64; PROGRAM_VK_LEN + ZISK_PUBLICS];
    for i in 0..ZISK_PUBLICS {
        words[PROGRAM_VK_LEN + i] = out32[i] as u64;
    }
    let publics = PublicValues::new_from_u64(&words);
    assert!(
        publics.verify_public_output(&plaintext),
        "sha256(captured output) must equal the committed OUTPUT_ADDR digest"
    );

    // Sanity: a tampered payload must NOT verify against the same digest.
    let mut tampered = plaintext.clone();
    *tampered.last_mut().unwrap() ^= 0x01;
    assert!(!publics.verify_public_output(&tampered), "tampered output must fail the digest bind");

    println!("round-trip OK: {} bytes captured across chunks, digest matches", plaintext.len());
}

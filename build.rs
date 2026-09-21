//! Build script: compiles the vendored TigerBeetle AOF (Zig, the pinned
//! 0.14.1 toolchain wired through the repo's mise setup) into a cdylib and
//! links the Rust wrapper against it.
//!
//! Zig resolution order:
//! 1. `LUNET_LOCKS_AOF_ZIG` — an explicit zig binary path;
//! 2. `mise which zig` (the project's pinned toolchain, see mise.toml);
//! 3. plain `zig` from PATH (a mise-activated shell provides it).
//!
//! Incremental: `cargo:rerun-if-changed` covers the whole zig/ tree and the
//! build script itself; zig's own cache handles source-level increments.
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let lib_dir = if let Ok(path) = std::env::var("LUNET_LOCKS_AOF_LIB_DIR") {
        // Container/release builds can consume the separately built,
        // architecture-specific AOF artifact.
        PathBuf::from(path)
    } else {
        let zig_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("zig");
        let zig = locate_zig();
        let optimize = if std::env::var("PROFILE").as_deref() == Ok("release") {
            "-Doptimize=ReleaseSafe"
        } else {
            "-Doptimize=Debug"
        };
        let target =
            std::env::var("LUNET_LOCKS_AOF_TARGET").unwrap_or_else(|_| "native".to_string());
        let target_flag = if target == "native" {
            "-Dtarget=native".to_string()
        } else {
            format!("-Dtarget={target}")
        };
        // The vendored checksum asserts AES hardware at comptime
        // (vsr/checksum.zig): x86_64 needs aes AND avx for the impl path,
        // aarch64 needs aes alone. An explicit LUNET_LOCKS_AOF_TARGET
        // names the architecture; a native build reads the cargo target
        // arch, since "native" on an amd64 host still needs +avx.
        let native_arch =
            std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| String::new());
        let cpu_flag = if target.starts_with("x86_64")
            || (target == "native" && native_arch == "x86_64")
        {
            "-Dcpu=baseline+aes+avx".to_string()
        } else {
            "-Dcpu=baseline+aes".to_string()
        };
        let args = vec![
            "build".to_string(),
            optimize.to_string(),
            target_flag,
            cpu_flag,
            "--prefix".to_string(),
            out_dir.to_str().unwrap().to_string(),
        ];
        let status = Command::new(&zig)
            .current_dir(&zig_dir)
            .args(&args)
            .status()
            .unwrap_or_else(|err| panic!("aof build: cannot run zig toolchain: {err}"));
        assert!(status.success(), "aof build: zig build failed");
        out_dir.join("lib")
    };

    println!("cargo:rustc-link-search=native={}", lib_dir.display());

    // Link mode: the crate's default is the shared library (the runtime
    // lookup rides the `@rpath` install name); the `static` feature links
    // the same ABI statically — the advisory-lock adapter's cdylib is
    // loaded by the Lua runtime and must not grow a runtime dependency on
    // this shared library, so it opts in.
    let static_link = std::env::var("CARGO_FEATURE_STATIC").as_deref() == Ok("1");
    if static_link {
        println!("cargo:rustc-link-lib=static=lunet_locks_aof");
    } else {
        println!("cargo:rustc-link-lib=dylib=lunet_locks_aof");

        // The cdylib's install name is `@rpath/liblunet_locks_aof.dylib` (zig's
        // default), so every runtime consumer — the wrapper's own tests, the
        // lease-sequencer binary — needs the rpath pointing at the artifact.
        // `rustc-link-arg-tests` requires a test target; the package's tests are
        // integration tests, declared alongside this crate's manifests.
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_dir.display());
    }

    // Downstream binaries (e.g. the lease-sequencer example) read this
    // metadata through the `links = "lunet_locks_aof"` contract as
    // DEP_LUNET_LOCKS_AOF_LIB_DIR and emit their own runtime rpath.
    println!("cargo:metadata=lib_dir={}", lib_dir.display());

    println!("cargo:rerun-if-changed=zig");
    // The target and toolchain overrides change the AOF's own output, so
    // they are build-script inputs, not incidental environment.
    println!("cargo:rerun-if-env-changed=LUNET_LOCKS_AOF_TARGET");
    println!("cargo:rerun-if-env-changed=LUNET_LOCKS_AOF_ZIG");
    println!("cargo:rerun-if-env-changed=LUNET_LOCKS_AOF_LIB_DIR");
}

/// Resolve the zig binary: explicit override, then the mise-pinned
/// toolchain, then PATH.
fn locate_zig() -> PathBuf {
    if let Ok(path) = std::env::var("LUNET_LOCKS_AOF_ZIG") {
        let path = PathBuf::from(path);
        assert!(
            path.exists(),
            "LUNET_LOCKS_AOF_ZIG does not exist: {path:?}"
        );
        return path;
    }

    if let Ok(output) = Command::new("mise").arg("which").arg("zig").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return PathBuf::from(path);
            }
        }
    }

    PathBuf::from("zig")
}

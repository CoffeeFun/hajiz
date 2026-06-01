use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bpf_src = "bpf/audit_syscalls.c";
    let bpf_obj = out_dir.join("audit_syscalls.o");

    println!("cargo:rerun-if-changed={bpf_src}");
    println!("cargo:rerun-if-changed=build.rs");
    // Declare the custom cfg so rustc doesn't warn about unknown names.
    println!("cargo::rustc-check-cfg=cfg(ebpf_compiled)");

    let compiled = Command::new("clang")
        .args([
            "-target",
            "bpf",
            "-O2",
            "-g",
            "-Wall",
            "-Wno-unused-value",
            "-Wno-pointer-sign",
            "-Wno-compare-distinct-pointer-types",
            "-I/usr/include",
            "-c",
            bpf_src,
            "-o",
            bpf_obj.to_str().unwrap(),
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if compiled {
        // Tells Rust code: #[cfg(ebpf_compiled)] blocks are active.
        println!("cargo:rustc-cfg=ebpf_compiled");
    } else {
        println!(
            "cargo:warning=BPF compilation failed — eBPF audit disabled, falling back to strace"
        );
    }
}

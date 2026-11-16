//! Builds the C shim on Linux only (spec/11-build.md §4.1); macOS uses kernel_udp and sim.
fn main() {
    println!("cargo:rerun-if-changed=../../c/vyrn-nic-shim");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    cc::Build::new()
        .compiler("clang")
        .archiver("llvm-ar")
        .file("../../c/vyrn-nic-shim/shim.c")
        .include("../../c/vyrn-nic-shim")
        .flag("-std=c11")
        .flag("-flto=thin")
        .flag("-fno-strict-aliasing")
        .flag("-fwrapv")
        .flag("-fno-delete-null-pointer-checks")
        .flag("-ftrivial-auto-var-init=zero")
        .flag("-fvisibility=hidden")
        .flag("-Wall")
        .flag("-Wextra")
        .flag("-Werror")
        .flag("-Wconversion")
        .flag("-Wstrict-prototypes")
        .flag("-Wmissing-prototypes")
        .compile("vyrn_nic_shim");
}

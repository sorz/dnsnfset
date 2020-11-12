use bindgen;
use protobuf_codegen_pure as protobuf;
use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-lib=nftables");
    let bindings = bindgen::Builder::default()
        .whitelist_function("nft_run_cmd_from_buffer")
        .whitelist_function("nft_ctx_(new|free)")
        .whitelist_type("nft_ctx")
        .header("wrapper.h")
        .generate()
        .expect("Unable to generate bindings");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    protobuf::Codegen::new()
        .out_dir("src")
        .include("dnstap.pb")
        .input("dnstap.pb/dnstap.proto")
        .run()
        .expect("Couldn't generate dnstap protobuf");
}

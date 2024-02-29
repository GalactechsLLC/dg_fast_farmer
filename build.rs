// use std::env;
// use std::path::PathBuf;

fn main() {
    // For Future Use, example on how to add 3rd party C Harvester
    // let project_path =
    //     env::var("CARGO_MANIFEST_DIR").expect("Expected to find env var CARGO_MANIFEST_DIR");
    // let interface_path =
    //     env::var("C_SOURCE_PATH").unwrap_or(format!("{project_path}/c_interface"));
    // let header_file_path = format!("{interface_path}/C_HEADER_FILE.hpp");
    // println!("cargo:rustc-link-arg=-Wl,-z,muldefs");
    // println!("cargo:rustc-link-search={interface_path}");
    // println!("cargo:rustc-link-lib=static:+whole-archive=stdc++");
    // println!("cargo:rerun-if-changed={header_file_path}");
    // let bindings = bindgen::Builder::default()
    //     // The input header we would like to generate bindings for.
    //     .header(header_file_path)
    //     // Tell cargo to invalidate the built crate whenever any of the
    //     // included header files changed.
    //     .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
    //     .clang_arg("-std=c++14")
    //     //Define each Function and Type to Allow
    //     .allowlist_type("MANUALLY SET ALLOW LIST(These are the function names)")
    //     .generate()
    //     .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    // let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    // bindings
    //     .write_to_file(out_path.join("bindings.rs"))
    //     .expect("Couldn't write bindings!");
}

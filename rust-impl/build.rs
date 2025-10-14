// Copyright (c) 2024 Daniel Bergløv
// 
// Permission is hereby granted, free of charge, to any person obtaining a 
// copy of this software and associated documentation files (the "Software"), 
// to deal in the Software without restriction, including without limitation 
// the rights to use, copy, modify, merge, publish, distribute, sublicense, 
// and/or sell copies of the Software, and to permit persons to whom the 
// Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in 
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
// DEALINGS IN THE SOFTWARE.

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let out_file: std::path::PathBuf = [manifest_dir.as_str(), "src", "pam_bindings.rs"].iter().collect();
        
    println!("cargo:rerun-if-changed={}", out_file.display());
    println!("cargo:rerun-if-changed=build.rs");
        
    if std::env::var("CARGO_FEATURE_USE_PAM").is_err() {
        println!("cargo:warning=build.rs: feature `use_pam` not enabled; skipping bindgen");
        return;
        
    } else if out_file.exists() {
        println!("cargo:warning=build.rs: {} exists — skipping generation", out_file.display());
        return;
    }
    
    println!("cargo:warning=build.rs: Generating {}", out_file.display());

    let bindings = bindgen::Builder::default()
        // point to the system header
        .header("/usr/include/security/pam_appl.h")
        // only generate PAM_* constants/types
        .allowlist_var("PAM_.*")
        .allowlist_type("pam_.*")
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate PAM bindings");

    bindings
        .write_to_file(&out_file)
        .expect("Couldn't write bindings!");
}


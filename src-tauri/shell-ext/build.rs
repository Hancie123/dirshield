//! Embeds the sparse package identity in the DLL's manifest. Explorer only
//! loads a packaged menu handler whose DLL names the package it belongs to,
//! so the publisher must be the exact subject of the certificate that signs
//! the package. `scripts/build-sparse-package.ps1` sets it; without it (local
//! builds) nothing is embedded and the DLL can't be used by a package.

use std::{env, fs, path::PathBuf};

#[allow(dead_code)]
#[path = "../src/platform/menu_spec.rs"]
mod menu_spec;

fn main() {
    println!("cargo:rerun-if-env-changed=DIRSHIELD_SPARSE_PUBLISHER");
    println!("cargo:rerun-if-changed=../src/platform/menu_spec.rs");
    println!("cargo:rerun-if-changed=exports.def");
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        // COM entry points are looked up by name, never linked against.
        let def = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("exports.def");
        println!("cargo:rustc-cdylib-link-arg=/DEF:{}", def.display());
    }
    let Ok(publisher) = env::var("DIRSHIELD_SPARSE_PUBLISHER") else { return };
    if publisher.trim().is_empty() || env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        return;
    }
    let esc = |s: &str| s.replace('&', "&amp;").replace('"', "&quot;").replace('<', "&lt;").replace('>', "&gt;");
    let manifest = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1">
  <msix xmlns="urn:schemas-microsoft-com:msix.v1" publisher="{}" packageName="{}" applicationId="DirShield" />
</assembly>
"#,
        esc(publisher.trim()),
        menu_spec::SPARSE_PACKAGE_NAME
    );
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("identity.manifest");
    fs::write(&out, manifest).unwrap();
    // ID 2 = ISOLATIONAWARE_MANIFEST_RESOURCE_ID, the one DLLs use.
    println!("cargo:rustc-cdylib-link-arg=/MANIFEST:EMBED,ID=2");
    println!("cargo:rustc-cdylib-link-arg=/MANIFESTINPUT:{}", out.display());
}

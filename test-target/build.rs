//! Build the native no-CRT PE-entry fixtures with the MSVC toolchain that rustc uses.
//!
//! `cl.exe` is not on PATH inside Cargo's build-script environment. The `cc` crate
//! discovers the MSVC toolchain through the same Visual Studio registry keys that
//! rustc uses, and supplies the INCLUDE/LIB environment for it.
use std::{env, path::PathBuf, process::Command};

mod supervised_process {
    include!("../test-support/process.rs");
}

fn run(command: &mut Command) {
    let output = supervised_process::command_output(command, std::time::Duration::from_secs(60))
        .expect("run MSVC tool");
    assert!(
        output.status.success(),
        "MSVC tool failed: {command:?}\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn main() {
    println!("cargo:rerun-if-changed=entry.c");
    println!("cargo:rerun-if-changed=noimport.c");
    println!("cargo:rerun-if-changed=mixed.cpp");
    println!("cargo:rerun-if-changed=mscoree.def");
    println!("cargo:rerun-if-changed=../test-support/process.rs");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    // OUT_DIR = target/<profile>/build/<pkg>-<hash>/out
    let profile = out.ancestors().nth(3).expect("profile dir").to_path_buf();
    let compiler = cc::Build::new().cargo_metadata(false).get_compiler();
    let envs: Vec<_> = compiler.env().to_vec();
    let cl = compiler.path().to_path_buf();
    let link = cl
        .parent()
        .expect("cl has no parent directory")
        .join("link.exe");
    assert!(
        link.is_file(),
        "link.exe not found next to cl.exe: {}",
        link.display()
    );

    for fixture in ["entry", "noimport"] {
        let object = out.join(format!("{fixture}.obj"));
        let executable = profile.join(format!("test_target_{fixture}.exe"));
        run(Command::new(&cl)
            .envs(envs.iter().cloned())
            .args(["/nologo", "/c", "/O2", "/GS-", "/Zl"])
            .arg(format!("{fixture}.c"))
            .arg(format!("/Fo{}", object.display())));
        run(Command::new(&link)
            .envs(envs.iter().cloned())
            .args([
                "/nologo",
                "/subsystem:console",
                "/entry:stork_entry",
                "/nodefaultlib",
            ])
            .arg(&object)
            .arg("kernel32.lib")
            .arg(format!("/out:{}", executable.display())));
    }
    let mixed = profile.join("test_target_mixed.exe");
    let cli_library = cl
        .ancestors()
        .nth(4)
        .expect("MSVC directory")
        .join("lib/x64/msvcmrt.lib");
    if cli_library.is_file() {
        // Generate the fixture's import library; the .NET Framework SDK's
        // mscoree.lib is not installed with every C++/CLI toolchain.
        run(Command::new(&link)
            .envs(envs.iter().cloned())
            .args(["/lib", "/nologo", "/machine:x64", "/def:mscoree.def"])
            .arg(format!("/out:{}", out.join("mscoree.lib").display())));
        run(Command::new(&cl)
            .envs(envs.iter().cloned())
            .args(["/nologo", "/clr", "/MD", "/O2", "mixed.cpp"])
            .arg(format!("/Fo{}", out.join("mixed.obj").display()))
            .arg(format!("/Fe{}", mixed.display()))
            .arg("/link")
            .arg(format!("/libpath:{}", out.display())));
    } else {
        if mixed.exists() {
            std::fs::remove_file(&mixed).expect("remove stale mixed-mode fixture");
        }
        println!("cargo:warning=C++/CLI component is absent; mixed-mode fixture unavailable");
    }
}

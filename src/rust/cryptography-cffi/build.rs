// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    let target = env::var("TARGET").unwrap();
    let openssl_static = env::var("OPENSSL_STATIC")
        .map(|x| x == "1")
        .unwrap_or(false);
    if target.contains("apple") && openssl_static {
        // On (older) OSX we need to link against the clang runtime,
        // which is hidden in some non-default path.
        //
        // More details at https://github.com/alexcrichton/curl-rust/issues/279.
        if let Some(path) = macos_link_search_path() {
            println!("cargo:rustc-link-lib=clang_rt.osx");
            println!("cargo:rustc-link-search={}", path);
        }
    }

    let out_dir = env::var("OUT_DIR").unwrap();
    // FIXME: maybe pyo3-build-config should provide a way to do this?
    let python = env::var("PYO3_PYTHON").unwrap_or_else(|_| "python3".to_string());
    println!("cargo:rerun-if-env-changed=PYO3_PYTHON");
    println!("cargo:rerun-if-changed=../../_cffi_src/");
    println!("cargo:rerun-if-changed=../../cryptography/__about__.py");
    let output = Command::new(&python)
        .env("OUT_DIR", &out_dir)
        .arg("../../_cffi_src/build_openssl.py")
        .output()
        .expect("failed to execute build_openssl.py");
    if !output.status.success() {
        panic!(
            "failed to run build_openssl.py, stdout: \n{}\nstderr: \n{}\n",
            String::from_utf8(output.stdout).unwrap(),
            String::from_utf8(output.stderr).unwrap()
        );
    }

    let python_impl = run_python_script(
        &python,
        "import platform; print(platform.python_implementation(), end='')",
    )
    .unwrap();
    println!("cargo:rustc-cfg=python_implementation=\"{}\"", python_impl);
    let python_includes = run_python_script(
        &python,
        "import os; \
         import setuptools.dist; \
         import setuptools.command.build_ext; \
         b = setuptools.command.build_ext.build_ext(setuptools.dist.Distribution()); \
         b.finalize_options(); \
         print(os.pathsep.join(b.include_dirs), end='')",
    )
    .unwrap();
    let openssl_include =
        std::env::var_os("DEP_OPENSSL_INCLUDE").expect("unable to find openssl include path");
    let openssl_c = Path::new(&out_dir).join("_openssl.c");

    let mut build = cc::Build::new();
    build
        .file(openssl_c)
        .include(openssl_include)
        .flag_if_supported("-Wconversion")
        .flag_if_supported("-Wno-error=sign-conversion")
        .flag_if_supported("-Wno-unused-parameter");

    for python_include in env::split_paths(&python_includes) {
        build.include(python_include);
    }

    // Enable abi3 mode if we're not using PyPy.
    if python_impl != "PyPy" {
        // cp37 (Python 3.7 to help our grep when we some day drop 3.7 support)
        build.define("Py_LIMITED_API", "0x030700f0");
    }

    if cfg!(windows) {
        build.define("WIN32_LEAN_AND_MEAN", None);
    }

    build.compile("_openssl.a");
}

/// Run a python script using the specified interpreter binary.
fn run_python_script(interpreter: impl AsRef<Path>, script: &str) -> Result<String, String> {
    let interpreter = interpreter.as_ref();
    let out = Command::new(interpreter)
        .env("PYTHONIOENCODING", "utf-8")
        .arg("-c")
        .arg(script)
        .output();

    match out {
        Err(err) => Err(format!(
            "failed to run the Python interpreter at {}: {}",
            interpreter.display(),
            err
        )),
        Ok(ok) if !ok.status.success() => Err(format!(
            "Python script failed: {}",
            String::from_utf8(ok.stderr).expect("failed to parse Python script stderr as utf-8")
        )),
        Ok(ok) => Ok(
            String::from_utf8(ok.stdout).expect("failed to parse Python script stdout as utf-8")
        ),
    }
}

fn macos_link_search_path() -> Option<String> {
    let output = Command::new("clang")
        .arg("--print-search-dirs")
        .output()
        .ok()?;
    if !output.status.success() {
        println!(
            "failed to run 'clang --print-search-dirs', continuing without a link search path"
        );
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.contains("libraries: =") {
            let path = line.split('=').nth(1)?;
            return Some(format!("{}/lib/darwin", path));
        }
    }

    println!("failed to determine link search path, continuing without it");
    None
}

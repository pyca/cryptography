use std::{
    collections::BTreeMap,
    env,
    path::PathBuf,
    sync::{Arc, Mutex},
};

#[derive(Debug)]
struct Macros(Arc<Mutex<BTreeMap<String, i64>>>);
impl bindgen::callbacks::ParseCallbacks for Macros {
    fn will_parse_macro(&self, name: &str) -> bindgen::callbacks::MacroParsingBehavior {
        // Configuration switches are often empty macros. int_macro alone does
        // not observe them, which would misreport disabled backend features.
        if name.starts_with("OPENSSL_NO_") {
            self.0.lock().unwrap().entry(name.into()).or_insert(0);
        }
        // bindgen's integer callback omits option expressions implemented with
        // SSL_OP_BIT(n). Evaluate these object-like macros with the target C
        // compiler, excluding the function-like SSL_OP_BIT helper itself.
        if name == "SSL3_VERSION" || (name.starts_with("SSL_OP_") && name != "SSL_OP_BIT") {
            self.0.lock().unwrap().entry(name.into()).or_insert(0);
        }
        bindgen::callbacks::MacroParsingBehavior::Default
    }
    fn int_macro(&self, name: &str, value: i64) -> Option<bindgen::callbacks::IntKind> {
        if name.starts_with("OPENSSL_")
            || name.starts_with("LIBRESSL_")
            || name.starts_with("OB_")
            || name.starts_with("SSL_")
            || name.starts_with("TLS")
            || name.starts_with("DTLS")
            || name.starts_with("X509_V_")
        {
            self.0.lock().unwrap().insert(name.into(), value);
        }
        None
    }
}

fn configured(name: &str) -> Option<std::ffi::OsString> {
    let target = env::var("TARGET").unwrap().to_uppercase().replace('-', "_");
    let specific = format!("{target}_{name}");
    println!("cargo:rerun-if-env-changed={specific}");
    println!("cargo:rerun-if-env-changed={name}");
    env::var_os(&specific).or_else(|| env::var_os(name))
}

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=shim.c");
    let root = configured("OPENSSL_DIR").map(PathBuf::from);
    let include = configured("OPENSSL_INCLUDE_DIR")
        .map(PathBuf::from)
        .or_else(|| root.as_ref().map(|p| p.join("include")));
    let lib = configured("OPENSSL_LIB_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            root.as_ref().map(|p| {
                if p.join("lib64").is_dir() {
                    p.join("lib64")
                } else {
                    p.join("lib")
                }
            })
        });
    let static_link = configured("OPENSSL_STATIC").map(|v| v == "1");
    let includes = match (include, lib) {
        (Some(include), Some(lib)) => {
            assert!(include.join("openssl/evp.h").is_file(), "OPENSSL_INCLUDE_DIR must contain openssl/evp.h");
            assert!(lib.is_dir(), "OPENSSL_LIB_DIR must be a directory");
            println!("cargo:rustc-link-search=native={}", lib.display());
            let windows = env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
            let is_static = static_link.unwrap_or_else(|| {
                (lib.join("libssl.a").is_file()
                    && !lib.join("libssl.so").exists()
                    && !lib.join("libssl.dylib").exists())
                    || lib.join("libssl_static.lib").is_file()
            });
            let kind = if is_static { "static" } else { "dylib" };
            for name in ["ssl", "crypto"] {
                let name = if windows {
                    if lib.join(format!("lib{name}_static.lib")).is_file() {
                        format!("lib{name}_static")
                    } else {
                        format!("lib{name}")
                    }
                } else {
                    name.to_owned()
                };
                println!("cargo:rustc-link-lib={kind}={name}");
            }
            if windows {
                for name in ["ws2_32", "crypt32", "advapi32", "user32", "gdi32"] {
                    println!("cargo:rustc-link-lib={name}");
                }
            }
            vec![include]
        }
        (None, None) => pkg_config::Config::new()
            .statik(static_link.unwrap_or(false)).probe("openssl")
            .expect("install an OpenSSL backend and pkg-config, or set OPENSSL_DIR (and OPENSSL_LIB_DIR for multiarch installs)")
            .include_paths,
        _ => panic!("set both OPENSSL_INCLUDE_DIR and OPENSSL_LIB_DIR, or set OPENSSL_DIR"),
    };
    let macros = Arc::new(Mutex::new(BTreeMap::new()));
    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .parse_callbacks(Box::new(Macros(macros.clone())))
        .allowlist_type("poly1305_state")
        .allowlist_function("(MLDSA|CBS_).*")
        .allowlist_var("MLDSA.*")
        .allowlist_function("(OB_|OPENSSL_|OpenSSL_|CRYPTO_|ERR_|EVP_|BN_|RSA_|DSA_|DH_|EC_|ECDSA_|ECDH_|HMAC_|CMAC_|RAND_|OBJ_|BIO_|PEM_|SMIME_|PKCS|d2i_|i2d_|X509|ASN1_|SSL_|TLS_|DTLS_|OSSL_|FIPS_|sk_|OPENSSL_sk_).*" )
        .allowlist_var("(OPENSSL_|LIBRESSL_|EVP_|NID_|RSA_|EC_|POINT_|ERR_|SSL_|TLS|DTLS|TLSEXT_|BIO_|X509_|PKCS|OSSL_|V_ASN1_).*" )
        .derive_default(false)
        .layout_tests(false)
        .generate_comments(false);
    for include in &includes {
        builder = builder.clang_arg(format!("-I{}", include.display()));
    }
    let bindings = builder
        .generate()
        .expect("generate bindings from the selected backend's headers");
    bindings
        .write_to_file(PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("bindings.rs"))
        .expect("write generated bindings");
    let macros = macros.lock().unwrap();
    // Export numeric compatibility constants using their final preprocessor
    // values. The safe TLS boundary copies values, never native object handles.
    let mut constants = String::from("#include \"wrapper.h\"\nstruct OB_constant { const char *name; int64_t value; };\nstatic const struct OB_constant constants[] = {\n");
    for name in macros.keys().filter(|name| {
        name.as_str() == "SSL3_VERSION"
            || name.starts_with("SSL_")
            || name.starts_with("TLS")
            || name.starts_with("DTLS")
            || name.starts_with("X509_V_")
            || name.starts_with("OPENSSL_")
    }) {
        if name.starts_with("OPENSSL_NO_") {
            continue;
        }
        constants.push_str(&format!(
            "#ifdef {name}\n{{\"{name}\", (int64_t){name}}},\n#endif\n"
        ));
    }
    constants.push_str("};\nsize_t OB_tls_constant_count(void) { return sizeof(constants)/sizeof(constants[0]); }\nconst char *OB_tls_constant_name(size_t i) { return i < OB_tls_constant_count() ? constants[i].name : NULL; }\nint64_t OB_tls_constant_value(size_t i) { return i < OB_tls_constant_count() ? constants[i].value : 0; }\n");
    let constants_path = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("tls_constants.c");
    std::fs::write(&constants_path, constants).expect("write compatibility constants");
    let backend = match macros["OB_BACKEND_CODE"] {
        3 => "awslc",
        2 => "boringssl",
        1 => "libressl",
        0 => "openssl",
        _ => unreachable!(),
    };
    println!("cargo:backend={backend}");
    println!(
        "cargo:include={}",
        env::join_paths(&includes).unwrap().to_str().unwrap()
    );
    match backend {
        "awslc" => println!("cargo:awslc=true"),
        "boringssl" => println!("cargo:boringssl=true"),
        "libressl" => println!(
            "cargo:libressl_version_number={:x}",
            macros["LIBRESSL_VERSION_NUMBER"]
        ),
        _ => println!(
            "cargo:version_number={:x}",
            macros["OPENSSL_VERSION_NUMBER"]
        ),
    }
    if backend == "openssl" {
        println!(
            "cargo:version_number_decimal={}",
            macros["OPENSSL_VERSION_NUMBER"]
        );
    }
    // Headers may define and then undefine compatibility switches. Probe their
    // final state with the target C preprocessor instead of trusting a callback
    // which observes historical definitions (including empty macro definitions).
    let mut probe = String::from("#include \"wrapper.h\"\n");
    for name in macros.keys().filter(|name| name.starts_with("OPENSSL_NO_")) {
        probe.push_str(&format!("#ifdef {name}\nOB_CONF_{name}\n#endif\n"));
    }
    let probe_path = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("configuration.c");
    std::fs::write(&probe_path, probe).expect("write configuration probe");
    let expanded = cc::Build::new()
        .file(&probe_path)
        .include(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .includes(&includes)
        .warnings(false)
        .expand();
    let expanded = String::from_utf8(expanded).expect("C preprocessor output is UTF-8");
    let disabled: Vec<_> = expanded
        .lines()
        .filter_map(|line| line.trim().strip_prefix("OB_CONF_"))
        .collect();
    println!("cargo:conf={}", disabled.join(","));
    cc::Build::new()
        .file("shim.c")
        .file(constants_path)
        .include(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .includes(&includes)
        .warnings(false)
        .compile("openssl_bridge_shim");
    if matches!(backend, "boringssl" | "awslc") && env::var("CARGO_CFG_UNIX").is_ok() {
        if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
            println!("cargo:rustc-link-lib=c++");
        } else {
            println!("cargo:rustc-link-lib=stdc++");
        }
    }
}

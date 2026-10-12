use anyhow::Result;
use clap::{Args, Subcommand};

use crate::config;
use crate::util;

#[derive(Args)]
pub struct CodegenArgs {
    #[command(subcommand)]
    pub target: Option<CodegenTarget>,

    /// Only ensure dependencies are installed, don't run codegen
    #[arg(long)]
    pub ensure_deps_only: bool,
}

#[derive(Subcommand)]
pub enum CodegenTarget {
    /// Regenerate Firecracker API client
    Firecracker,
    /// Regenerate envd HTTP client
    Envd,
    /// Regenerate AENV HTTP server stubs
    Server,
    /// Normalize existing AENV server signatures offline, without running codegen.
    ServerNormalize {
        /// Refuse stale signatures without writing any files.
        #[arg(long)]
        check: bool,
    },
    /// Regenerate custom extension HTTP client
    CustomExtension,
}

/// npm wrapper version for @openapitools/openapi-generator-cli.
/// The actual generator jar version is controlled by openapitools.json in the project root.
const OPENAPI_GENERATOR_CLI_VERSION: &str = "2.32.0";

pub fn run(args: CodegenArgs) -> Result<()> {
    let project_root = config::project_root()?;

    if args.ensure_deps_only {
        let cfg = config::load_config_from_root(&project_root)?;
        // Also ensure protoc
        crate::ensure_tool::ensure_protoc(&cfg.protoc.version, &cfg.protoc.url)?;
        util::info("All codegen dependencies are ready.");
        return Ok(());
    }

    match args.target {
        Some(CodegenTarget::Firecracker) => run_firecracker(&project_root),
        Some(CodegenTarget::Envd) => run_envd(&project_root),
        Some(CodegenTarget::Server) => run_server(&project_root),
        Some(CodegenTarget::ServerNormalize { check }) => {
            normalize_server_apis(&project_root.join("src/api/generated"), check)
        }
        Some(CodegenTarget::CustomExtension) => run_custom_extension(&project_root),
        None => {
            run_firecracker(&project_root)?;
            run_envd(&project_root)?;
            run_server(&project_root)?;
            run_custom_extension(&project_root)?;
            Ok(())
        }
    }
}

/// Regenerate the custom extension HTTP client into
/// `src/custom_extension_api/generated`.
fn run_custom_extension(project_root: &std::path::Path) -> Result<()> {
    let ext_dir = project_root.join("src/custom_extension_api/generated");
    let spec = project_root.join("src/custom_extension_api/openapi.yml");

    util::info("Regenerating custom extension HTTP client...");
    run_openapi_generator(
        project_root,
        &[
            "generate",
            "-i",
            &spec.to_string_lossy(),
            "-g",
            "rust",
            "-o",
            &ext_dir.to_string_lossy(),
            "--additional-properties=packageName=custom_extension_client,hideGenerationTimestamp=true",
            "--skip-validate-spec",
        ],
    )?;

    prepend_allow_attrs(&ext_dir.join("src/lib.rs"))?;
    util::cmd("cargo", &["fmt", "-p", "custom_extension_client"])?;
    util::info("custom extension client generated.");
    Ok(())
}

/// Run openapi-generator-cli via npx.
/// The generator jar version is read from openapitools.json in the project root.
fn run_openapi_generator(project_root: &std::path::Path, args: &[&str]) -> Result<()> {
    let package = format!(
        "@openapitools/openapi-generator-cli@{}",
        OPENAPI_GENERATOR_CLI_VERSION
    );
    let mut cmd_args: Vec<&str> = vec!["--yes", &package, "--"];
    cmd_args.extend_from_slice(args);
    util::cmd_in_dir("npx", &cmd_args, project_root)
}

fn run_firecracker(project_root: &std::path::Path) -> Result<()> {
    let fc_dir = project_root.join("thirdparty/firecracker-client");
    let spec = fc_dir.join("firecracker.yaml");

    util::info("Regenerating Firecracker API client...");
    run_openapi_generator(
        project_root,
        &[
            "generate",
            "-i",
            &spec.to_string_lossy(),
            "-g",
            "rust",
            "-o",
            &fc_dir.to_string_lossy(),
            "--global-property",
            "models,supportingFiles",
            "--additional-properties=packageName=firecracker_client,hideGenerationTimestamp=true",
        ],
    )?;

    prepend_allow_attrs(&fc_dir.join("src/lib.rs"))?;
    util::cmd("cargo", &["fmt", "-p", "firecracker_client"])?;
    util::info("Firecracker client generated.");
    Ok(())
}

fn run_envd(project_root: &std::path::Path) -> Result<()> {
    let envd_dir = project_root.join("thirdparty/envd/http-client");
    let spec = envd_dir.join("envd.yaml");

    util::info("Regenerating envd HTTP client...");
    run_openapi_generator(
        project_root,
        &[
            "generate",
            "-i",
            &spec.to_string_lossy(),
            "-g",
            "rust",
            "-o",
            &envd_dir.to_string_lossy(),
            "--additional-properties=packageName=http_client,hideGenerationTimestamp=true",
            "--skip-validate-spec",
        ],
    )?;

    prepend_allow_attrs(&envd_dir.join("src/lib.rs"))?;
    util::cmd("cargo", &["fmt", "-p", "http_client"])?;
    util::info("envd HTTP client generated.");
    Ok(())
}

fn run_server(project_root: &std::path::Path) -> Result<()> {
    let server_dir = project_root.join("src/api/generated");
    let spec = project_root.join("src/api/openapi.yml");

    util::info("Regenerating AENV HTTP server...");
    run_openapi_generator(
        project_root,
        &[
            "generate",
            "-g",
            "rust-axum",
            "-i",
            &spec.to_string_lossy(),
            "-o",
            &server_dir.to_string_lossy(),
            "--additional-properties=packageName=agentenv_http_server,hideGenerationTimestamp=true",
        ],
    )?;

    // Port of fix_rust_axum_duplicate_auth_trait.py
    let mod_rs = server_dir.join("src/apis/mod.rs");
    fix_duplicate_auth_trait(&mod_rs)?;
    normalize_server_apis(&server_dir, false)?;

    util::cmd("cargo", &["fmt", "-p", "agentenv_http_server"])?;
    util::info("AENV server generated.");
    Ok(())
}

/// Prepend #![allow(clippy::all)] and #![allow(warnings)] to a file if not already present.
fn prepend_allow_attrs(path: &std::path::Path) -> Result<()> {
    let content = std::fs::read_to_string(path)?;
    if content.starts_with("#![allow(clippy::all)]") {
        return Ok(());
    }
    let new_content = format!("#![allow(clippy::all)]\n#![allow(warnings)]\n{content}");
    std::fs::write(path, new_content)?;
    Ok(())
}

/// Port of scripts/fix_rust_axum_duplicate_auth_trait.py
/// Removes duplicate ApiKeyAuthHeader trait blocks from generated code.
fn fix_duplicate_auth_trait(path: &std::path::Path) -> Result<()> {
    use std::sync::LazyLock;

    if !path.exists() {
        anyhow::bail!("file not found: {}", path.display());
    }

    let content = std::fs::read_to_string(path)?;

    static PATTERN: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(concat!(
            r"(?s)/// API Key Authentication - Header\.\r?\n",
            r"\s*#\[async_trait::async_trait\]\r?\n",
            r"\s*pub trait ApiKeyAuthHeader \{\r?\n",
            r"\s+type Claims;\r?\n\r?\n",
            r"\s*/// Extracting Claims from Header\. Return None if the Claims are invalid\.\r?\n",
            r"\s+async fn extract_claims_from_header\(&self, headers: &axum::http::header::HeaderMap, key: &str\) -> Option<Self::Claims>;\r?\n",
            r"\s*\}\r?\n\r?\n"
        ))
        .unwrap()
    });

    let matches: Vec<_> = PATTERN.find_iter(&content).collect();

    if matches.is_empty() {
        anyhow::bail!(
            "ApiKeyAuthHeader trait block not found in {}",
            path.display()
        );
    }

    if matches.len() == 1 {
        util::info(&format!("No duplicate trait blocks in {}", path.display()));
        return Ok(());
    }

    // Keep the first match, remove subsequent duplicates
    let first_end = matches[0].end();
    let before = &content[..first_end];
    let after = PATTERN.replace_all(&content[first_end..], "");
    let deduped = format!("{before}{after}");

    std::fs::write(path, deduped)?;
    util::info(&format!(
        "Removed {} duplicate ApiKeyAuthHeader trait block(s) in {}",
        matches.len() - 1,
        path.display()
    ));
    Ok(())
}

const API_FUTURE_ALIAS: &str = "/// Send future returned by generated object-safe API declarations.\npub type ApiFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;\n\n";
const SERVER_API_FILES: [&str; 6] = [
    "admin",
    "default",
    "sandboxes",
    "snapshots",
    "templates",
    "mod",
];

/// Normalize only the pinned generator's abstract API methods. Implementations
/// and the tracing-instrumented ErrorHandler default remain untouched.
fn normalize_api_source(content: &str, authentication_module: bool) -> Result<String> {
    use std::sync::LazyLock;
    static START: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?m)^[ \t]*(?:unsafe[ \t]+)?async[ \t]+(?:unsafe[ \t]+)?fn[ \t]+([A-Za-z_][A-Za-z0-9_]*)\b",
        )
        .unwrap()
    });
    static SIGNATURE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?s)^    async fn ([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*->\s*([^;{]+)([;{])",
        )
        .unwrap()
    });
    static ARGUMENTS: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"^[A-Za-z0-9_:,\s&<>\[\]]+$").unwrap());
    static RETURN: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"^[A-Za-z0-9_:,\s<>\[\]]+$").unwrap());
    let mut edits = Vec::new();
    for method in START.find_iter(content) {
        let signature = SIGNATURE
            .captures(&content[method.start()..])
            .ok_or_else(|| anyhow::anyhow!("unsupported generated API method syntax"))?;
        let name = &signature[1];
        if &signature[4] == "{" {
            if !authentication_module
                || name != "handle_error"
                || !content[..method.start()]
                    .trim_end()
                    .ends_with("#[tracing::instrument(skip_all)]")
            {
                anyhow::bail!("unsupported generated API default method");
            }
            continue;
        }
        let args = &signature[2];
        let returned = signature[3].trim();
        if !ARGUMENTS.is_match(args)
            || !RETURN.is_match(returned)
            || !args.trim_start().starts_with("&self,")
            || args
                .split_whitespace()
                .any(|word| matches!(word, "dyn" | "impl" | "fn" | "where"))
            || returned
                .split_whitespace()
                .any(|word| matches!(word, "dyn" | "impl" | "fn" | "where"))
        {
            anyhow::bail!("unsupported generated API signature types");
        }
        let mut borrowed = String::new();
        let mut lifetimes = Vec::new();
        for character in args.chars() {
            if character == '&' {
                let lifetime = format!("'life{}", lifetimes.len());
                borrowed.push('&');
                borrowed.push_str(&lifetime);
                borrowed.push(' ');
                lifetimes.push(lifetime);
            } else {
                borrowed.push(character);
            }
        }
        let mut generics = lifetimes.clone();
        generics.push("'async_trait".into());
        let alias = if authentication_module {
            "ApiFuture"
        } else {
            "super::ApiFuture"
        };
        let mut normalized = format!(
            "    fn {name}<{}>({borrowed}) -> {alias}<'async_trait, {returned}>\n    where\n",
            generics.join(", ")
        );
        for lifetime in lifetimes {
            normalized.push_str(&format!("        {lifetime}: 'async_trait,\n"));
        }
        normalized.push_str("        Self: 'async_trait;");
        edits.push((
            method.start(),
            method.start() + signature.get(0).unwrap().end(),
            normalized,
        ));
    }
    let mut result = content.to_owned();
    for (start, end, replacement) in edits.into_iter().rev() {
        result.replace_range(start..end, &replacement);
    }
    if authentication_module && !result.contains("pub type ApiFuture<") {
        result.insert_str(0, API_FUTURE_ALIAS);
    }
    Ok(result)
}

fn normalize_server_apis(server_dir: &std::path::Path, check: bool) -> Result<()> {
    // Parse every file before any write: unsupported generator output leaves the
    // entire generated tree unchanged. Check mode performs no writes or tools.
    let mut changes = Vec::new();
    for name in SERVER_API_FILES {
        let path = server_dir.join(format!("src/apis/{name}.rs"));
        let content = std::fs::read_to_string(&path)?;
        let normalized = normalize_api_source(&content, name == "mod")?;
        if normalized != content {
            changes.push((path, normalized));
        }
    }
    if check && !changes.is_empty() {
        anyhow::bail!("generated API future signatures require offline normalization");
    }
    for (path, normalized) in changes {
        std::fs::write(path, normalized)?;
    }
    Ok(())
}

#[cfg(test)]
mod future_normalization_tests {
    use super::*;
    #[test]
    fn abstract_api_normalization_preserves_separate_borrows_and_generic_result() {
        let input = "#[async_trait]\npub trait Api<E: Send + Sync + 'static>: super::ErrorHandler<E> {\n    async fn get(\n        &self,\n        claims: &Self::Claims,\n        names: &[&str],\n    ) -> Result<Response, E>;\n}\n";
        let result = normalize_api_source(input, false).unwrap();
        assert!(result.contains("fn get<'life0, 'life1, 'life2, 'life3, 'async_trait>"));
        assert!(result.contains("claims: &'life1 Self::Claims"));
        assert!(result.contains("names: &'life2 [&'life3 str]"));
        assert!(result.contains("super::ApiFuture<'async_trait, Result<Response, E>>"));
        assert!(result.contains("pub trait Api<E: Send + Sync + 'static>: super::ErrorHandler<E>"));
        for n in 0..4 {
            assert!(result.contains(&format!("'life{n}: 'async_trait")));
        }
        assert_eq!(normalize_api_source(&result, false).unwrap(), result);
    }
    #[test]
    fn authentication_normalization_preserves_tracing_default_and_is_idempotent() {
        let input = "#[async_trait::async_trait]\npub trait Auth {\n    type Claims;\n    async fn extract(\n        &self,\n        headers: &HeaderMap,\n        key: &str,\n    ) -> Option<Self::Claims>;\n}\n#[async_trait::async_trait]\npub trait ErrorHandler<E: Send + Sync + 'static> {\n    #[allow(unused_variables)]\n    #[tracing::instrument(skip_all)]\n    async fn handle_error(&self, error: E) -> Result<Response, StatusCode> {\n        tracing::error!(\"error: {:?}\", error);\n        response()\n    }\n}\n";
        let result = normalize_api_source(input, true).unwrap();
        assert!(result.starts_with(API_FUTURE_ALIAS));
        assert!(result.contains("ApiFuture<'async_trait, Option<Self::Claims>>"));
        let default = input
            .split("#[async_trait::async_trait]\npub trait ErrorHandler")
            .nth(1)
            .unwrap();
        assert!(result.ends_with(default));
        assert_eq!(normalize_api_source(&result, true).unwrap(), result);
    }
    #[test]
    fn unsupported_generator_signatures_and_defaults_refuse() {
        for input in [
            "    async fn get<T>(&self, arg: &T) -> Result<Response, E>;",
            "  async fn get(&self, arg: &str) -> Result<Response, E>;",
            "    unsafe async fn get(&self, arg: &str) -> Result<Response, E>;",
            "    async unsafe fn get(&self, arg: &str) -> Result<Response, E>;",
            "    async fn get(&self, arg: &'a str) -> Result<Response, E>;",
            "    async fn get(&self, arg: impl Send) -> Result<Response, E>;",
            "    async fn get(&self) -> Result<Response, E> where Self: Sync;",
            "    async fn get(&self, arg: &str) -> Result<Response, E> { response() }",
        ] {
            assert!(normalize_api_source(input, false).is_err());
        }
    }
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn offline_check_and_unsupported_later_file_never_write_earlier_files() {
        let path = std::env::temp_dir().join(format!(
            "adev-api-futures-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        let scratch = Scratch(path);
        std::fs::create_dir_all(scratch.0.join("src/apis")).unwrap();
        let original =
            "pub trait Api {\n    async fn get(&self, key: &str) -> Result<Response, E>;\n}\n";
        for name in SERVER_API_FILES {
            std::fs::write(scratch.0.join(format!("src/apis/{name}.rs")), original).unwrap();
        }
        assert!(normalize_server_apis(&scratch.0, true).is_err());
        assert_eq!(
            std::fs::read_to_string(scratch.0.join("src/apis/admin.rs")).unwrap(),
            original
        );
        let unsupported = "pub trait Api {\n    async unsafe fn get(&self, key: &str) -> Result<Response, E>;\n}\n";
        std::fs::write(scratch.0.join("src/apis/templates.rs"), unsupported).unwrap();
        assert!(normalize_server_apis(&scratch.0, false).is_err());
        assert_eq!(
            std::fs::read_to_string(scratch.0.join("src/apis/admin.rs")).unwrap(),
            original
        );
        std::fs::write(scratch.0.join("src/apis/templates.rs"), original).unwrap();
        normalize_server_apis(&scratch.0, false).unwrap();
        normalize_server_apis(&scratch.0, true).unwrap();
    }
}

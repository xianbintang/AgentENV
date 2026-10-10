//! Check actual vendored C declarations; no Python interpreter is needed.
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn original_mask_failure_and_patched_high_bit_flags() {
    let internal = include_str!(
        "../vendor/tikv-jemalloc-sys/jemalloc/include/jemalloc/internal/jemalloc_internal_types.h"
    );
    let public =
        include_str!("../vendor/tikv-jemalloc-sys/jemalloc/include/jemalloc/jemalloc_macros.h.in");
    let mut definitions = String::new();
    for (source, name) in [
        (internal, "MALLOCX_ARENA_BITS"),
        (internal, "MALLOCX_ARENA_SHIFT"),
        (internal, "MALLOCX_ARENA_MASK"),
        (public, "MALLOCX_ARENA(a)"),
    ] {
        let lines: Vec<_> = source.lines().collect();
        let indexes: Vec<_> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| {
                line.strip_prefix("#define ")
                    .is_some_and(|rest| rest.split_whitespace().next() == Some(name))
            })
            .map(|(i, _)| i)
            .collect();
        assert_eq!(indexes.len(), 1, "{name}");
        let mut i = indexes[0];
        loop {
            definitions.push_str(lines[i]);
            definitions.push('\n');
            if !lines[i].trim_end().ends_with('\\') {
                break;
            }
            i += 1;
        }
    }
    let body = r#"
#include <stdint.h>
int main(void) {
    _Static_assert(sizeof(int) == 4, "32-bit arena flags required");
    volatile unsigned mask = MALLOCX_ARENA_MASK;
    if (mask != UINT32_C(0xfff00000)) return 1;
    const int arenas[] = {-1, 0, 2047, 4094};
    const uint32_t flags[] = {0, UINT32_C(0x00100000), UINT32_C(0x80000000), UINT32_C(0xfff00000)};
    for (unsigned i = 0; i < 4; ++i) {
        volatile int arena = arenas[i];
        if ((uint32_t)MALLOCX_ARENA(arena) != flags[i]) return 2;
    }
    return 0;
}
"#;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("jemalloc-arena-{}-{nonce}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let source = directory.join("flags.c");
    let binary = directory.join("flags");
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    for original in [true, false] {
        let declarations = if original {
            definitions
                .replace("1U << MALLOCX_ARENA_BITS", "1 << MALLOCX_ARENA_BITS")
                .replace("- 1U)", "- 1)")
        } else {
            definitions.clone()
        };
        fs::write(&source, format!("{declarations}{body}")).unwrap();
        assert!(Command::new(&compiler)
            .args([
                "-std=c11",
                "-O0",
                "-fsanitize=undefined",
                "-fno-sanitize-recover=undefined"
            ])
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .status()
            .unwrap()
            .success());
        let result = Command::new(&binary).output().unwrap();
        if original {
            assert!(!result.status.success());
            let diagnostic = String::from_utf8(result.stderr).unwrap();
            assert!(diagnostic.contains("left shift") || diagnostic.contains("shift of"));
        } else {
            assert!(result.status.success());
        }
    }
    fs::remove_file(source).unwrap();
    fs::remove_file(binary).unwrap();
    fs::remove_dir(directory).unwrap();
}

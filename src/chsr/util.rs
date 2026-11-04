use std::fs::DirBuilder;
use std::mem;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::Path;

#[cfg(not(debug_assertions))]
use konst::eq_str;
use nix::sys::stat::Mode;
use pest::{RuleType, error::LineColLocation};

use rootasrole_core::util::escape_parser_string;

#[cfg(not(test))]
pub const RAR_CFG_PATH: &str = env!("RAR_CFG_PATH");
#[cfg(test)]
pub const RAR_CFG_PATH: &str = "target/rootasrole.json";

#[cfg(not(test))]
pub const RAR_CFG_DATA_PATH: &str = env!("RAR_CFG_DATA_PATH");
#[cfg(test)]
pub const RAR_CFG_DATA_PATH: &str = "target/rootasrole.json";

#[cfg(debug_assertions)]
pub const RAR_CFG_IMMUTABLE: bool = false;
#[cfg(not(debug_assertions))]
pub const RAR_CFG_IMMUTABLE: bool = eq_str(env!("RAR_CFG_IMMUTABLE"), "true");

/// The directory of the temporary folders of chsr. In /run, which only root writes and which is
/// emptied at boot: a name in /tmp, which every user writes, can be taken first. Landlock lets chsr
/// remove the directories beneath it, and no other, so that its folder goes at the end.
pub const CHSR_RUN_DIR: &str = "/run/chsr";

/// Create `dir` with mode 0700 when it is missing, and refuse it when it is not a directory of the
/// user that chsr runs as, that only this user opens: chsr makes its temporary folder there.
pub fn secure_dir(dir: &Path) -> std::io::Result<()> {
    match DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let meta = std::fs::symlink_metadata(dir)?;
    if meta.file_type().is_dir()
        && meta.uid() == nix::unistd::geteuid().as_raw()
        && !Mode::from_bits_truncate(meta.mode()).intersects(Mode::S_IRWXG | Mode::S_IRWXO)
    {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} must be a directory that only the user of chsr opens",
                dir.display()
            ),
        ))
    }
}

const fn start<R>(error: &pest::error::Error<R>) -> (usize, usize)
where
    R: RuleType,
{
    match error.line_col {
        LineColLocation::Pos(line_col) => line_col,
        LineColLocation::Span(start_line_col, _) => start_line_col,
    }
}

pub fn underline<R>(error: &pest::error::Error<R>) -> String
where
    R: RuleType,
{
    let mut underline = String::new();

    let mut start = start(error).1;
    let end = match error.line_col {
        LineColLocation::Span(_, (_, mut end)) => {
            let inverted_cols = start > end;
            if inverted_cols {
                mem::swap(&mut start, &mut end);
                start -= 1;
                end += 1;
            }

            Some(end)
        }
        LineColLocation::Pos(_) => None,
    };
    let offset = start - 1;
    let line_chars = error.line().chars();

    for c in line_chars.take(offset) {
        match c {
            '\t' => underline.push('\t'),
            _ => underline.push(' '),
        }
    }

    if let Some(end) = end {
        underline.push('^');
        if end - start > 1 {
            for _ in 2..(end - start) {
                underline.push('-');
            }
            underline.push('^');
        }
    } else {
        underline.push_str("^---");
    }

    underline
}

pub fn escape_parser_string_vec<S, I>(s: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    s.into_iter()
        .map(|s| escape_parser_string(s))
        .collect::<Vec<String>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pest::error::{Error, ErrorVariant};

    // Simple rule type for testing - pest provides a blanket implementation
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    enum TestRule {}

    // the directory of the temporary folders is made with mode 0700, and refused when others may
    // open it, or when it is a link or a file
    #[test]
    fn test_secure_dir() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let base = std::env::temp_dir().join(format!("rar_secure_dir_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir(&base).unwrap();
        let dir = base.join("run");
        assert!(secure_dir(&dir).is_ok());
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert!(secure_dir(&dir).is_ok());
        let link = base.join("link");
        symlink(&dir, &link).unwrap();
        assert!(secure_dir(&link).is_err());
        let file = base.join("file");
        std::fs::write(&file, b"").unwrap();
        assert!(secure_dir(&file).is_err());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(secure_dir(&dir).is_err());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_underline_with_pos() {
        let input = "hello world";
        let error = Error::<TestRule>::new_from_pos(
            ErrorVariant::CustomError {
                message: "test error".to_string(),
            },
            pest::Position::new(input, 6).unwrap(),
        );

        let result = underline(&error);
        // Should have 6 spaces followed by ^---
        assert_eq!(result, "      ^---");
    }

    #[test]
    fn test_underline_with_span() {
        let input = "hello world";
        let error = Error::<TestRule>::new_from_span(
            ErrorVariant::CustomError {
                message: "test error".to_string(),
            },
            pest::Span::new(input, 6, 11).unwrap(), // "world"
        );

        let result = underline(&error);
        // Should have 6 spaces, then ^ followed by 3 dashes, then ^
        assert_eq!(result, "      ^---^");
    }

    #[test]
    fn test_underline_with_span_single_char() {
        let input = "hello world";
        let error = Error::<TestRule>::new_from_span(
            ErrorVariant::CustomError {
                message: "test error".to_string(),
            },
            pest::Span::new(input, 6, 7).unwrap(), // single char "w"
        );

        let result = underline(&error);
        // Should have 6 spaces followed by single ^
        assert_eq!(result, "      ^");
    }

    #[test]
    fn test_underline_with_tabs() {
        let input = "\t\thello world";
        let error = Error::<TestRule>::new_from_pos(
            ErrorVariant::CustomError {
                message: "test error".to_string(),
            },
            pest::Position::new(input, 8).unwrap(), // "world" position
        );

        let result = underline(&error);
        // Should preserve tabs in the underline
        assert_eq!(result, "\t\t      ^---");
    }

    #[test]
    fn test_underline_at_beginning() {
        let input = "hello world";
        let error = Error::<TestRule>::new_from_pos(
            ErrorVariant::CustomError {
                message: "test error".to_string(),
            },
            pest::Position::new(input, 0).unwrap(), // beginning
        );

        let result = underline(&error);
        // Should start with ^--- immediately
        assert_eq!(result, "^---");
    }

    #[test]
    fn test_escape_parser_string_vec_empty() {
        let result = escape_parser_string_vec(std::iter::empty::<String>());
        assert_eq!(result, "");
    }

    #[test]
    fn test_escape_parser_string_vec_single() {
        let input = vec!["hello"];
        let result = escape_parser_string_vec(input);
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_escape_parser_string_vec_multiple() {
        let input = vec!["hello", "world", "test"];
        let result = escape_parser_string_vec(input);
        assert_eq!(result, "hello world test");
    }

    #[test]
    fn test_escape_parser_string_vec_with_quotes() {
        let input = vec!["\"hello\"", "'world'", "test"];
        let result = escape_parser_string_vec(input);
        // The escape_parser_string function should remove quotes
        assert_eq!(result, "hello world test");
    }

    #[test]
    fn test_escape_parser_string_vec_with_nested_quotes() {
        let input = vec!["\"'hello'\"", "\"test\""];
        let result = escape_parser_string_vec(input);
        // Should recursively remove outer quotes
        assert_eq!(result, "hello test");
    }

    #[test]
    fn test_escape_parser_string_vec_different_types() {
        // Test with different string types that implement AsRef<str>
        let input = vec!["hello".to_string(), "world".to_string()];
        let result = escape_parser_string_vec(input);
        assert_eq!(result, "hello world");

        // Test with mixed str references
        let input = vec!["hello", "world"];
        let result = escape_parser_string_vec(input);
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_start_with_pos() {
        let input = "hello world";
        let error = Error::<TestRule>::new_from_pos(
            ErrorVariant::CustomError {
                message: "test error".to_string(),
            },
            pest::Position::new(input, 6).unwrap(),
        );

        let (line, col) = start(&error);
        assert_eq!(line, 1); // pest uses 1-based line numbers
        assert_eq!(col, 7); // pest uses 1-based column numbers, position 6 = column 7
    }

    #[test]
    fn test_start_with_span() {
        let input = "hello world";
        let error = Error::<TestRule>::new_from_span(
            ErrorVariant::CustomError {
                message: "test error".to_string(),
            },
            pest::Span::new(input, 6, 11).unwrap(),
        );

        let (line, col) = start(&error);
        assert_eq!(line, 1); // pest uses 1-based line numbers
        assert_eq!(col, 7); // pest uses 1-based column numbers
    }
}

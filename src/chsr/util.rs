use std::mem;

use pest::{error::LineColLocation, RuleType};

use rar_common::util::escape_parser_string;

fn start<R>(error: &pest::error::Error<R>) -> (usize, usize)
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
        _ => None,
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
        underline.push_str("^---")
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

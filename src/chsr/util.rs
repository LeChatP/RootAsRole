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

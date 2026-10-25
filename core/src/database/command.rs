//! How a command of the policy is written: its path, then its arguments, which may be a
//! regular expression. dosr matches the commands and chsr writes them, both read them here.

/// The path of a command of the policy and its arguments, both as written.
///
/// The path keeps its quotes, and a regular expression must not go through shell splitting,
/// which removes its backslashes and splits it on its spaces.
#[must_use]
pub fn split_command(line: &str) -> Option<(&str, &str)> {
    let line = line.trim_start();
    let first = line.chars().next()?;
    let path_end = if first == '\'' || first == '"' {
        line[1..].find(first)? + 2
    } else {
        line.find(char::is_whitespace).unwrap_or(line.len())
    };
    Some((&line[..path_end], &line[path_end..]))
}

/// The regular expression of the arguments of a command of the policy, as written after its
/// path: arguments starting with `^` and ending with `$`, single-quoted or not.
#[must_use]
pub fn regex_arguments(args: &str) -> Option<&str> {
    let args = args.trim();
    let args = args
        .strip_prefix('\'')
        .and_then(|quoted| quoted.strip_suffix('\''))
        .filter(|quoted| quoted.starts_with('^') && quoted.ends_with('$'))
        .unwrap_or(args);
    (args.len() >= 2 && args.starts_with('^') && args.ends_with('$')).then_some(args)
}

/// The body of the regular expression of the arguments, between its `^` and its final `$`. A
/// final `\$` is a dollar sign, not the end of the arguments, and stays in the body.
#[must_use]
pub fn regex_body(regex: &str) -> &str {
    let body = regex.strip_prefix('^').unwrap_or(regex);
    match body.strip_suffix('$') {
        Some(stripped) if !ends_with_an_escape(stripped) => stripped,
        _ => body,
    }
}

/// The regular expression of the arguments, anchored at both ends whatever its alternations.
///
/// `^start|stop$` alone is `^start` or `stop$`, which allows any arguments that start with
/// `start` or end with `stop`.
#[must_use]
pub fn anchored_regex(regex: &str) -> String {
    format!("^(?:{})$", regex_body(regex))
}

/// Whether `body` has a `|` outside of any group and character class.
///
/// It is the alternation that `^…$` does not anchor on both sides.
#[must_use]
pub fn has_top_level_alternation(body: &str) -> bool {
    let (mut groups, mut classes) = (0usize, 0usize);
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '[' => {
                classes += 1;
                // a `]` right after `[` or `[^` is a bracket, not the end of the class
                chars.next_if_eq(&'^');
                chars.next_if_eq(&']');
            }
            ']' if classes > 0 => classes -= 1,
            '(' if classes == 0 => groups += 1,
            ')' if classes == 0 => groups = groups.saturating_sub(1),
            '|' if classes == 0 && groups == 0 => return true,
            _ => {}
        }
    }
    false
}

fn ends_with_an_escape(text: &str) -> bool {
    text.chars().rev().take_while(|&c| c == '\\').count() % 2 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_command() {
        assert_eq!(
            split_command("/usr/bin/tail ^-n [0-9]+$"),
            Some(("/usr/bin/tail", " ^-n [0-9]+$"))
        );
        assert_eq!(
            split_command("  '/opt/my tool' -v"),
            Some(("'/opt/my tool'", " -v"))
        );
        assert_eq!(
            split_command("\"/opt/my tool\""),
            Some(("\"/opt/my tool\"", ""))
        );
        assert_eq!(split_command("/usr/bin/id"), Some(("/usr/bin/id", "")));
        assert_eq!(split_command(""), None);
        // an unterminated quote is not a path
        assert_eq!(split_command("'/usr/bin/id"), None);
    }

    #[test]
    fn test_anchored_regex() {
        assert_eq!(anchored_regex("^start|stop$"), "^(?:start|stop)$");
        assert_eq!(anchored_regex("^-n [0-9]+$"), "^(?:-n [0-9]+)$");
        assert_eq!(anchored_regex("^$"), "^(?:)$");
        // an escaped dollar sign is part of the body
        assert_eq!(regex_body("^price \\$"), "price \\$");
        assert_eq!(anchored_regex("^price \\$"), "^(?:price \\$)$");
        // an escaped backslash before the final $ does not escape it
        assert_eq!(regex_body("^a\\\\$"), "a\\\\");
    }

    #[test]
    fn test_has_top_level_alternation() {
        for body in [
            "start|stop",
            "(?i)start|stop",
            "a(b|c)|d",
            "[a-z]|x",
            "\\(|x",
        ] {
            assert!(has_top_level_alternation(body), "{body}");
        }
        for body in [
            "(start|stop)",
            "(?:start|stop) now",
            "[|]",
            "[]|]",
            "[^]|]",
            "[[:alpha:]|]+",
            "a\\|b",
            "-n [0-9]+",
            "",
        ] {
            assert!(!has_top_level_alternation(body), "{body}");
        }
    }

    #[test]
    fn test_regex_arguments() {
        assert_eq!(
            regex_arguments(" ^(-n [0-9]+|-f) /var/log/caddy/[^/ ]+$"),
            Some("^(-n [0-9]+|-f) /var/log/caddy/[^/ ]+$")
        );
        assert_eq!(regex_arguments(" '^-f a\\.log$' "), Some("^-f a\\.log$"));
        assert_eq!(regex_arguments("^$"), Some("^$"));
        assert_eq!(regex_arguments(" --no-pager -u caddy"), None);
        assert_eq!(regex_arguments("^"), None);
        // what chsr wrote before 4.2.0: every word quoted on its own
        assert_eq!(regex_arguments(" '^(-n' '[0-9]+|-f)'"), None);
    }
}

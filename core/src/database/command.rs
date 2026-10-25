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

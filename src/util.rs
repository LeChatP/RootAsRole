use capctl::{Cap, CapSet, ParseCapError};
use tracing::warn;

pub fn capset_to_string(set: &CapSet) -> String {
    set.iter()
        .fold(String::new(), |mut acc, cap| {
            acc.push_str(&format!("CAP_{:?} ", cap));
            acc
        })
        .trim_end()
        .to_string()
}

pub fn capset_to_vec(set: &CapSet) -> Vec<String> {
    set.iter().map(|cap| cap.to_string()).collect()
}

//parse string iterator to capset
pub fn parse_capset_iter<'a, I>(iter: I) -> Result<CapSet, ParseCapError>
where
    I: Iterator<Item = &'a str>,
{
    let mut res = CapSet::empty();

    for part in iter {
        match part.parse() {
            Ok(cap) => res.add(cap),
            Err(error) => {
                return Err(error);
            }
        }
    }
    Ok(res)
}

pub fn parse_capset(s: &str) -> Result<CapSet, ParseCapError> {
    if s.is_empty() || s.eq_ignore_ascii_case("all") {
        return Ok(!CapSet::empty() & capctl::bounding::probe());
    }

    parse_capset_iter(s.split(' '))
}

/// Reference every capabilities that lead to almost a direct privilege escalation
pub fn capabilities_are_exploitable(caps: &CapSet) -> bool {
    caps.has(Cap::SYS_ADMIN)
        || caps.has(Cap::SYS_PTRACE)
        || caps.has(Cap::SYS_MODULE)
        || caps.has(Cap::DAC_READ_SEARCH)
        || caps.has(Cap::DAC_OVERRIDE)
        || caps.has(Cap::FOWNER)
        || caps.has(Cap::CHOWN)
        || caps.has(Cap::SETUID)
        || caps.has(Cap::SETGID)
        || caps.has(Cap::SETFCAP)
        || caps.has(Cap::SYS_RAWIO)
        || caps.has(Cap::LINUX_IMMUTABLE)
        || caps.has(Cap::SYS_CHROOT)
        || caps.has(Cap::SYS_BOOT)
        || caps.has(Cap::MKNOD)
}

#[cfg(test)]
pub(super) mod test {
    pub fn test_resources_folder() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("resources")
    }
    pub fn test_resources_file(filename: &str) -> String {
        test_resources_folder().join(filename).display().to_string()
    }
}

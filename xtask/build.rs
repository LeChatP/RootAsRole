use std::env;
use serde_json::Value;
use serde_json::Map;

const RAR_CFG_PATH: &str = "/etc/security/rootasrole.json";
const RAR_CFG_IMMUTABLE: bool = true;
const RAR_TIMEOUT_TYPE: &str = "PPID";
const RAR_TIMEOUT_DURATION: &str = "00:05:00";
const RAR_PATH_DEFAULT: &str = "delete";
const RAR_PATH_ADD_LIST: &[&str] = &[
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    "/snap/bin",
];
const RAR_PATH_REMOVE_LIST: &[&str] = &[""];
const RAR_ENV_DEFAULT: &str = "delete";
const RAR_ENV_KEEP_LIST: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "COLORS",
    "DISPLAY",
    "HOSTNAME",
    "KRB5CCNAME",
    "LS_COLORS",
    "PS1",
    "PS2",
    "XAUTHORY",
    "XAUTHORIZATION",
    "XDG_CURRENT_DESKTOP",
];
const RAR_ENV_CHECK_LIST: &[&str] = &[
    "COLORTERM",
    "LANG",
    "LANGUAGE",
    "LC_.*",
    "LINGUAS",
    "TERM",
    "TZ",
];
const RAR_ENV_DELETE_LIST: &[&str] = &[
    "PS4",
    "SHELLOPTS",
    "PERLLIB",
    "PERL5LIB",
    "PERL5OPT",
    "PYTHONINSPECT",
];
const RAR_ENV_SET_LIST: &[(&str, &str)] = &[];
const RAR_ENV_OVERRIDE_BEHAVIOR: &str = "false";
const RAR_AUTHENTICATION: &str = "perform";
const RAR_USER_CONSIDERED: &str = "user";
const RAR_BOUNDING: &str = "strict";
const RAR_WILDCARD_DENIED: &str = ";&|";

fn config_env() {
    println!(
        "cargo:rustc-env=RAR_CFG_PATH={}",
        env::var("RAR_CFG_PATH").unwrap_or_else(|_| RAR_CFG_PATH.to_string())
    );

    println!(
        "cargo:rustc-env=RAR_CFG_IMMUTABLE={}",
        env::var("RAR_CFG_IMMUTABLE").unwrap_or_else(|_| RAR_CFG_IMMUTABLE.to_string())
    );
    println!(
        "cargo:rustc-env=RAR_TIMEOUT_TYPE={}",
        env::var("RAR_TIMEOUT_TYPE").unwrap_or_else(|_| RAR_TIMEOUT_TYPE.to_string())
    );
    println!(
        "cargo:rustc-env=RAR_TIMEOUT_DURATION={}",
        env::var("RAR_TIMEOUT_DURATION").unwrap_or_else(|_| RAR_TIMEOUT_DURATION.to_string())
    );
    println!(
        "cargo:rustc-env=RAR_PATH_DEFAULT={}",
        env::var("RAR_PATH_DEFAULT").unwrap_or_else(|_| RAR_PATH_DEFAULT.to_string())
    );
    println!(
        "cargo:rustc-env=RAR_PATH_ADD_LIST={}",
        env::var("RAR_PATH_ADD_LIST").unwrap_or_else(|_| RAR_PATH_ADD_LIST.join(","))
    );
    println!(
        "cargo:rustc-env=RAR_PATH_REMOVE_LIST={}",
        env::var("RAR_PATH_REMOVE_LIST").unwrap_or_else(|_| RAR_PATH_REMOVE_LIST.join(","))
    );
    println!(
        "cargo:rustc-env=RAR_ENV_DEFAULT={}",
        env::var("RAR_ENV_DEFAULT").unwrap_or_else(|_| RAR_ENV_DEFAULT.to_string())
    );
    println!(
        "cargo:rustc-env=RAR_ENV_KEEP_LIST={}",
        env::var("RAR_ENV_KEEP_LIST").unwrap_or_else(|_| RAR_ENV_KEEP_LIST.join(","))
    );
    println!(
        "cargo:rustc-env=RAR_ENV_CHECK_LIST={}",
        env::var("RAR_ENV_CHECK_LIST").unwrap_or_else(|_| RAR_ENV_CHECK_LIST.join(","))
    );
    println!(
        "cargo:rustc-env=RAR_ENV_DELETE_LIST={}",
        env::var("RAR_ENV_DELETE_LIST").unwrap_or_else(|_| RAR_ENV_DELETE_LIST.join(","))
    );

    println!(
        "cargo:rustc-env=RAR_ENV_SET_LIST={}",
        env::var("RAR_ENV_SET_LIST").unwrap_or_else(|_| serde_json::to_string(&RAR_ENV_SET_LIST.iter().map(|(k,v)| {(k.to_string(), Value::String(v.to_string()))}).collect::<Map<String,Value>>()).unwrap())
    );
    println!(
        "cargo:rustc-env=RAR_ENV_OVERRIDE_BEHAVIOR={}",
        env::var("RAR_ENV_OVERRIDE_BEHAVIOR")
            .unwrap_or_else(|_| RAR_ENV_OVERRIDE_BEHAVIOR.to_string())
    );
    println!(
        "cargo:rustc-env=RAR_AUTHENTICATION={}",
        env::var("RAR_AUTHENTICATION").unwrap_or_else(|_| RAR_AUTHENTICATION.to_string())
    );
    println!(
        "cargo:rustc-env=RAR_USER_CONSIDERED={}",
        env::var("RAR_USER_CONSIDERED").unwrap_or_else(|_| RAR_USER_CONSIDERED.to_string())
    );
    println!(
        "cargo:rustc-env=RAR_BOUNDING={}",
        env::var("RAR_BOUNDING").unwrap_or_else(|_| RAR_BOUNDING.to_string())
    );
    println!(
        "cargo:rustc-env=RAR_WILDCARD_DENIED={}",
        env::var("RAR_WILDCARD_DENIED").unwrap_or_else(|_| RAR_WILDCARD_DENIED.to_string())
    );
}

fn main() {
    config_env();
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=build.rs");
}
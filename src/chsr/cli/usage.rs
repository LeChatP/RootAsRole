use std::{error::Error, fmt::Write};

use log::debug;

use super::data::Rule;
use crate::util::underline;
use rar_common::util::{BOLD, RED, RST, UNDERLINE};

const LONG_ABOUT: &str = "
chsr allows you to manage RootAsRole policies through a command-line interface.
The main idea in this CLI is to provide individual commands for each operation
and use a consistent syntax for options management across different levels 
(global, role, task).
";

#[derive(Debug, Clone, Copy)]
struct UsageItem {
    name: &'static str,
    description: &'static str,
    indent: usize,
}

#[derive(Debug, Clone, Copy)]
struct UsageSection {
    title: &'static str,
    synopsis: &'static [&'static str],
    items: &'static [UsageItem],
    examples: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UsageSectionId {
    Usage,
    Commands,
    Role,
    Task,
    Command,
    Credentials,
    CredentialsCaps,
    OptionsGeneral,
    OptionsPath,
    OptionsWorkdir,
    OptionsEnv,
    OptionsTimeout,
    OptionsAuth,
    OptionsExecinfo,
    OptionsUmask,
    Listing,
    Convert,
}

const USAGE_GENERAL: UsageSection = UsageSection {
    title: "Usage",
    synopsis: &["chsr [command] [options]"],
    items: &[],
    examples: &[],
};

const USAGE_COMMANDS: UsageSection = UsageSection {
    title: "Commands",
    synopsis: &[],
    items: &[
        UsageItem {
            name: "-h, --help",
            description: "Show help for commands and options.",
            indent: 1,
        },
        UsageItem {
            name: "list, show, l",
            description: "List available items; use with specific commands for detailed views.",
            indent: 1,
        },
        UsageItem {
            name: "role, r",
            description: "Manage roles and related operations.",
            indent: 1,
        },
    ],
    examples: &["chsr --help", "chsr list"],
};

const USAGE_ROLE: UsageSection = UsageSection {
    title: "Role Operations",
    synopsis: &["chsr role [role_name] [operation] [options]"],
    items: &[
        UsageItem {
            name: "add, create",
            description: "Add a new role.",
            indent: 1,
        },
        UsageItem {
            name: "del, delete, unset, d, rm",
            description: "Delete a specified role.",
            indent: 1,
        },
        UsageItem {
            name: "show, list, l",
            description: "Show details of a specified role (actors, tasks, all).",
            indent: 1,
        },
        UsageItem {
            name: "purge",
            description: "Remove all items from a role (actors, tasks, all).",
            indent: 1,
        },
        UsageItem {
            name: "grant",
            description: "Grant permissions to a user or group.",
            indent: 1,
        },
        UsageItem {
            name: "revoke",
            description: "Revoke permissions from a user or group.",
            indent: 1,
        },
        UsageItem {
            name: "-u, --user [user_name]",
            description: "Specify a user for grant or revoke operations.",
            indent: 2,
        },
        UsageItem {
            name: "-g, --group [group_names]",
            description: "Specify one or more group combinations for grant or revoke operations.",
            indent: 2,
        },
    ],
    examples: &["chsr role admin add", "chsr role admin grant -u alice"],
};

const USAGE_TASK: UsageSection = UsageSection {
    title: "Task Operations",
    synopsis: &["chsr role [role_name] task [task_name] [operation]"],
    items: &[
        UsageItem {
            name: "show, list, l",
            description: "Show task details (all, cmd, cred).",
            indent: 1,
        },
        UsageItem {
            name: "purge",
            description: "Purge configurations or credentials of a task (all, cmd, cred).",
            indent: 1,
        },
        UsageItem {
            name: "add, create",
            description: "Add a new task.",
            indent: 1,
        },
        UsageItem {
            name: "del, delete, unset, d, rm",
            description: "Remove a task.",
            indent: 1,
        },
    ],
    examples: &[
        "chsr role admin task backup add",
        "chsr role admin task backup show",
    ],
};

const USAGE_COMMAND: UsageSection = UsageSection {
    title: "Command Operations",
    synopsis: &["chsr role [role_name] task [task_name] command [cmd]"],
    items: &[
        UsageItem {
            name: "show",
            description: "Show commands.",
            indent: 1,
        },
        UsageItem {
            name: "setpolicy [policy]",
            description: "Set policy for commands (allow-all, deny-all).",
            indent: 1,
        },
        UsageItem {
            name: "whitelist, wl [listing]",
            description: "Manage the whitelist for commands.",
            indent: 1,
        },
        UsageItem {
            name: "blacklist, bl [listing]",
            description: "Manage the blacklist for commands.",
            indent: 1,
        },
    ],
    examples: &["chsr role admin task backup command setpolicy allow-all"],
};

const USAGE_CREDENTIALS: UsageSection = UsageSection {
    title: "Credentials Operations",
    synopsis: &["chsr role [role_name] task [task_name] credentials [operation]"],
    items: &[
        UsageItem {
            name: "show",
            description: "Show credentials.",
            indent: 1,
        },
        UsageItem {
            name: "set, unset",
            description: "Set or unset credentials details.",
            indent: 1,
        },
        UsageItem {
            name: "caps",
            description: "Manage capabilities for credentials.",
            indent: 1,
        },
    ],
    examples: &["chsr role admin task backup credentials show"],
};

const USAGE_CREDENTIALS_CAPS: UsageSection = UsageSection {
    title: "Capabilities Operations",
    synopsis: &["chsr role [role_name] task [task_name] credentials caps [operation]"],
    items: &[
        UsageItem {
            name: "setpolicy [policy]",
            description: "Set policy for capabilities (allow-all, deny-all).",
            indent: 1,
        },
        UsageItem {
            name: "whitelist, wl [listing]",
            description: "Manage whitelist for credentials.",
            indent: 1,
        },
        UsageItem {
            name: "blacklist, bl [listing]",
            description: "Manage blacklist for credentials.",
            indent: 1,
        },
    ],
    examples: &["chsr role admin task backup credentials caps whitelist add cap_net_raw"],
};

const USAGE_OPTIONS_GENERAL: UsageSection = UsageSection {
    title: "Options",
    synopsis: &[
        "chsr options [option] [operation]",
        "chsr role [role_name] options [option] [operation]",
        "chsr role [role_name] task [task_name] options [option] [operation]",
    ],
    items: &[
        UsageItem {
            name: "path",
            description: "Manage path settings (set, whitelist, blacklist).",
            indent: 1,
        },
        UsageItem {
            name: "workdir, w",
            description: "Manage workdir settings (set, whitelist, blacklist).",
            indent: 1,
        },
        UsageItem {
            name: "env",
            description: "Manage environment variable settings (set, whitelist, blacklist, checklist).",
            indent: 1,
        },
        UsageItem {
            name: "root [policy]",
            description: "Defines when root gets privileges (unset, privileged, user, inherit).",
            indent: 1,
        },
        UsageItem {
            name: "bounding [policy]",
            description: "Defines how dropped capabilities are handled (unset, strict, ignore, inherit).",
            indent: 1,
        },
        UsageItem {
            name: "timeout",
            description: "Manage timeout settings (set, unset).",
            indent: 1,
        },
        UsageItem {
            name: "authentication [policy]",
            description: "Defines if user needs to authenticate (unset, skip, perform, inherit).",
            indent: 1,
        },
        UsageItem {
            name: "execinfo [policy]",
            description: "Defines if user can see execution settings (unset, display, hide, inherit).",
            indent: 1,
        },
        UsageItem {
            name: "umask, mask [del|umask]",
            description: "Defines the umask for executed command (unset or 022).",
            indent: 1,
        },
    ],
    examples: &["chsr options path show", "chsr role admin options env show"],
};

const USAGE_OPTIONS_PATH: UsageSection = UsageSection {
    title: "Path options",
    synopsis: &["chsr options path [operation]"],
    items: &[
        UsageItem {
            name: "setpolicy [policy]",
            description: "Specify the policy to use.",
            indent: 1,
        },
        UsageItem {
            name: "set [path]",
            description: "Enforce the specified path.",
            indent: 1,
        },
        UsageItem {
            name: "whitelist, wl [listing]",
            description: "Manage the whitelist settings.",
            indent: 1,
        },
        UsageItem {
            name: "blacklist, bl [listing]",
            description: "Manage the blacklist settings.",
            indent: 1,
        },
    ],
    examples: &[
        "chsr options path setpolicy keep-safe",
        "chsr options path whitelist add /usr/bin:/bin",
    ],
};

const USAGE_OPTIONS_WORKDIR: UsageSection = UsageSection {
    title: "Workdir options",
    synopsis: &["chsr options workdir [operation]"],
    items: &[
        UsageItem {
            name: "setpolicy [policy]",
            description: "Specify the policy for workdir settings (all, none, inherit).",
            indent: 1,
        },
        UsageItem {
            name: "set [path]",
            description: "Set the working directory path.",
            indent: 1,
        },
        UsageItem {
            name: "whitelist, wl [listing]",
            description: "Manage the whitelist for workdir settings.",
            indent: 1,
        },
        UsageItem {
            name: "blacklist, bl [listing]",
            description: "Manage the blacklist for workdir settings.",
            indent: 1,
        },
    ],
    examples: &[
        "chsr options workdir setpolicy none",
        "chsr options workdir set /home/user",
    ],
};

const USAGE_OPTIONS_ENV: UsageSection = UsageSection {
    title: "Environment options",
    synopsis: &["chsr options env [operation]"],
    items: &[
        UsageItem {
            name: "setpolicy [policy]",
            description: "Specify the policy for environment settings (delete-all, keep-all, inherit).",
            indent: 1,
        },
        UsageItem {
            name: "set [key=value,...]",
            description: "Set variables to enforce.",
            indent: 1,
        },
        UsageItem {
            name: "keep-only [key,...]",
            description: "Set policy as delete-all and key map to keep.",
            indent: 1,
        },
        UsageItem {
            name: "delete-only [key,...]",
            description: "Set policy as keep-all and key map to delete.",
            indent: 1,
        },
        UsageItem {
            name: "whitelist, wl [listing]",
            description: "Manage the whitelist for environment settings.",
            indent: 1,
        },
        UsageItem {
            name: "blacklist, bl [listing]",
            description: "Manage the blacklist for environment settings.",
            indent: 1,
        },
        UsageItem {
            name: "checklist, cl [listing]",
            description: "Manage checklist for environment settings (removed if unsafe).",
            indent: 1,
        },
        UsageItem {
            name: "setlist, sl [listing]",
            description: "Manage the setlist for environment settings.",
            indent: 1,
        },
    ],
    examples: &[
        "chsr options env setpolicy keep-all",
        "chsr options env keep-only PATH,HOME",
    ],
};

const USAGE_OPTIONS_TIMEOUT: UsageSection = UsageSection {
    title: "Timeout options",
    synopsis: &["chsr options timeout [operation]"],
    items: &[
        UsageItem {
            name: "set, unset",
            description: "Set or unset timeout settings.",
            indent: 1,
        },
        UsageItem {
            name: "--type [tty, ppid, uid]",
            description: "Specify the type of timeout.",
            indent: 2,
        },
        UsageItem {
            name: "--duration [HH:MM:SS]",
            description: "Specify the duration of the timeout.",
            indent: 2,
        },
        UsageItem {
            name: "--max-usage [number]",
            description: "Specify the maximum usage of the timeout.",
            indent: 2,
        },
    ],
    examples: &["chsr options timeout set --type tty --duration 00:05:00 --max-usage 3"],
};

const USAGE_OPTIONS_AUTH: UsageSection = UsageSection {
    title: "Authentication options",
    synopsis: &["chsr options authentication [policy]"],
    items: &[
        UsageItem {
            name: "skip",
            description: "Skip authentication.",
            indent: 1,
        },
        UsageItem {
            name: "perform",
            description: "Perform authentication.",
            indent: 1,
        },
        UsageItem {
            name: "unset",
            description: "Reset authentication behavior.",
            indent: 1,
        },
    ],
    examples: &["chsr options authentication skip"],
};

const USAGE_OPTIONS_EXECINFO: UsageSection = UsageSection {
    title: "Execution info options",
    synopsis: &["chsr options execinfo [policy]"],
    items: &[
        UsageItem {
            name: "show",
            description: "Display execution settings.",
            indent: 1,
        },
        UsageItem {
            name: "hide",
            description: "Hide execution settings.",
            indent: 1,
        },
        UsageItem {
            name: "unset",
            description: "Reset execution info behavior.",
            indent: 1,
        },
    ],
    examples: &["chsr options execinfo hide"],
};

const USAGE_OPTIONS_UMASK: UsageSection = UsageSection {
    title: "Umask options",
    synopsis: &["chsr options umask [value]"],
    items: &[
        UsageItem {
            name: "del",
            description: "Unset umask.",
            indent: 1,
        },
        UsageItem {
            name: "0000-0777",
            description: "Set umask value (octal).",
            indent: 1,
        },
    ],
    examples: &["chsr options umask 022", "chsr options umask del"],
};

const USAGE_LISTING: UsageSection = UsageSection {
    title: "Listing",
    synopsis: &[],
    items: &[
        UsageItem {
            name: "add [items,...]",
            description: "Add items to the list.",
            indent: 1,
        },
        UsageItem {
            name: "del [items,...]",
            description: "Remove items from the list.",
            indent: 1,
        },
        UsageItem {
            name: "set [items,...]",
            description: "Set items in the list.",
            indent: 1,
        },
        UsageItem {
            name: "purge",
            description: "Remove all items from the list.",
            indent: 1,
        },
    ],
    examples: &["chsr options env whitelist add PATH,HOME"],
};

const USAGE_CONVERT: UsageSection = UsageSection {
    title: "Convert policy format",
    synopsis: &[
        "chsr convert (-r) (--from [from_type] [from_file]) [to_type] [to_file]",
        "Supported types: json, cbor",
        "Warning: the new location should be under a protected directory.",
    ],
    items: &[
        UsageItem {
            name: "-r, --reconfigure",
            description: "Reconfigure /etc/security/rootasrole.json to specify the new location.",
            indent: 1,
        },
        UsageItem {
            name: "--from [from_type] [from_file]",
            description: "Specify the type and file to convert from.",
            indent: 1,
        },
    ],
    examples: &["chsr convert --from json /etc/security/rootasrole.json cbor /tmp/rar.cbor"],
};

const fn usage_section(id: UsageSectionId) -> &'static UsageSection {
    match id {
        UsageSectionId::Usage => &USAGE_GENERAL,
        UsageSectionId::Commands => &USAGE_COMMANDS,
        UsageSectionId::Role => &USAGE_ROLE,
        UsageSectionId::Task => &USAGE_TASK,
        UsageSectionId::Command => &USAGE_COMMAND,
        UsageSectionId::Credentials => &USAGE_CREDENTIALS,
        UsageSectionId::CredentialsCaps => &USAGE_CREDENTIALS_CAPS,
        UsageSectionId::OptionsGeneral => &USAGE_OPTIONS_GENERAL,
        UsageSectionId::OptionsPath => &USAGE_OPTIONS_PATH,
        UsageSectionId::OptionsWorkdir => &USAGE_OPTIONS_WORKDIR,
        UsageSectionId::OptionsEnv => &USAGE_OPTIONS_ENV,
        UsageSectionId::OptionsTimeout => &USAGE_OPTIONS_TIMEOUT,
        UsageSectionId::OptionsAuth => &USAGE_OPTIONS_AUTH,
        UsageSectionId::OptionsExecinfo => &USAGE_OPTIONS_EXECINFO,
        UsageSectionId::OptionsUmask => &USAGE_OPTIONS_UMASK,
        UsageSectionId::Listing => &USAGE_LISTING,
        UsageSectionId::Convert => &USAGE_CONVERT,
    }
}

fn render_section(section: &UsageSection) -> String {
    let mut output = String::new();
    let _ = writeln!(
        output,
        "{UNDERLINE}{BOLD}{}:{RST}",
        section.title,
        UNDERLINE = UNDERLINE,
        BOLD = BOLD,
        RST = RST
    );
    for line in section.synopsis {
        output.push_str(line);
        output.push('\n');
    }
    let mut max_name_len = 0usize;
    for item in section.items {
        let len = item.name.chars().count();
        if len > max_name_len {
            max_name_len = len;
        }
    }
    for item in section.items {
        let indent = "  ".repeat(item.indent);
        let padding = if max_name_len > item.name.chars().count() {
            " ".repeat(max_name_len - item.name.chars().count())
        } else {
            String::new()
        };
        let _ = writeln!(
            output,
            "{}{}{}{}{}  {}",
            indent, BOLD, item.name, RST, padding, item.description
        );
    }
    if !section.examples.is_empty() {
        let _ = writeln!(output, "{BOLD}Examples:{RST}");
        for example in section.examples {
            let _ = writeln!(output, "  {example}");
        }
    }
    output
}

fn render_usage(sections: &[UsageSectionId]) -> String {
    let mut usage = String::new();
    for (index, section) in sections.iter().enumerate() {
        usage.push_str(&render_section(usage_section(*section)));
        if index + 1 < sections.len() {
            usage.push('\n');
        }
    }
    usage
}

pub fn help() {
    debug!("chsr help");
    println!("{LONG_ABOUT}");
    println!(
        "{}",
        render_usage(&[UsageSectionId::Usage, UsageSectionId::Commands])
    );
}

fn rule_to_string(rule: Rule) -> String {
    match rule {
        Rule::EOI => "no more input",
        Rule::args => "role, options, timeout or --help",
        Rule::opt_timeout_operations => "timeout set/unset operations",
        Rule::opt_timeout_d_arg => "--duration (hh:mm:ss)",
        Rule::opt_timeout_t_arg => "--type (tty, ppid, uid)",
        Rule::opt_timeout_m_arg => "--max-usage (\\d+)",
        Rule::roles_operations => "roles list/purge/add/del operations or existing role name",
        Rule::role_type_arg => "all, actors or tasks",
        Rule::role_grant_revoke => "grant, revoke",
        Rule::role_show_purge => "show, purge",
        Rule::task_keyword => "task",
        Rule::task_id => "task identifier",
        Rule::command_operations => "cmd",
        Rule::credentials_operations => "cred",
        Rule::cmd_checklisting | Rule::opt_path_listing | Rule::opt_workdir_listing => {
            "whitelist, blacklist"
        }
        Rule::cmd_policy => "allow-all or deny-all",
        Rule::cmd | Rule::cli => "a command line",
        Rule::cred_c => "--caps \"cap_net_raw, cap_sys_admin, ...\"",
        Rule::cred_g => "--group \"g1,g2\"",
        Rule::cred_u => "--user \"u1\"",
        Rule::cred_caps_operations => "caps",
        Rule::list => "show, list, l",
        Rule::opt_timeout => "timeout",
        Rule::opt_path | Rule::path => "path",
        Rule::opt_env => "env",
        Rule::opt_workdir => "workdir",
        Rule::opt_root => "root",
        Rule::opt_bounding => "bounding",
        Rule::opt_skip_auth => "authentication",
        Rule::opt_execinfo => "execinfo",
        Rule::opt_mask => "umask",
        Rule::help => "--help",
        Rule::set => "set",
        Rule::setpolicy => "setpolicy",
        Rule::opt_env_listing => "whitelist, blacklist, checklist",
        Rule::opt_workdir_args => "setpolicy, set, whitelist, blacklist",
        Rule::convert => "convert",
        Rule::convert_type => "json or cbor",
        Rule::convert_args => "--from, -r, --reconfigure or file_type",
        Rule::convert_reconfigure => "-r or --reconfigure",
        Rule::to => "[to_type] [to_file]",
        Rule::from => "[from_type] [from_file]",
        Rule::workdir_policy => "all, none, inherit",
        Rule::env_policy => "delete-all, keep-all, inherit",
        Rule::path_policy => "delete-all, keep-safe, keep-unsafe, inherit",
        Rule::options_operations => "options",
        Rule::add => "add",
        Rule::del => "del",
        Rule::purge => "purge",
        _ => {
            println!("{rule:?}");
            "unknown rule"
        }
    }
    .to_string()
}

const DEFAULT_USAGE_SECTIONS: &[UsageSectionId] = &[
    UsageSectionId::Usage,
    UsageSectionId::Commands,
    UsageSectionId::Role,
    UsageSectionId::Task,
    UsageSectionId::Command,
    UsageSectionId::Credentials,
    UsageSectionId::Convert,
];

const OPTIONS_GENERAL_SECTIONS: &[UsageSectionId] = &[UsageSectionId::OptionsGeneral];
const OPTIONS_AUTH_SECTIONS: &[UsageSectionId] = &[UsageSectionId::OptionsAuth];
const OPTIONS_EXECINFO_SECTIONS: &[UsageSectionId] = &[UsageSectionId::OptionsExecinfo];
const OPTIONS_UMASK_SECTIONS: &[UsageSectionId] = &[UsageSectionId::OptionsUmask];
const OPTIONS_TIMEOUT_SECTIONS: &[UsageSectionId] = &[UsageSectionId::OptionsTimeout];
const OPTIONS_PATH_SECTIONS: &[UsageSectionId] = &[UsageSectionId::OptionsPath];
const OPTIONS_WORKDIR_SECTIONS: &[UsageSectionId] = &[UsageSectionId::OptionsWorkdir];
const OPTIONS_ENV_SECTIONS: &[UsageSectionId] = &[UsageSectionId::OptionsEnv];
const CREDENTIALS_CAPS_SECTIONS: &[UsageSectionId] =
    &[UsageSectionId::CredentialsCaps, UsageSectionId::Listing];
const COMMAND_LISTING_SECTIONS: &[UsageSectionId] =
    &[UsageSectionId::Command, UsageSectionId::Listing];
const PATH_LISTING_SECTIONS: &[UsageSectionId] =
    &[UsageSectionId::OptionsPath, UsageSectionId::Listing];
const ENV_LISTING_SECTIONS: &[UsageSectionId] =
    &[UsageSectionId::OptionsEnv, UsageSectionId::Listing];
const CONVERT_SECTIONS: &[UsageSectionId] = &[UsageSectionId::Convert];

const fn usage_sections_for_rule(rule: Rule) -> Option<&'static [UsageSectionId]> {
    match rule {
        Rule::options_operations
        | Rule::opt_args
        | Rule::opt_show
        | Rule::opt_show_arg
        | Rule::opt_root
        | Rule::opt_root_args
        | Rule::opt_bounding
        | Rule::opt_bounding_args => Some(OPTIONS_GENERAL_SECTIONS),
        Rule::opt_skip_auth | Rule::opt_skip_auth_args => Some(OPTIONS_AUTH_SECTIONS),
        Rule::opt_execinfo | Rule::opt_execinfo_args => Some(OPTIONS_EXECINFO_SECTIONS),
        Rule::opt_mask | Rule::opt_mask_args => Some(OPTIONS_UMASK_SECTIONS),
        Rule::opt_timeout
        | Rule::opt_timeout_operations
        | Rule::opt_timeout_d_arg
        | Rule::opt_timeout_t_arg
        | Rule::opt_timeout_m_arg => Some(OPTIONS_TIMEOUT_SECTIONS),
        Rule::opt_path
        | Rule::opt_path_args
        | Rule::opt_path_set
        | Rule::opt_path_setpolicy
        | Rule::path_policy
        | Rule::path => Some(OPTIONS_PATH_SECTIONS),
        Rule::opt_workdir
        | Rule::opt_workdir_args
        | Rule::workdir_policy
        | Rule::opt_workdir_listing => Some(OPTIONS_WORKDIR_SECTIONS),
        Rule::opt_env
        | Rule::opt_env_args
        | Rule::opt_env_setpolicy
        | Rule::env_policy
        | Rule::opt_env_set
        | Rule::env_key_list
        | Rule::env_value_list
        | Rule::env_key => Some(OPTIONS_ENV_SECTIONS),
        Rule::caps_listing => Some(CREDENTIALS_CAPS_SECTIONS),
        Rule::cmd_checklisting => Some(COMMAND_LISTING_SECTIONS),
        Rule::opt_path_listing => Some(PATH_LISTING_SECTIONS),
        Rule::opt_env_listing => Some(ENV_LISTING_SECTIONS),
        Rule::convert => Some(CONVERT_SECTIONS),
        _ => None,
    }
}

pub fn print_usage(e: pest::error::Error<Rule>) -> Result<bool, Box<dyn Error>> {
    let mut usage = render_usage(DEFAULT_USAGE_SECTIONS);
    let e = e.renamed_rules(|rule| {
        if let Some(next_sections) = usage_sections_for_rule(*rule) {
            usage = render_usage(next_sections);
        }
        rule_to_string(*rule)
    });
    println!("{usage}");
    println!(
        "{RED}{BOLD}Unrecognized command line:\n| {RST}{}{RED}{BOLD}\n| {}\n= {}{RST}",
        e.line(),
        underline(&e),
        e.variant.message(),
        RED = RED,
        BOLD = BOLD,
        RST = RST
    );
    Err(Box::new(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_env_listing_to_env_and_listing_sections() {
        assert_eq!(
            usage_sections_for_rule(Rule::opt_env_listing),
            Some(ENV_LISTING_SECTIONS)
        );
    }

    #[test]
    fn maps_authentication_to_auth_section() {
        assert_eq!(
            usage_sections_for_rule(Rule::opt_skip_auth),
            Some(OPTIONS_AUTH_SECTIONS)
        );
    }

    #[test]
    fn maps_timeout_rules_to_timeout_section() {
        assert_eq!(
            usage_sections_for_rule(Rule::opt_timeout_m_arg),
            Some(OPTIONS_TIMEOUT_SECTIONS)
        );
    }

    #[test]
    fn returns_none_for_unknown_rule() {
        assert_eq!(usage_sections_for_rule(Rule::EOI), None);
    }
}

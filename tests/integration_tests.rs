mod helpers;

#[cfg(test)]
mod tests {
    use pcre2::bytes::RegexBuilder;
    use serial_test::serial;

    use crate::helpers::get_test_runner;

    #[test]
    #[serial]
    fn test_dosr_help() {
        let runner = get_test_runner().expect("Failed to setup test environment");
        let result = runner
            .run_dosr(&["--help"])
            .call()
            .expect("Failed to run dosr --help");

        assert!(result.success, "Command failed: {}", result.stderr);
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("Usage:"));
    }

    #[test]
    #[serial]
    fn test_dosr_version() {
        let runner = get_test_runner().expect("Failed to setup test environment");
        let result = runner
            .run_dosr(&["--version"])
            .call()
            .expect("Failed to run dosr --version");

        assert!(result.success, "Command failed: {}", result.stderr);
        assert!(result
            .stdout
            .contains(&env!("CARGO_PKG_VERSION").to_string()));
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    #[serial]
    fn test_dosr_role_selection() {
        let runner = get_test_runner().expect("Failed to setup test environment");
        let result = runner
            .run_dosr(&["--role", "B", "env"])
            .fixture_name("tests/fixtures/multi_role.json")
            .call()
            .expect("Failed to run dosr with invalid role");
        assert!(
            result.success,
            "Command unexpectedly failed: {}",
            result.stderr
        );
        assert!(result.stdout.contains("ROLE=B"));
        assert!(result.stdout.contains("TASK=B_A"));
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    #[serial]
    fn test_dosr_task_selection() {
        let runner = get_test_runner().expect("Failed to setup test environment");
        let result = runner
            .run_dosr(&["--role", "A", "--task", "A_B", "env"])
            .fixture_name("tests/fixtures/multi_role.json")
            .call()
            .expect("Failed to run dosr with invalid task");
        assert!(
            result.success,
            "Command unexpectedly failed: {}",
            result.stderr
        );
        assert!(result.stdout.contains("ROLE=A"));
        assert!(result.stdout.contains("TASK=A_B"));
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    #[serial]
    fn test_dosr_invalid_role() {
        let runner = get_test_runner().expect("Failed to setup test environment");
        let result = runner
            .run_dosr(&["--role", "C", "env"])
            .fixture_name("tests/fixtures/multi_role.json")
            .call()
            .expect("Failed to run dosr with invalid role");
        assert!(!result.success, "Command unexpectedly succeeded");
        assert!(!result.stdout.contains("ROLE="));
        assert!(!result.stdout.contains("TASK="));
        assert!(result.stderr.contains("Permission denied"));
        assert_eq!(result.exit_code, 1);
    }

    #[test]
    #[serial]
    fn test_dosr_env_override() {
        let runner = get_test_runner().expect("Failed to setup test environment");
        let result = runner
            .run_dosr(&["-E", "--role", "env", "--task", "allowed", "env"])
            .fixture_name("tests/fixtures/env_override.json")
            .env_vars(&[
                ("KEEP", ""),
                ("TZ", "Europe/Paris"),
                ("DELETE", ""),
                ("FOO", "BAR"),
            ])
            .call()
            .expect("Failed to run dosr with env override");
        assert!(
            result.success,
            "Command unexpectedly failed: {}",
            result.stderr
        );
        assert!(result.stdout.contains("FOO=BAR"));
        assert!(result.stdout.contains("KEEP="));
        assert!(result.stdout.contains("TZ=Europe/Paris"));
        assert!(!result.stdout.contains("DELETE="));
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    #[serial]
    fn test_dosr_env_override_not_overriden() {
        let runner = get_test_runner().expect("Failed to setup test environment");
        let result = runner
            .run_dosr(&["--role", "env", "--task", "allowed", "env"])
            .fixture_name("tests/fixtures/env_override.json")
            .env_vars(&[
                ("KEEP", ""),
                ("TZ", "Europe/Paris"),
                ("DELETE", ""),
                ("FOO", "BAR"),
            ])
            .call()
            .expect("Failed to run dosr with env override");
        assert!(
            result.success,
            "Command unexpectedly failed: {}",
            result.stderr
        );
        assert!(!result.stdout.contains("FOO=BAR"));
        assert!(result.stdout.contains("KEEP="));
        assert!(result.stdout.contains("TZ=Europe/Paris"));
        assert!(!result.stdout.contains("DELETE="));
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    #[serial]
    fn test_dosr_env_override_denied() {
        let runner = get_test_runner().expect("Failed to setup test environment");
        let result = runner
            .run_dosr(&["-E", "--role", "env", "--task", "denied", "env"])
            .fixture_name("tests/fixtures/env_override.json")
            .env_vars(&[
                ("KEEP", ""),
                ("TZ", "Europe/Paris"),
                ("DELETE", ""),
                ("FOO", "BAR"),
            ])
            .call()
            .expect("Failed to run dosr with env override");
        assert!(!result.success, "Command unexpectedly succeeded");
        assert!(!result.stdout.contains("FOO=BAR"));
        assert!(!result.stdout.contains("KEEP="));
        assert!(!result.stdout.contains("TZ=Europe/Paris"));
        assert!(!result.stdout.contains("DELETE="));
        assert!(result.stderr.contains("Permission denied"));
        assert_eq!(result.exit_code, 1);
    }

    #[test]
    #[serial]
    fn test_dosr_env_override_denied_not_overriden() {
        let runner = get_test_runner().expect("Failed to setup test environment");
        let result = runner
            .run_dosr(&["--role", "env", "--task", "denied", "env"])
            .fixture_name("tests/fixtures/env_override.json")
            .env_vars(&[
                ("KEEP", ""),
                ("TZ", "Europe/Paris"),
                ("DELETE", ""),
                ("FOO", "BAR"),
            ])
            .call()
            .expect("Failed to run dosr with env override");
        assert!(
            result.success,
            "Command unexpectedly failed: {}",
            result.stderr
        );
        assert!(!result.stdout.contains("FOO=BAR"));
        assert!(result.stdout.contains("KEEP="));
        assert!(result.stdout.contains("TZ=Europe/Paris"));
        assert!(!result.stdout.contains("DELETE="));
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    #[serial]
    fn test_dosr_as_user() {
        let runner = get_test_runner().expect("Failed to setup test environment");
        let result = runner
            .run_dosr(&["-u", "nobody", "id"])
            .fixture_name("tests/fixtures/user_group.json")
            .users(&["nobody"])
            .call()
            .expect("Failed to run dosr -u nobody id");

        assert!(result.success, "Command failed: {}", result.stderr);
        assert!(result.stdout.contains("uid=65534(nobody)"));
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    #[serial]
    fn test_dosr_as_group() {
        let runner = get_test_runner().expect("Failed to setup test environment");
        let result = runner
            .run_dosr(&["-g", "nobody", "id"])
            .fixture_name("tests/fixtures/user_group.json")
            .users(&["nobody"])
            .groups(&["nobody"])
            .call()
            .expect("Failed to run dosr -u nobody id");
        if !result.success {
            eprintln!("stderr: {}", result.stderr);
            println!("stdout: {}", result.stdout);
        }
        assert!(result.success, "Command failed: {}", result.stderr);
        let re_gid = RegexBuilder::new().build(r"gid=\d+\(nobody\)").unwrap();
        assert!(re_gid.is_match(result.stdout.as_bytes()).is_ok_and(|b| b));
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    #[serial]
    fn test_dosr_as_user_and_group() {
        let runner = get_test_runner()
            .inspect_err(|e| eprintln!("Failed to setup test environment: {}", e))
            .unwrap();
        let result = runner
            .run_dosr(&["-u", "nobody", "-g", "daemon,nobody", "id"])
            .users(&["nobody"])
            .groups(&["nobody", "daemon"])
            .fixture_name("tests/fixtures/user_group.json")
            .env_vars(&[("LANG", "en_US")])
            .call()
            .inspect_err(|e| eprintln!("Failed to run dosr -u nobody -g daemon,nobody id: {}", e))
            .unwrap();
        if !result.success {
            eprintln!("stderr: {}", result.stderr);
            println!("stdout: {}", result.stdout);
        }
        assert!(result.success, "Command failed: {}", result.stderr);
        let re_gid = RegexBuilder::new().build(r"gid=\d+\(daemon\)").unwrap();
        let re_groups = RegexBuilder::new()
            .build(r"groups=\d+\(daemon\),\d+\(nobody\)")
            .unwrap();
        assert!(
            re_gid.is_match(result.stdout.as_bytes()).is_ok_and(|b| b),
            "stdout: {}",
            result.stdout
        );
        assert!(
            re_groups
                .is_match(result.stdout.as_bytes())
                .is_ok_and(|b| b),
            "stdout: {}",
            result.stdout
        );
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    #[serial]
    fn test_dosr_auth() {
        if env!("RAR_PAM_SERVICE") == "dosr" {
            println!("Skipping test_dosr_auth because RAR_PAM_SERVICE is set to original dosr");
            return;
        }
        let runner = get_test_runner().expect("Failed to setup test environment");
        let result = runner
            .run_dosr(&["/usr/bin/true"])
            .fixture_name("tests/fixtures/perform_auth.json")
            .call()
            .expect("Failed to run dosr with auth role");
        assert!(
            result.success,
            "Command unexpectedly failed: {}",
            result.stderr
        );
        assert_eq!(result.exit_code, 0);
        // assert that a timestamp cookie was created
        let path = std::path::Path::new("/var/run/rar/ts").join("0");
        assert!(path.exists(), "Timestamp cookie was not created");
        // run dosr -K to delete the timestamp cookie
        let result = runner
            .run_dosr(&["-K"])
            .fixture_name("tests/fixtures/perform_auth.json")
            .call()
            .expect("Failed to run dosr with auth role");
        assert!(
            result.success,
            "Command unexpectedly failed: {}",
            result.stderr
        );
        assert_eq!(result.exit_code, 0);
        assert!(!path.exists(), "Timestamp cookie was not deleted");
    }

    #[test]
    #[serial]
    fn test_dosr_info() {
        let runner = get_test_runner().expect("Failed to setup test environment");
        let result = runner
            .run_dosr(&["--info", "-r", "A", "cat", "/proc/self/status"])
            .fixture_name("tests/fixtures/multi_role.json")
            .call()
            .expect("Failed to run dosr --info");
        assert!(result.success, "Command failed: {}", result.stderr);
        // it must print execution info, not executing the command
        assert!(!result.stdout.contains("CapEff"));
        assert!(result.stdout.contains("Role: A"));
        // this also tests that not writing a absolute path in the policy is not a valid command.
        assert!(result.stdout.contains("Task: A_B"));
        assert!(result
            .stdout
            .contains("Execute as user: root (0) and group(s): root (0)"));
        assert!(result
            .stdout
            .contains("With capabilities: CAP_DAC_OVERRIDE"));
        assert_eq!(result.exit_code, 0);
    }
}

# Performance Evaluation and Optimisation

Infrastructure-as-code environments can generate large and complex privilege policies. Tools such as Ansible rely heavily on privilege escalation through `become: true`.

With RaR policies, every role and task can introduce additional access control rules. In large infrastructures, this can result in thousands of policy entries being evaluated during production operations. Therefore, the privilege evaluation engine must scale efficiently.

> Update for 4.2.0 of the performance evaluation is co-written with Claude for correctness.

## How it is measured

The measures are performed with the dedicated [RaR-perf](https://github.com/LeChatP/RaR-perf) repository. Each tool runs `/usr/bin/true` as root, without a password, with a policy of N rules where only the last rule allows the command. [hyperfine](https://github.com/sharkdp/hyperfine) measures the time of each run. Since a remark from reddit, 4.2.0 evaluations verifies the `/usr/bin/true` performance too for completeness.

The tools do not do the same work for the same rule: sudo and dosr (since 4.0) run the PAM account and session stacks, even when they ask no password, while doas and `please` do not call PAM when they ask no password. A comparison shows how much each design costs.

After some thoughts, run0 is not in the figures. Its rules aren't read at each run: polkitd loads them once, and keep it loaded in memory, while the other tools read their policy each time. Its numbers would not measure the same work. That said, the time to make a dbus call is significantly slower than reading a policy of 10000 tasks.
Another point is : polkit's run0 rules has no idea about what command is being executed as input. So that makes the comparison not even feasible.

## The first implementation

The initial implementation of the policy engine revealed a scalability challenge. It was measured in April 2025, while 3.1.0 was in development, when dosr was still named `sr`. The first JSON-based policy engine was faster than sudo for small policies, but its execution time increased significantly as the number of tasks grew.

![Performance degradation of the initial JSON-based policy engine (sr, 3.1.0 in development) as policy size increases from 1 to 90 tasks.](https://github.com/LeChatP/RaR-perf/raw/main/figures/25-04-16_sudo-sr-json/result.png)

As shown above, the initial implementation suffered from poor scalability. While it performed well with small policies, the execution time quickly surpassed sudo as policy size increased, making it unsuitable for large-scale deployments.

### Moving from JSON to CBOR

The first optimization focused on the policy storage format. JSON is human-readable and convenient, but parsing large JSON documents introduces unnecessary overhead. To reduce this cost, dosr introduced support for Compact Binary Object Representation (CBOR), a binary format designed for efficient serialization and parsing, and completely compatible with the JSON structure.

![Limited performance gain after switching to CBOR, showing the underlying scalability issue persists as policy size increases to 400 tasks (time in seconds).](https://github.com/LeChatP/RaR-perf/raw/main/figures/25-04-16_sudo-sr-cbor/result.png)

Although CBOR reduced part of the parsing overhead, the improvement remained limited. The performance curve continued to increase significantly with policy size, demonstrating that file parsing was only one part of the problem. The main bottleneck was located deeper in the policy evaluation architecture.

### Architectural Optimisation

The next optimization phase focused on the complete execution path of dosr. Instead of only improving the policy format, the internal architecture was redesigned to remove unnecessary overhead.

The main improvements included:

- reducing redundant memory allocations;
- improving internal data structures;
- streamlining policy loading and evaluation;
- optimizing rule matching and execution paths.

These changes, combined with the CBOR policy format, resulted in a significant improvement in both execution time and scalability.

![Scalability of the optimized engine (sr, 3.1.0 in development, with CBOR and architectural improvements) and of sudo, benchmarked up to 10,000 tasks in July 2025.](https://github.com/LeChatP/RaR-perf/raw/main/figures/25-07-04_sudo-sr/result.png)

In July 2025, just before the release of 3.1.0, this engine ran 77% faster than sudo for a single-rule policy, and its execution time grew approximately 40% slower than sudo's as the policy grew.

<blockquote class="caroot">
Do you see these very straight lines compared to the previous ones? This is because we changed the way to way to plot the data. Instead of using a some arbitrary increase (e.g., 100, 200, 300), we used a logarithmic increase.
</blockquote>

## From 3.1.0 to 4.1.0

These numbers were not measured again for the releases that followed. In October 2026, every version was built again and measured on the same virtual machine, with the same policy:

| version | one rule | each additional rule |
|---|---|---|
| 3.1.0 | 5.4 ms | 1.9 µs |
| 4.0.0 | 13.9 ms | 2.5 µs |
| 4.0.2 | 14.4 ms | 2.5 µs |
| 4.1.0 | 11.7 ms | 13.4 µs |
| 4.2.0 | 9.4 ms | 2.3 µs |

![The versions of RootAsRole from 3.1.0 to 4.2.0 (rar-dev), measured in October 2026 with the same policy, from 1 to 10,000 tasks.](https://github.com/LeChatP/RaR-perf/raw/main/figures/26-10-27_versions/result.png)

In this figure, `rar-dev` is 4.2.0, just before its release.

**The time of a single rule grew with PAM.** Since 4.0.0, dosr runs the whole PAM transaction even for a task that skips the authentication: it starts PAM, checks the account, sets the credentials, then opens and closes a session. 3.1.0 did not call PAM at all for such a task. The account check is what refuses an account that has expired, or that may not log in at this hour; sudo runs it too for a `NOPASSWD` rule. This cost is therefore kept, as a security choice. Measured commit by commit, it added about 5 ms to a run. Part of it comes from `pam_unix`, which starts its `unix_chkpwd` helper to read the account, because dosr runs as the user with file capabilities instead of being setuid root. The rest of the difference, about 1.5 ms during 3.2 and 1 ms at the end of 4.0, was not traced to a single commit.

**The cost of each rule grew with patterns.** In 4.1.0, the command paths of the policy that contain wildcards were fixed: they never matched before (commit `1c3084f`). The fix matches them with globset patterns. But it compiled every command path of the policy as a pattern, even a path without any wildcard, which costs about 10 µs for each command of each task. In the same release, other changes made a run with a single rule about 2.7 ms faster.

## RootAsRole 4.2.0

4.2.0 now implement performance indicators unit tests, ignored by default, that print the cost of one task, so that a change can be measured before and after it:

```sh
cargo test --release --all-features --lib -- --ignored --nocapture --test-threads=1 finder::tests::perf
```

With 4.2.0, a run with one rule takes 9.4 ms, and each additional rule costs 2.3 µs. More than half of a run is the PAM transaction, which a timing probe measured at about 5.6 ms.

The other tools, measured the same way on the same machine:

![dosr 4.2.0, sudo, doas and please, from 1 to 10,000 rules, measured in October 2026.](https://github.com/LeChatP/RaR-perf/raw/main/figures/26-10-27_tools/result.png)

| tool | one rule | 10,000 rules | each additional rule |
|---|---|---|---|
| dosr 4.2.0 | 9.4 ms | 30.1 ms | 2.1 µs |
| sudo 1.9.17 | 10.5 ms | 41.1 ms | 3.0 µs |
| doas 6.4 | 2.0 ms | 186 ms | 18.4 µs |
| please 0.5.6 | 5.3 ms | 1,675 ms | 167 µs |

`/usr/bin/true` alone takes 0.7 ms. With one rule, most of the time of dosr and sudo is the PAM transaction, which doas and please programs do not run when they ask no password. As the policy grows, the cost of each rule depends on how the tool reads and compares its rules. The policy of this figure is written by confgen, and the one of the versions by genpol, which is why the numbers of dosr differ slightly between the two.

## Large-Scale Automation

This scalability improvement is particularly important in automation environments.

Tools such as Ansible frequently invoke privilege escalation through `become: true` configuration option. With RaR, every role and task can introduce additional access control rules, potentially resulting in thousands of policy entries on a single system.

The benchmark results show that this additional security granularity does not introduce a proportional performance cost. With 4.2.0, a policy of 10,000 tasks adds about 21 ms to a run.

This enables administrators to define significantly more precise privilege policies while maintaining operational efficiency.

## Comparison with sudo-rs

For comparison, **sudo-rs** provides performance comparable to sudo in standard scenarios. However, its implementation shows a hardcoded limit of 100 rules.

## Future Improvements

One potential direction is the integration of a SQLite-based policy backend. The RBAC model of RaR map to relational data structures. A relational database could provide additional advantages as we could do efficient indexing as an example.

The figures of the first engine were measured in 2025, with the scripts of that time. @@billo2025

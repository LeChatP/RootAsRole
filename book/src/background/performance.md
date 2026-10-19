# Performance Evaluation and Optimisation

Infrastructure-as-code environments can generate large and complex privilege policies. Tools such as Ansible rely heavily on privilege escalation through `become: true`.

With RaR policies, every role and task can introduce additional access control rules. In large infrastructures, this can result in thousands of policy entries being evaluated during production operations. Therefore, the privilege evaluation engine must scale efficiently.

The initial implementation of dosr revealed a scalability challenge. The first JSON-based policy engine was faster than sudo for small policies, but its execution time increased significantly as the number of tasks grew.

![Performance degradation of the initial JSON-based dosr implementation as policy size increases from 1 to 100 tasks.](https://github.com/LeChatP/RaR-perf/raw/main/before_json_result.png)

As shown above, the initial implementation suffered from poor scalability. While it performed well with small policies, the execution time quickly surpassed sudo as policy size increased, making it unsuitable for large-scale deployments.

## Moving from JSON to CBOR

The first optimization focused on the policy storage format. JSON is human-readable and convenient, but parsing large JSON documents introduces unnecessary overhead. To reduce this cost, dosr introduced support for Compact Binary Object Representation (CBOR), a binary format designed for efficient serialization and parsing, and completely compatible with the JSON structure.

![Limited performance gain after switching to CBOR, showing the underlying scalability issue persists as policy size increases to 400 tasks.](https://github.com/LeChatP/RaR-perf/raw/main/before_cbor_result.png)

Although CBOR reduced part of the parsing overhead, the improvement remained limited. The performance curve continued to increase significantly with policy size, demonstrating that file parsing was only one part of the problem. The main bottleneck was located deeper in the policy evaluation architecture.

## Architectural Optimisation

The next optimization phase focused on the complete execution path of dosr. Instead of only improving the policy format, the internal architecture was redesigned to remove unnecessary overhead.

The main improvements included:

- reducing redundant memory allocations;
- improving internal data structures;
- streamlining policy loading and evaluation;
- optimizing rule matching and execution paths.

These changes, combined with the CBOR policy format, resulted in a significant improvement in both execution time and scalability.

![Final scalability comparison showing the fully optimized dosr (with CBOR and architectural improvements) vastly outperforming sudo at scale, benchmarked up to 10,000 tasks.](https://github.com/LeChatP/RaR-perf/raw/main/result_25-07-04_15.44.png)

The optimized dosr engine now outperforms sudo by up to 77% for a single-rule policy. More importantly, its execution time scales linearly and grows approximately 40% slower than sudo, maintaining a performance advantage even with policies containing tens of thousands of tasks.

<blockquote class="caroot">
Do you see these very straight lines compared to the previous ones? This is because we changed the way to way to plot the data. Instead of using a some arbitrary increase (e.g., 100, 200, 300), we used a logarithmic increase.
</blockquote>

## Large-Scale Automation

This scalability improvement is particularly important in automation environments.

Tools such as Ansible frequently invoke privilege escalation through `become: true` configuration option. With RaR, every role and task can introduce additional access control rules, potentially resulting in thousands of policy entries on a single system.

The benchmark results show that this additional security granularity does not introduce a proportional performance cost. The optimized dosr engine can reach the execution time of a single sudo rule while evaluating approximately 4,000 RaR rules.

This enables administrators to define significantly more precise privilege policies while maintaining operational efficiency.

## Comparison with sudo-rs

For comparison, **sudo-rs** provides performance comparable to sudo in standard scenarios. However, its implementation shows a hardcoded limit of 100 rules.

## Future Improvements

One potential direction is the integration of a SQLite-based policy backend. The RBAC model of RaR map to relational data structures. A relational database could provide additional advantages as we could do efficient indexing as an example.

The benchmarks presented above were performed in July 2025. Since then, additional performance optimisations have been implemented across the codebase, improving internal execution paths and reducing overhead further.
 @@billo2025

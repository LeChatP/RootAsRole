# Performance

<blockquote class="caroot-stare">
This section needs rewriting.
</blockquote>

RootAsRole **3.1.0** introduced **CBOR** support, significantly boosting performance:

- ⚡ **77% faster** than `sudo` when using a single rule
- 📈 **Scales 40% better** than `sudo` as more rules are added

[![Performance comparison](https://github.com/LeChatP/RaR-perf/raw/main/result_25-07-04_15.44.png)](https://github.com/LeChatP/RaR-perf)

> 📝 sudo-rs matches sudo performance but crashes with >100 rules ([won’t fix for now](https://github.com/trifectatechfoundation/sudo-rs/issues/1192))

## Why it Matters

When using **Ansible** (or any automation tool), every task that uses `become: true` will invoke `dosr` on the target host.
With **RootAsRole (RaR)**, each role and task introduces additional access control logic.

💡 You can reach the performance of **1 `sudo` rule** with **~4000 RaR rules**.

That means:
- You can define thousands of fine-grained rules
- You **enforce better security** (POLP) without degrading performance
- The system stays **fast, even at scale**
# Architecture Overview

## Binaries

- `dosr`: policy lookup, authentication flow, and command execution uner a restricted context.
- `chsr`: policy editing and conversion interface.
- `capable`: policy discovery, available [in its own repository](https://github.com/LeChatP/RootAsRole-capable).
- `gensr`: fully automated policy generation, available [in its own repository](https://github.com/LeChatP/RootAsAnsible)

## Internal crates

- `rar-common`: shared policy model, storage handling, migrations, utility logic.
- `rar-exec`: execution pipeline primitives (runner, terminal/pty, pipe, signals).

<blockquote class="caroot">
Did you know that there are two approaches for secure execution?
<ul>
<li>
The openBSD one is about calling execve() directly for minimal code implementation. Less features, more robust is the software.
</li>
<li>
The sudo one is about adding a intermediary process in order to oversee the communication between user and privileged process.
</li>
</ul>
The version 4.0 of RaR is switching from the first to second design! We believe that the risk taken by implementation error is worth the security feature to protect against innapropriate user inputs.
</blockquote>

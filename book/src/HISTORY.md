# The RootAsRole history

## 1.0 (2018)

RootAsRole initiated by SIERA IRIT CNRS research team with Ahmad Samer WAZAN as owner of the proof of concept. It is presented for the first time at "Le capitole du libre" in Toulouse. A paper is published@@wazanRootAsRoleSecureAlternative2021.

## 2.0 (2019)

RootAsRole is still a proof of concept but now proposes an eBPF subprogram to obtain the capabilities of a generic command. A paper is published at Computer and Security@@wazanRootAsRoleSecurityModule2022

## 3.0 (2024)

RootAsRole direction is delegated to Eddie BILLOIR, a SIERA PhD student that contributed to the project all along its courses. It is now entirely rewritten in Rust, the eBPF subprogram is now in a separate project called RootAsRole-capable. The project takes a new direction and aims to be production ready with a massive reconception of every tools, a new configuration file format and complete documentation.

## 4.0 (2026)

RootAsRole reaches a major stabilization milestone with the modernized execution stack crate `rar-exec` for managing a secure execution for commands, thus handling signals and pty completely, introducing a way to monitor and curtail the execution in the future, exactly like sudo tool. It also introduces more configuration capabilities, such as folder-based configuration and CBOR-only format for even more performance. It also enhances the execution context, by adding the working directory management in the policy.

Documentation is refocused on operational usage, policy clarity, and contributor architecture. A comprehensive PhD thesis @@billo2025 consolidates the research foundation and design rationale for the project.

A new mascot, CaRoot, is introduced to personify the project and make it fancy. CaRoot was designed by EvaLaFougère, a talented artist! Her work is available on her [website](https://www.karde.me/evalafougere?utm_source=rootasrole&utm_medium=docs&utm_content=history).
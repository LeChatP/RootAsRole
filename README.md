<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
<p align="center">
  <img src="./RootAsRolev2.svg" width=30%>
 </p>
 <p align="center">
  
<img alt="Build Status" src="https://img.shields.io/github/actions/workflow/status/LeChatP/RootAsRole/build.yml?label=Build"/>
<img alt="Test Status" src="https://img.shields.io/github/actions/workflow/status/LeChatP/RootAsRole/tests.yml?label=Unit%20Tests">
<a href="https://codecov.io/gh/LeChatP/RootAsRole" ><img src="https://codecov.io/gh/LeChatP/RootAsRole/branch/main/graph/badge.svg?token=6J7CRGEIG8"/></a>
 <img alt="GitHub" src="https://img.shields.io/github/license/LeChatP/RootAsRole">

</p>
<!-- The project version is managed on json file in resources/rootasrole.json -->
<!-- markdownlint-restore -->

# RootAsRole (V3.2.0) — A better alternative to `sudo(-rs)`/`su` • ⚡ Blazing fast • 🛡️ Memory-safe • 🔐 Security-oriented

RootAsRole is a Linux/Unix privilege delegation tool based on **Role-Based Access Control (RBAC)**. It empowers administrators to assign precise privileges — not full root — to users and commands.

**[📚 Full Documentation for more details](https://lechatp.github.io/RootAsRole/)**


## 🚀 Why you need RootAsRole?

Most Linux systems break the [Principle of Least Privilege](https://en.wikipedia.org/wiki/Principle_of_least_privilege). Tools like `sudo` give **full root**, even if you just need one capability like `CAP_NET_RAW`.

RootAsRole solves this:

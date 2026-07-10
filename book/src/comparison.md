# Comparison with other tools

| Feature                                  | setcap??          | doas       | sudo                           | sudo-rs                       | dosr (RootAsRole)                                          |
|------------------------------------------|-------------------|------------|--------------------------------|--------------------------------|----------------------------------------------|
| **Change user/groups**                   | N/A               | ✅  | ✅ | ✅ | ✅✅ mandatory or optional                       |
| **Environment variables**                | N/A               | partial  | ✅ | partial                     | ✅                                    |
| **Specific command matching**            | N/A               | strict | strict & regex            | strict & wildcard            | strict & regex                       |
| **Centralized policy**                   | ❌                | ❌         | ✅                    | ❌                            | Planned                                          |
| **Secure signal forwarding**             | N/A               | ❌         | ✅                            | ✅                            | Planned                                      |
| **Set capabilities**                     | ⚠️ files     | ❌         | ❌                             | ❌                            | ✅                                 |
| **Prevent direct privilege escalation**  | ❌                | ❌         | ❌                             | ❌                            | ✅                         |
| **Untrust authorized users**             | ❌                | ❌         | ❌                             | ❌                            | ✅                   |
| **Standardized policy format**       | ❌                | ❌     | ❌                         | ❌                        | ✅                                   |
| **Scalable access control model**        | N/A               | ❌ ACL        | ❌ ACL                            | ❌ ACL                           | ✅ RBAC                                         |

<blockquote class="caroot-stare">
setcap is a tool to set capabilities on files, therefore comparing it with RaR or others is not relevant. We included it as many requested the comparison.
</blockquote>
# Comparison with other tools

| Feature                                  | setcap??          | doas       | sudo                           | sudo-rs                       | dosr (RootAsRole)                                          |
|------------------------------------------|-------------------|------------|--------------------------------|--------------------------------|----------------------------------------------|
| **Change user/groups**                   | N/A               | ✅  | ✅ | ✅ | ✅✅ mandatory or optional                       |
| **Environment variables**                | N/A               | partial  | ✅ | partial                     | ✅                                    |
| **Specific command matching**            | N/A               | strict | strict & regex            | strict & wildcard            | strict & regex                       |
| **Centralized policy**                   | ❌                | ❌         | ✅                    | ❌                            | Planned                                          |
| **Secure signal forwarding**             | N/A               | ❌         | ✅                            | ✅                            | ✅                                      |
| **Set capabilities**                     | ⚠️ files     | ❌         | ❌                             | ❌                            | ✅                                 |
| **Prevent direct privilege escalation**  | ❌                | ❌         | ❌                             | ❌                            | ✅                         |
| **Untrust authorized users**             | ❌                | ❌         | ❌                             | ❌                            | ✅                   |
| **Standardized policy format**       | ❌                | ❌     | ❌                         | ❌                        | ✅                                   |
| **Scalable access control model**        | N/A               | ❌ ACL        | ❌ ACL                            | ❌ ACL                           | ✅ RBAC                                         |

<blockquote class="caroot">
The sudo centralized policy feature relies on creating some LDAP entries that will be retrieved by sudo. This is somehwat not a conventional way to use LDAP. LDAP provides identity and directory information, but it does not evaluate authorization policies. So, scalability is a concern. Today, the preferred way is to use sudoers files with a configuration management tool like Ansible.
</blockquote>

<blockquote class="caroot-stare">
setcap is a tool to set capabilities on files, therefore comparing it with RaR or others is not relevant. We included it as many requested the comparison.
</blockquote>
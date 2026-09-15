# The RBAC model and access control model history

PoLP has its first implementation in access control theory, by managing the interaction (e.g., read, write) between subjects (e.g., users, processes) and objects (e.g., files, databases) within a system referred to as the SOA (Subject, Object, Action) matrix @@lampsonProtection1974,@@sandhuAccessControlPrinciple1994. This matrix was both resource-intensive for humans and computationally demanding to fully implement, as it required exhaustive enumeration and continuous maintenance of all possible subject-object-action combinations within the system. The resulting complexity is \\(O(n_s \cdot n_o \cdot n_a)\\), where \\(n_s\\), \\(n_o\\), and \\(n_a\\) represent the number of subjects, objects, and actions, respectively, just to define the matrix.

<blockquote class="caroot-stare">
The sudo policy model is describing one line per subject, object and action. While we can use wildcards and aliases to reduce the number of lines, it is still a model that lacks of organisational means to manage it. In other words, sudo is not implementing any access control model.
</blockquote>

Then, We are skipping the history of access control models. But to make it short, many engineering-focused access control models have been proposed to solve purely technical problems, such as the Object Capability Model for solving the Confused Deputy problem (or a Runtime Safety problem).

Now, I'll dive a bit into the Role-Based Access Control (RBAC) model. Role-based access control (RBAC) is an access control model that assigns permissions to roles rather than directly to individual users @@sandhuRoleBasedAccessControl1995. Permissions are the foundation of the model, defining the allowed interactions within the system. These permissions are not assigned directly to individuals. Instead, a Permission Assignment links them to a new entity called *Role*. A role is a logical grouping of permissions that corresponds to a specific job function or authority level within an organization (e.g., *System Administrator* or *Guest User*). By being assigned to a role, they inherit all the permissions associated with it, enabling them to perform their designated tasks. Finally, the model introduces Sessions. A User Session is an active connection between a user and the system. During a session, a user can activate one or more of their assigned roles, and the system uses a Role Session to grant them the corresponding permissions. This allows users to operate under different roles for different tasks within the same login.

This model is particularly useful and highly representing how our society is organized. If you want to learn more about it, you can read the PhD thesis @@billo2025 at section 1.2.5 where it makes a link with bees, ants as an example.

RootAsRole uses a RBAC model because admin delegation is first an assignment organisational problem.
@@billo2025, @@sandhuRoleBasedAccessControl1996, @@ferraioloProposedNISTStandard2001,
@@wazanRootAsRoleSecureAlternative2021,@@wazanRootAsRoleSecurityModule2022, @@billoirImplementingPrincipleLeast2023
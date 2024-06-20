# What is Role-Based Access Control Model?

Role-Based Access Control (RBAC) is a access control model that grants access to resources based on a user's role within an organization @@ferraioloProposedNISTStandard2001. This model makes it easier to manage user-centric access control policies. Indeed, this design allows to simply the distribution of user's responsibilities and better organize the access control policies in this context.

# What about Attribute-based Access Control Model ?

Attribute-Based Access Control (ABAC) is a more flexible model that grants access based on attributes of the user, the resource, the actions, and the environment by applying constraints on them. This design allows to implement generic access control policies. However, ABAC does not solve the problem of managing user-centric responsibilities access control policies. Indeed, ABAC allow to define generic policies, but not to manage them correctly given specific access control need. However, As ABAC can define a generic policy, it can be used to implement RBAC @@jinRABACRoleCentricAttributeBased2012, Bell-Lapadula (for confidentiality) @@balamuruganHoneyBeeBehaviour2015 or even Biba (for integrity) access control models @@kashmarAccessControlModels2020.

So ABAC is allowing to reach multiple access control properties by implementing multiple specific access control models. However, not respecting precisely these models designs may not reach the expected security properties.

# So why not use ABAC instead of RBAC for RootAsRole?

RootAsRole wants to delegate administrative responsibilities to severals users with more respect on the principle of least privilege. This means that RootAsRole access control policy is more user-centric, and thus, RBAC is more adapted to this context.

# Is it possible to use ABAC with RootAsRole?

Today, it requires some development to integrate RootAsRole in an ABAC implementation. However, RootAsRole will never implement ABAC by itself, so RootAsRole would requires to implement RBAC (with RootAsRole information) in the ABAC solution.
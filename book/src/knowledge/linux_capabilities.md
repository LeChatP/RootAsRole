# Linux capabilities

Linux implements a fine-grained privilege model through capabilities @@millerCapabilityMythsDemolished2003 (known as capability module), which partition the comprehensive power of the superuser (*root*) into distinct, manageable units. This mechanism allows specific privileges to be delegated to processes on an as-needed basis, obviating the requirement for them to operate with full root permissions. This design philosophy enhances system security by adhering to PoLP.

The concept was originally derived from the IEEE POSIX 1003.1e draft standard @@ieeeandtheopengroupIEEEOpenGroup2024, @@securityworkinggroupDraftStandardInformation1997a. Although this draft was ultimately withdrawn, its concepts were adopted and have since been independently maintained and significantly enhanced by the Linux kernel development community. The result is a LSM for defining discrete and mandatory access control policy for privileges on a per-thread basis. @@wazanRootAsRoleSecurityModule2022 @@billoirImplementingPrincipleLeast2023 @@billoirImplementingPrincipleLeast2024

In other terms, Linux capabilities switch from an Identity based access control with the root user to a set of privileges that can be granted to processes. It is an interesting features as long it allows to rely on a new mechanism to create organisational policies, such as Roles. This is where all started with this project.

For kernel-level capability documentation, see [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html).
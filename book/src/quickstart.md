# Your First Policy

In this chapter, we will build a minimal policy: 
**allowing users in the `ops` group to reboot the host via `dosr`**.

## 1. Create a Role

In RootAsRole, everything starts with a **Role**. 
A Role can be used to represent job operations, or a full procedure that some users are allowed to perform.
The main idea here is to organize system administration into wellknown sets of actions,
mastering your system's operations.

Here, we create a role named `ops` and grant it to the system group of the same name:

```bash
chsr role ops add
chsr role ops grant -g ops
```

## 2. Define a Task

A single Role can encompass many different actions.To keep your system clean and granular, 
we break down Roles into **Tasks**. Let’s create a task specifically dedicated to rebooting the system:

```bash
chsr role ops task reboot add
```

<blockquote class="caroot">
Keep your tasks narrow! One operational action per task is the golden rule. 
If you find yourself naming a task 'manage_everything', you are accidentally recreating the 'root' user!
</blockquote>

## 3. Define Execution Constraints

This is where we define what can be run and how it interacts with the system. 
The good practice is a whitelist approach to prevent arbitrary command execution.

### 3.1. Specify the Command

We must define *which binary* it is allowed to execute. We add the `reboot` command to our whitelist:

```bash
chsr role ops task reboot cmd whitelist add /usr/bin/reboot
```

<blockquote class="caroot">
You must write the absolute path to the command. 
This is a security measure to avoid command hijacking through PATH manipulation.
</blockquote>

### 3.2. Configure the Execution Context

Since systemd requires the root UID, we must configure dosr to handle this securely:

```bash
# Set effective UID to root for this task
chsr r ops t reboot cred set --setuid root

# Disable all capabilities explicitly for a clean slate
chsr r ops t reboot cred caps setpolicy deny-all

# Lock the execution environment
chsr r ops t reboot o root user
chsr r ops t reboot o bounding strict
```

The commands are doing the following:
- `cred set --setuid root`: This sets the UID to root for the task.
- `cred caps setpolicy deny-all`: This denies all capabilities for the task.
- `o root user`: This enables flag on the kernel to consider the root user as a not privileged user, 
        thus disabling the special treatment of the root user made by the kernel.
- `o bounding strict`: This enforces a strict bounding set of capabilities, further limiting the elevation of privileges.

In fact, The last 3 commands are not altering the configuration at all. Because RaR enforces already strict defaults, 
so, they were already set. But it is a good practice to explicitly set them, to avoid any misconfiguration by inheritance.

<blockquote class="caroot-stare">
You might wonder why we need setuid if we have Linux Capabilities. Modern systems rely heavily on systemd. 
Unlike older tools that check for CAP_SYS_BOOT capability, 
systemd do a simple check: "Are you UID 0?".
If you are not root, it denies the request, even if you technically have the capability.
</blockquote>

## 5. Execution and Verification

Your policy is now ready! As a member of the `ops` group, you can now invoke the `dosr` engine:

```bash
dosr reboot
```

If a user has multiple roles or tasks that could match the command, 
`dosr` will attempt to resolve the conflict by choosing the least privileged option. 
However, when using `dosr` in automation (like Ansible), it is best to be explicit to ensure deterministic behavior:

```bash
dosr -r ops -t reboot reboot
```
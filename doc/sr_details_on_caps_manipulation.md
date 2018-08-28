# Explanation of capabilities, process attributes and process Ids manipulation

We focus only here on the operations achieved by sr and sr_aux that may impact capabilities, process attributes or ids.
To explain the manipulations, we present X scenarios that are the possible usages of sr features: being root or a normal user, using the no-root option or not, using an other user.
All scenario could be use either with without a particular command given to sr. For the sake of simplicity, all scenario are presented as the execution of a simple shell under the role r1.

For all scenarios, we consider:

- the user root (UID=0, GID=0);
- the normal user remi (UID=1000, GID=1000);
- the role r1, set for remi, providing the capabilities cap_net_raw and cap_syslog.

The original file sr has the following capabilities in its file extensions: cap_setfcap, cap_setpcap in the permitted set.

The original file sr_aux has no capabilities defined.

## Scenario 1: normal user

The user remi executes `sr -r r1`.

1. The sr process stats with the following attributes:
    - RUID=EUID=SUID=1000;
    - RGID=EGID=SGID=1000;
    - capabilities: cap_setfcap, cap_setpcap in the PERMITTED set;
    - no process' attributes related to capabilities are set.
2. Once the sr_aux temporary file has been created, the sr process put cap_setfcap into its EFFECTIVE set.
3. The sr process adds to the PERMITTED set of the sr_aux temporary file (file extension) the capabilities read for the role r1: cap_net_raw and cap_syslog.
4. The sr process remove cap_setfcap from its EFFECTIVE set.
5. The sr process fork and wait for its child to terminate.
6. The child execve the sr_aux temporary file.
7. The sr_aux process starts with the following attributes:
    - RUID=EUID=SUID=1000;
    - RGID=EGID=SGID=1000;
    - capabilities: cap_net_raw, cap_syslog in the PERMITTED set;
    - no process' attributes related to capabilities are set.
8. The sr_aux process put all the capabilities it has in the PERMITTED set into the INHERITABLE set.
9. The sr_aux process put all the capabilities it has in the PERMITTED set into the AMBIENT set.
10. The sr_aux process execve a shell.
11. The shell starts with the following attributes: 	
    - RUID=EUID=SUID=1000;
    - RGID=EGID=SGID=1000;
    - capabilities: cap_net_raw, cap_syslog in its EFFECTIVE, PERMITTED, INHERITABLE and AMBIENT set;
    - no process' attributes related to capabilities are set.
	
_Within that shell, one can now execute a program to operate raw network operations or syslog operations. It is still possible for the user to execute a set-user-id/set-group-id programm or gains privileges (new capabilities, changing the userid...)._

## Scenario 2: normal user with no-root option

The user remi executes `sr -r r1 -n`.

1. the sr process stats with the following attributes:
    - RUID=EUID=SUID=1000
    - RGID=EGID=SGID=1000
    - capabilities: cap_setfcap, cap_setpcap in the PERMITTED set
    - no process' attributes related to capabilities are set	
2. Once the sr_aux temporary file has been created, the sr process put cap_setfcap into its EFFECTIVE set.
3. the sr process adds to the PERMITTED set of the sr_aux temporary file (file extension) the capabilities read for the role r1: cap_net_raw and cap_syslog.
4. The sr process remove cap_setfcap from its EFFECTIVE set.
5. The sr process fork and wait for its child to terminate.
6. The child put cap_setpcap into its EFFECTIVE set.
7. The child set the following securebits in the process' attributes: SECBIT_KEEP_CAPS_LOCKED, SECBIT_NO_SETUID_FIXUP, SECBIT_NO_SETUID_FIXUP_LOCKED, SECBIT_NOROOT, SECBIT_NOROOT_LOCKED. This is the first step of the no-root feature.
8. The child remove cap_setpcap from its EFFECTIVE set.
9. The child execve the sr_aux temporary file.
10. The sr_aux process starts with the following attributes:		
    - RUID=EUID=SUID=1000;
    - RGID=EGID=SGID=1000;
    - capabilities: cap_net_raw, cap_syslog in the PERMITTED set;
    - the previous securebits are set in the process' attributes.
11. The sr_aux process put all the capabilities it has in the PERMITTED set into the INHERITABLE set.
12. The sr_aux process put all the capabilities it has in the PERMITTED set into the AMBIENT set.
13. The sr_aux process set the process' attribute NO_NEW_PRIVS to 1.
14. The sr_aux process execve a shell.
15. The shell starts with the following attributes: 
    - RUID=EUID=SUID=1000
    - RGID=EGID=SGID=1000
    - capabilities: cap_net_raw, cap_syslog in its EFFECTIVE, PERMITTED, INHERITABLE and AMBIENT set
    - the previous securebits are set in the process' attributes and the NO_NEW_PRIVS is set to 1.

_Within that shell, remi can now execute a program to operate raw network operations or syslog operations. However, it is not possible to gains privileges, whatever happens (execution of a set-user-id/set-group-id file, execution of a privileged file, ...)._

## Scenario 3: root user with user usurpation

The user root executes `sr -r r1 -u remi`.
	
1. the sr process stats with the following attributes:
    - RUID=EUID=SUID=0;
    - RGID=EGID=SGID=0;
    - capabilities: ALL CAPABILITIES in the PERMITTED and EFFECTIVE sets;
    - no process' attributes related to capabilities are set.		
2. Once the sr_aux temporary file has been created, the sr process put cap_setfcap to its EFFECTIVE set (no effect here).
3. The sr process adds to the PERMITTED set of the sr_aux temporary file (file extension) the capabilities read for the role r1: cap_net_raw and cap_syslog.
4. The sr process remove cap_setfcap from its EFFECTIVE set.
5. The sr process fork and wait for its child to terminate.
6. The child apply a setgid() and setuid() to change the user. all the process ids are changed, and the process looses all the capabilities from its PERMITTED and EFFECTIVE sets.
7. The child execve the sr_aux temporary file.
8. The sr_aux process starts with the following attributes:
    - RUID=EUID=SUID=1000
    - RGID=EGID=SGID=1000
    - capabilities: cap_net_raw, cap_syslog in the PERMITTED set
    - no process' attributes related to capabilities are set
9. The sr_aux process put all the capabilities it has in the PERMITTED set into the INHERITABLE set.
10. The sr_aux process put all the capabilities it has in the PERMITTED set into the AMBIENT set.
11. The sr_aux process execve a shell.
12. The shell starts with the following attributes: 
    - RUID=EUID=SUID=1000;
    - RGID=EGID=SGID=1000;
    - capabilities: cap_net_raw, cap_syslog in its EFFECTIVE, PERMITTED, INHERITABLE and AMBIENT set;
    - no process' attributes related to capabilities are set.
	
_Within that shell, remi can now execute a program to operate raw network operations or syslog operations. It is still possible for the user to execute a set-user-id/set-group-id programm or gains privileges (new capabilities, changing the userid...)._

## Scenario 4: root user with no-root option

The user root executes `sr -r r1 -n`.

1. The sr process stats with the following attributes:
    - RUID=EUID=SUID=0;
    - RGID=EGID=SGID=0;
    - capabilities: ALL CAPABILITIES in the PERMITTED and EFFECTIVE sets;
    - no process' attributes related to capabilities are set.
2. Once the sr_aux temporary file has been created, the sr process put cap_setfcap to the EFFECTIVE set (no effect here).
3. The sr process adds to the PERMITTED set of the sr_aux temporary file (file extension) the capabilities read for the role r1: cap_net_raw and cap_syslog.
4. The sr process remove cap_setfcap from the EFFECTIVE set.
5. The sr process fork and wait for its child to terminate.
6. The child put cap_setpcap into its EFFECTIVE set.
7. The child set the following securebits in the process' attributes: SECBIT_KEEP_CAPS_LOCKED, SECBIT_NO_SETUID_FIXUP, SECBIT_NO_SETUID_FIXUP_LOCKED, SECBIT_NOROOT, SECBIT_NOROOT_LOCKED. This is the first step of the no-root feature.
8. The child remove cap_setpcap from its EFFECTIVE set.
9. The child apply a setgid() and setuid() to change the user. all the process ids are changed, and the process looses all the capabilities from its PERMITTED and EFFECTIVE sets.
10. The child execve the sr_aux temporary file.
10. The sr_aux process starts with the following attributes:			
    - RUID=EUID=SUID=1000;
    - RGID=EGID=SGID=1000;
    - capabilities: cap_net_raw, cap_syslog in the PERMITTED set;
    - the previous securebits are set in the process' attributes.
11. The sr_aux process put all the capabilities it has in the PERMITTED set into the INHERITABLE set.
12. The sr_aux process put all the capabilities it has in the PERMITTED set into the AMBIENT set.
13. The sr_aux process set the process' attribute NO_NEW_PRIVS to 1.
14. The sr_aux process execve a shell.
15. The shell starts with the following attributes: 
    - RUID=EUID=SUID=1000;
    - RGID=EGID=SGID=1000;
    - capabilities: cap_net_raw, cap_syslog in its EFFECTIVE, PERMITTED, INHERITABLE and AMBIENT set;
    - the previous securebits are set in the process' attributes and the NO_NEW_PRIVS is set to 1.
	
_Within that shell, the root is still root, and can execute any program that require only syslog or net raw operations. Also, it is not possible for the root to gains privileges, whatever happens (execution of a set-user-id/set-group-id file, execution of a privileged file, ...)._

## Scenario 5: root user with no-root option and user usurpation

The user root executes `sr -r r1 -n -u remi`.

1. the sr process stats with the following attributes:
    - RUID=EUID=SUID=0;
    - RGID=EGID=SGID=0;
    - capabilities: ALL CAPABILITIES in the PERMITTED and EFFECTIVE sets;
    - no process' attributes related to capabilities are set.
2. Once the sr_aux temporary file has been created, the sr process put cap_setfcap to the EFFECTIVE set (no effect here).
3. The sr process adds to the PERMITTED set of the sr_aux temporary file (file extension) the capabilities read for the role r1: cap_net_raw and cap_syslog.
4. The sr process remove cap_setfcap from the EFFECTIVE set.
5. The sr process fork and wait for its child to terminate.
6. The child put cap_setpcap into its EFFECTIVE set.
7. The child set the following securebits in the process' attributes: SECBIT_KEEP_CAPS_LOCKED, SECBIT_NO_SETUID_FIXUP, SECBIT_NO_SETUID_FIXUP_LOCKED, SECBIT_NOROOT, SECBIT_NOROOT_LOCKED. This is the first step of the no-root feature.
8. The child remove cap_setpcap from its EFFECTIVE set.
9. The child execve the sr_aux temporary file.
10. The sr_aux process starts with the following attributes:
    - RUID=EUID=SUID=0;
    - RGID=EGID=SGID=0;
    - capabilities: cap_net_raw, cap_syslog in the PERMITTED set;
    - the previous securebits are set in the process' attributes.
11. The sr_aux process put all the capabilities it has in the PERMITTED set into the INHERITABLE set.
12. The sr_aux process put all the capabilities it has in the PERMITTED set into the AMBIENT set.
13. The sr_aux process set the process' attribute NO_NEW_PRIVS to 1.
14. The sr_aux process execve a shell.
15. The shell starts with the following attributes: 
    - RUID=EUID=SUID=0;
    - RGID=EGID=SGID=0;
    - capabilities: cap_net_raw, cap_syslog in its EFFECTIVE, PERMITTED, INHERITABLE and AMBIENT set;
    - the previous securebits are set in the process' attributes and the NO_NEW_PRIVS is set to 1.
	
_Within that shell, the root acts as remi and can now execute a program to operate raw network operations or syslog operations. However, it is not possible to gains privileges, whatever happens (execution of a set-user-id/set-group-id file, execution of a privileged file, ...)._

## More on the no-root feature

The no-root feature allows launching an privileged shell (or any program) with a given set of capabilities, but restricted to these capabilities only, whatever happen next (e.g.: execve a privileged or a set-user-id file).
This setting is achieved two steps.
First, before launching sr_aux, a set a securebits are set in the process' attibutes. Here is a brief explanation of their goal:

- KEEP_CAPS_LOCKED: prevent changing the KEEP_CAPS securebits. When set to 1, KEEP_CAPS to 0-uid process to keep its capabilities after a modification of uids that would results in no uid 0 any more. KEEP_CAPS is here set to 0 (and reset to 0 at each execve). We locked the value 0 here, to prevent that behavior
- NO_SETUID_FIXUP: stops the kernel from adjusting the process's permitted, effective, and ambient capability sets when the thread's effective and filesystem UIDs are switched between zero and nonzero values
- SECBIT_NO_SETUID_FIXUP_LOCKED: prevent changing the SECBIT_NO_SETUID_FIXUP securebit
- SECBIT_NOROOT: the kernel does not grant capabilities when a set-user-ID-root program is executed, or when a process with an effective or real UID of 0 calls execve
- SECBIT_NOROOT_LOCKED: prevent changing the SECBIT_NOROOT securebits

__Note:__ All these 5 securebits remains across execve operations.

__Note:__ The operation of setting these securebits requires the SETPCAP capability. That is why this operation is achieved before any setuid/setgid operation, as it would result a lost of capabilities for the sr process (see scenario 5).

While sr_aux runs, the second step is achieved, once the process have done all the capabilities manipulation (putting caps into the inheritable set then into the ambient set).

The sr_aux process set the process' attribute NO_NEW_PRIVS to 1. As a results, further execve calls will not grant any new privilege (i.e.: set-user-ID and set-group-ID mode bits, and file capabilities are rendered non-functional).




	
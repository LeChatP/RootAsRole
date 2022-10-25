[![Version](https://img.shields.io/badge/Langage-C-blue)]()
# Role Manager - Manage Root As Role XML file

Role Manager was developed with the aim of facilitating role management as well as avoiding semantic bugs related to manual editing of the XML file used by the sr command.

## addrole
|Options|Description|
|---|---|
|Role|The role to be added. It must not already exist|
|Capabilities|Capabilities to be added (see man capabilities). If a star is used as an argument, all capabilities will be allocated to the role.|
|`-u, --user=user1,user2...`|All parameter users are added only if they are already present on the system. The first call to this option allows to allocate in memory all the users as arguments. Second call is the user eligible for the next command entered.|
|`-g, --group=group1,group2...`|All parameter groups are added only if they are already present on the system. The first call to this option allows to allocate in memory all groups as arguments. Second call is the group eligible for the next order entered.|
|`-c, --command="ma commande"`|Commands can be added for the role, for all users, for all groups or only selected groups and users|

### Scenario 1
	addrole role2 cap_fowner,cap_setuid -g zayed -g zayed \
			-c "/usr/bin/passwd" -c "/usr/bin/chmod" -c /opt/myprogram -i"
Here commands will only be available for the zayed group. In the case or the second parameter `-g zayed` had not been written, commands would have been available for all existing groups.

	<role name="role2">
		<capabilities>
			<capability>cap_fowner</capability>
			<capability>cap_setuid</capability>
		</capabilities>
		<groups>
			<group name="zayed">
				<commands>
					<command>/usr/bin/passwd</command>
					<command>/usr/bin/chmod</command>
					<command>/opt/myprogram -i</command>
				</commands>
			</group>
		</groups>
	</role>

### Scenario 2
	addrole role2 cap_net_raw,cap_sys_nice -u anderson,ahmed -g zayed,irit,univ \
			-u ahmed -c "/usr/sbin/tcpdump" -u * -c "/usr/sbin/iptables" \
			-g unive -c "/usr/bin/printer" -c "/usr/bin/other"
-

	<role name="role1">
		<capabilities>
			<capability>cap_net_raw</capability>
			<capability>cap_sys_nice</capability>
		</capabilities>
		<users>
			<user name="anderson"/>
			<user name="ahmed">
				<commands>
					<command>/usr/sbin/tcpdump</command>
				</commands>
			</user>
			<commands>
				<command>/usr/sbin/iptables</command>
			</commands>
		</users>
		<groups>
			<group name="zayed"/>
			<group name="irit"/>
			<group name="univ">
				<commands>
					<command>/usr/bin/printer</command>
					<command>/usr/bin/other</command>
				</commands>
			</group>
		</groups>
	</role>

### Scenario 3
	addrole root * -c "/my/root/command" -u root

	<role name="root">
		<capabilities>
			<capability>*</capability>
		</capabilities>
		<commands>
			<command>/my/root/command</command>
		</commands>
		<users>
			<user name="root"/>
		</users>
	</role>

## editrole
editrole redirects the user to a multiple choice: add, edit or delete a node.

### Add Node
Uses the URL syntax `/parent/to/child` to designate which node should be added. In case a command needs to be added, to avoid confusion with the `strtok` parser, you will be asked to type the command regardless of the desired path.  
  
**Exemple :**
  
	./editrole role2
	1. Add
	2. Edit
	3. Delete
	0. Quit
	What do you want to do ? -> 1
	Use URL syntax for add an element to xml file
	Example : /capabilities/cap_net_bind_service
	What do you want to add ? -> /capabilities/cap_net_bind_service
-

	./editrole role2
	1. Add
	2. Edit
	3. Delete
	0. Quit
	What do you want to do ? -> 1
	Use URL syntax for add an element to xml file
	Example : /capabilities/cap_net_bind_service
	What do you want to add ? -> /groups/anderson/commands
	Type your commands : myprogram.sh -c options

### Edit and delete node
Displays the XML tree preceded by numbers representing the block number. You will need to type the block number to be able to edit or delete a node from the XML file. Some blocks depending on their property cannot be edited or deleted :
  
 - Vous ne pouvez pas supprimer le bloc `<role>`  
 - Vous ne pouvez pas éditer les blocs `<capabilities>` `<commands>` `<users>` `<groups>`  

**Example :**
 
	./editrole role2
	1. Add
	2. Edit
	3. Delete
	0. Quit
	What do you want to do ? -> 2
	1 role2 :
	2	Capabilities :
	3		cap_fowner
	4		cap_setuid
	5	Groups :
	6		mygroup
	7			Commands :
	8				/usr/bin/passwd
	9				/usr/bin/chmod
	10				/opt/myprogram -i

	Use the displayed tree and selects the number corresponding to the node -> 6
	By what element would you replace ? -> ahmed

## deleterole
Delete an existing role

## Author
Anderson Hemlee - anderson.hemlee@protonmail.com

## To Do List
1. Improve add node from editrole
2. Protect editrole memory leak from SIGINT
3. Make test
4. Map in memory real DTD, and compare with DTD from XML file for more security (Suggest)
5. Write "printrole" command, to allow the root user to display role informations (Suggest)

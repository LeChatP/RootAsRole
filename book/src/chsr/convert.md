# File Config Conversion

## Converting JSON to CBOR and vice versa

Converting the `/etc/security/rootasrole.json` file to CBOR format (and configure the policy to the new location with `-r` option) :

`chsr convert -r cbor /etc/security/rootasrole.bin`

This command will read the JSON file, convert it to CBOR format, and save it to `/etc/security/rootasrole.bin`. The `-r` option changes the file `/etc/security/rootasrole.json` to specify the new location in `path` field of the configuration file.

To convert the CBOR file back to JSON format, you can use the following command:

`chsr convert -r json /etc/security/rootasrole.json`

This command will read the CBOR file, convert it back to JSON format, and save it to `/etc/security/rootasrole.json`. The `-r` option changes the file `/etc/security/rootasrole.json` to specify the new location in `path` field of the configuration file.
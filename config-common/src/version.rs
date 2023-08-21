pub const PACKAGE_VERSION: &'static str = "3.0.0-alpha.3";
pub const DTD: &'static str = "
<!DOCTYPE rootasrole [
	<!ELEMENT rootasrole (roles|options?)*>
	<!ATTLIST rootasrole version CDATA #REQUIRED
		timestamp-timeout CDATA #IMPLIED>
	<!ELEMENT options (path?|env-keep?|env-check?|env-reset?|allow-root?|allow-bounding?|setuid?|wildcard-denied?)*>
	<!ELEMENT env-keep (#PCDATA|EMPTY)*>
	<!ELEMENT env-check (#PCDATA|EMPTY)*>
	<!ELEMENT allow-root EMPTY>
	<!ATTLIST allow-root enforce (true|false) \"true\">
	<!ELEMENT allow-bounding EMPTY>
	<!ATTLIST allow-bounding enforce (true|false) \"true\">
	<!ELEMENT wildcard-denied (#PCDATA|EMPTY)*>
	<!ELEMENT path (#PCDATA|EMPTY)*>
	<!ELEMENT roles (role*)>
	<!ELEMENT role (actors?|task*|options?)*>
	<!ATTLIST role
		name ID #REQUIRED
		parents IDREFS #IMPLIED
		denied-capabilities CDATA #IMPLIED
		incompatible-with IDREFS #IMPLIED >
	<!ELEMENT actors (user*|group*)>
	<!ELEMENT user EMPTY>
	<!ATTLIST user name CDATA #REQUIRED>
	<!ELEMENT group EMPTY>
	<!ATTLIST group names CDATA #REQUIRED>
	<!ELEMENT task (command*|options?|purpose?)*>
	<!ATTLIST task
		id ID #IMPLIED
		capabilities CDATA #IMPLIED
		setuser CDATA #IMPLIED
		setgroups CDATA #IMPLIED>
	<!ELEMENT command (#PCDATA)>
	<!ATTLIST command
		regex (true|false) \"false\">
	<!ELEMENT purpose (#PCDATA)>
]>
";

********************************************
* Instructions for posting to LDAP Servers *
********************************************

1.	Extract files to the /tmp directory.
	(pkits.ldif contains file path certs
	and crls, rather than base64 encoded
	certs and crls, so if you change the
	directory structure, also change the
	file path names in pkits.ldif.

2.	Run openLDAP's ldapadd or ldapmodify
	script, passing in pkits.ldif as the
	file (-f) parameter.

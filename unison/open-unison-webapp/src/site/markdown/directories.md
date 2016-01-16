# Directory Integration

Open Unison integrates MyVirtualDirectory (http://myvd.sourceforge.net) as its directory integration layer.  The only requirement for the MyVD configuration is that the root must be o=Tremolo.  While any number of inserts can be used in any configuration, its recommended that the pattern of using the below inserts is used to maintain compatibility with commercial Unison.  This section details each of the main integration types and provides example configurations.

## Admin Directory

This insert provides for a single user.  It was originally intended to store the Unison root user, but is also useful for testing Unison deployments prior to integrating with an external identity source.

### Configuration Properties

| Name | Value | Example |
| --- | --- |--- |
| uid | The login id of the user | adminuser |
| password | The user's password | mypassword |

### Example

`````
server.admin.nameSpace=ou=admin,o=Tremolo
server.admin.chain=admindir
server.admin.weight=0
server.admin.admindir.className=com.tremolosecurity.proxy.myvd.inserts.admin.AdminInsert
server.admin.admindir.config.uid=adminuser
server.admin.admindir.config.password=mypassword
`````

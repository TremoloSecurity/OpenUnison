# Authentication Mechanisms Configuration Reference


## Anonymous Authentication
Anonymous authentication is used for scenarios when user authentication is not needed.  This mechanism will assign a default user.

### Mechanism

#### &lt;mechanism&gt; Tag Attributes

| Attribute | Value |
| --- | --- |
| uri | /auth/anon |
| className | com.tremolosecurity.proxy.auth.AnonAuth | 

#### &lt;init&gt; Parameters

| name | value | Example |
| ---- | ----- | ------- |
| userName | RDN of the user | uid=Anonymous |

In addition to the userName parameter, you can add any number of arbitrary attributes to the anonymous user.  This is useful when down stream applications require default values for attributes even for anonymous users.

#### Example Configuration

`````xml
<tns:mechanism name="anonymous">
	<tns:uri>/auth/anon</tns:uri>
	<tns:className>com.tremolosecurity.proxy.auth.AnonAuth</tns:className>
	<tns:init>
		<tns:param name="userName" value="uid=Anonymous"/>
		<tns:param name="roles" value="Users" />
	</tns:init>
	<tns:params></tns:params>
</tns:mechanism>
`````

### Chain

There are no chain specific configuration options.

## Form Login
An HTML login form. All login forms must be stored in the auth/forms directory. Forms can be static HTML or JSP pages. See auth/forms/defaultForm.jsp as an example.

### Mechanism

#### &lt;mechanism&gt; Tag Attributes

| Attribute | Value |
| --- | --- |
| uri | /auth/form |
| className | com.tremolosecurity.proxy.auth.FormLoginAuthMech |
 

#### &lt;init&gt; Parameters

There are no mechanism level attributes.

#### Example Configuration

`````xml
<tns:mechanism name="form">
	<tns:uri>/auth/form</tns:uri>
	<tns:className>ccom.tremolosecurity.proxy.auth.FormLoginAuthMech</tns:className>
	<tns:init />
	<tns:params />
</tns:mechanism>
`````

### Chain

#### &lt;params&gt; Tag Attributes

| name | value | Example |
| ---- | ----- | ------- |
| FORMLOGIN_JSP | The URI for the jsp page used to log the user in | /auth/forms/defaultForm.jsp |
| uidAttr | Either an attribute name OR an ldap filter mapping the form parameters. If this is an ldap filter, form parameters are identified by ${parameter} | Attribute name : uid <br /> Filter : (&(uid=${username})(l=${locationName})) |
| uidIsFilter | If true, the user is determined based on an LDAP filter rather than a simple user lookup | false |

#### Example Configuration

`````xml
<tns:authMech>
	<tns:name>form</tns:name>
	<tns:required>required</tns:required>
	<tns:params>
		<tns:param name="FORMLOGIN_JSP" value="/auth/forms/defaultForm.jsp"/>
		<tns:param name="uidAttr" value="uid"/>
		<tns:param name="uidIsFilter" value="false"/>
	</tns:params>
</tns:authMech>
`````


### Chain

There are no chain specific configuration options.

## SAML2
This mechanism is used to authenticate the user using a SAML2 assertion. The HTTP-POST and HTTP-REDIRECT profiles are supported.



### Mechanism

#### &lt;mechanism&gt; Tag Attributes

| Attribute | Value |
| --- | --- |
| uri | /auth/saml2 |
| className | com.tremolosecurity.proxy.auth.SAML2Auth |
 

#### &lt;init&gt; Parameters

Some identity providers, such as Active Directory Federation Services, do not have a way of providing a default RelayState for IdP Initiated SSO. In such cases, a mapping from the Referer HTTP header to a default relay state may be configured on the mechanism.

| name | value | Example |
| ---- | ----- | ------- |
| defaultRelayStates | Mapping of the referer header of the request to the final RelayState.  The format of the value is referer&#124;RelayState.  This parameter can be listed any number of times. | https://someidp.com/idpinit&#124;http://localhost.localdomain:8080/myapp |

#### Example Configuration

`````xml
<tns:mechanism name="saml2">
	<tns:uri>/auth/saml2</tns:uri>
	<tns:className>ccom.tremolosecurity.proxy.auth.SAML2Auth</tns:className>
	<tns:init>
		<tns:param name="defaultRelayStates" value="https://someidp.com/idpinit|http://localhost.localdomain:8080/myapp"/>
	</tns:init>
	<tns:params />
</tns:mechanism>
`````

### Chain

#### &lt;params&gt; Tag Attributes

| name | value | Example |
| ---- | ----- | ------- |
| entityID | Optional - The URL for the IdP’s EntityID, needed for Single Logout | https://www.myidp.com/fed/aunth20Response |
| idpURL | The URL for the IdP’s POST endpoint | https://www.myidp.com/fed/aunth20Response |
| idpRedirURL | The URL for the IdP’s REDIRECT endpoint |  https://www.myidp.com/fed/aunth20Response |
| idpRedirLogoutURL | Optional - The URL for the IdP’s Single Logout Service HTTP-Redirect endpoint; requires that the Signature Certificate and Optional Final Logout URL be set | https://www.myidp.com/fed/aunth20Response |
| logoutURL | Optional - URL to redirect users to after receiving a response from the identity provider indicating a successful single logout	 | https://www.myhost.com/logout |
| assertionsSigned | Should the assertion be signed? | false |
| responsesSigned | Should the entire response (including the assertion) be signed? | true |
| sigAlg |  The algorithm to use when signing AuthnRequest and SingleLogoutRequest messages to the identity provider | One of: <br />RSA-SHA1<br />RSA-SHA256<br />RSA-SHA384<br />RSA-SHA512|
| idpSigKeyName | The name of the certificate used to validate the signed response / assertion | Stored in Unison key store |
| authCtxRef | How does the user need to be authenticated? | Leave blank for any, otherwise any Authentication Context Class Ref type |
| forceToSSL | For sites that do not work well with SSL this feature will allow an application to use federation for https, but switch back to HTTP once authentication is complete. Note: for this feature to work sesison cookies must NOT be marked as secure. | false |
| assertionEncrypted | Must assertions be encrypted? If false, encrypted assertions will still be accepted if properly encrypted. | false |
| spEncKey | If an assertion is encrypted, which key should be used to decrypt it? | Name of the key in the Unison key store |
| signAuthnReq | Should authentication requests be signed before being sent to the Identity Provider? | true |
| spSigKey | If authentication requests are signed, what key to use to sign the request | Name of the key in the Unison key store |
| jumpPage | Optional - An optional setting to allow for a page to be displayed to the user prior to SP initiated federation being triggered. This page is for notifying the user they will be redirected for authentication. | Empty to be ignored or /auth/forms/jump.jsp for the default jump page |
| ldapAttribute | Name of the attribute that the NameID in the assertion | uid |
| dnOU | What the ou of the DN for an unlinked user should be. For instance if a user named testuser is authenticated but not associated with a user in the directory and the value of this setting is SAML2 the user’s DN will be uid=test,ou=SAML2,o=Tremolo | SAML2 |
| defaultOC | If a user can not be mapped, the objectClass that should be used when constructing the user object | inetOrgPerson |
| dontLinkToLDAP | If checked, Unison will skip attempting to find an object in the internal virtual directory to associate with this user. This should be checked when using Just-In-Time provisioning and will reload the context AFTER the workflow executes. | false |


#### Example Configuration

`````xml
<tns:authMech>
	<tns:name>form</tns:name>
	<tns:required>required</tns:required>
	<tns:params>
		<tns:param name="FORMLOGIN_JSP" value="/auth/forms/defaultForm.jsp"/>
		<tns:param name="uidAttr" value="uid"/>
		<tns:param name="uidIsFilter" value="false"/>
	</tns:params>
</tns:authMech>
`````
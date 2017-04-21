## 1.0.9-2017040801


**bugs:**
 - slf4j dependency not being set correctly [\#190](https://github.com/TremoloSecurity/OpenUnison/issues/190)
 - activemq-all causing classpath clashes [\#189](https://github.com/TremoloSecurity/OpenUnison/issues/189)
 - Facebook login failing [\#188](https://github.com/TremoloSecurity/OpenUnison/issues/188)
 - persistent cookie auth failing [\#187](https://github.com/TremoloSecurity/OpenUnison/issues/187)
 - compliance erroring out when one of the values is null [\#185](https://github.com/TremoloSecurity/OpenUnison/issues/185)
 - document db insert [\#158](https://github.com/TremoloSecurity/OpenUnison/issues/158)
 - JIT docs not aligned [\#172](https://github.com/TremoloSecurity/OpenUnison/issues/172)
 - conflict between email attribute insert and templates [\#181](https://github.com/TremoloSecurity/OpenUnison/issues/181)
 - strip "Transfer-Encoding" header from downstream responses [\#179](https://github.com/TremoloSecurity/OpenUnison/issues/179)
 - default behavior when context variables not set [\#180](https://github.com/TremoloSecurity/OpenUnison/issues/180)
 - compliance - load provisioning attributes from authenticated object [\#176](https://github.com/TremoloSecurity/OpenUnison/issues/176)
 - LoadAttributes doesn't check if the user exists [\#175](https://github.com/TremoloSecurity/OpenUnison/issues/175)
 - db composite insert can't have multiple on a single server [\#173](https://github.com/TremoloSecurity/OpenUnison/issues/173)
 - Workflow fails to start if attributes missing [\#171](https://github.com/TremoloSecurity/OpenUnison/issues/171)
 - Compliance checks fail with DB users if user doesn't exist [\#170](https://github.com/TremoloSecurity/OpenUnison/issues/170)
 - 3+ levels of choice in workflow not completing properly [\#165](https://github.com/TremoloSecurity/OpenUnison/issues/165)
 - Add log4j to openunison util [\#163](https://github.com/TremoloSecurity/OpenUnison/issues/163)
 - upgrade opensaml to v3 [\#153](https://github.com/TremoloSecurity/OpenUnison/issues/153)
 - JIT with Tremolo Provisioning Target not failing when provisioning fails [\#147](https://github.com/TremoloSecurity/OpenUnison/issues/147)
 - C3PO conflict from Quartz [\#150](https://github.com/TremoloSecurity/OpenUnison/issues/150)
 - Correct security issues found by docker scan [\#148](https://github.com/TremoloSecurity/OpenUnison/issues/148)
 - LoadGroups not failing on failed user lookup [\#146](https://github.com/TremoloSecurity/OpenUnison/issues/146)

**enhancements:**
 - provisioning - add types to target attributes [\#177](https://github.com/TremoloSecurity/OpenUnison/issues/177)
 - deployment build [\#186](https://github.com/TremoloSecurity/OpenUnison/issues/186)
 - add ability to import aes-256 key to keystore [\#164](https://github.com/TremoloSecurity/OpenUnison/issues/164)
 - Header filter [\#184](https://github.com/TremoloSecurity/OpenUnison/issues/184)
 - Add overide for notify user when caller and subject are different [\#182](https://github.com/TremoloSecurity/OpenUnison/issues/182)
 - add switch to allow import of environment variables [\#183](https://github.com/TremoloSecurity/OpenUnison/issues/183)
 - Remove internal AMQ from non-provisioning enabled systems [\#167](https://github.com/TremoloSecurity/OpenUnison/issues/167)
 - Add filter to execute arbitrary workflows [\#166](https://github.com/TremoloSecurity/OpenUnison/issues/166)
 - Create remote call with lastmile provisioning task [\#168](https://github.com/TremoloSecurity/OpenUnison/issues/168)
 - myvd - load attribute from target [\#178](https://github.com/TremoloSecurity/OpenUnison/issues/178)
 - Add support for environment variables in the command line utilities [\#162](https://github.com/TremoloSecurity/OpenUnison/issues/162)
 - Simplify logic for compliance checking [\#169](https://github.com/TremoloSecurity/OpenUnison/issues/169)
 - Support "groups only" for db insert [\#160](https://github.com/TremoloSecurity/OpenUnison/issues/160)
 - Create way for db provider to provision user passwords [\#64](https://github.com/TremoloSecurity/OpenUnison/issues/64)
 - support pbkdf2 passwords in the db insert [\#157](https://github.com/TremoloSecurity/OpenUnison/issues/157)
 - Move to MyVD 1.0.1 [\#156](https://github.com/TremoloSecurity/OpenUnison/issues/156)
 - support custom hibernate configurations [\#151](https://github.com/TremoloSecurity/OpenUnison/issues/151)
 - Add pre-approvals in ScaleJS [\#149](https://github.com/TremoloSecurity/OpenUnison/issues/149)


## 1.0.8-2016122901

**bugs:**
 - JIT with Tremolo Provisioning Target not failing when provisioning fails [\#147](https://github.com/TremoloSecurity/OpenUnison/issues/147)
 - C3PO conflict from Quartz [\#150](https://github.com/TremoloSecurity/OpenUnison/issues/150)

## 1.0.8-2016121701

**bugs:**
 - Correct security issues found by docker scan [\#148](https://github.com/TremoloSecurity/OpenUnison/issues/148)

## 1.0.8-2016121601

**bugs:**
 - Correct security issues found by docker scan [\#148](https://github.com/TremoloSecurity/OpenUnison/issues/148)
 - LoadGroups not failing on failed user lookup [\#146](https://github.com/TremoloSecurity/OpenUnison/issues/146)

## 1.0.8-2016112701

**enhancements:**
 - Updates to support CII Best Practices [\#141](https://github.com/TremoloSecurity/OpenUnison/issues/141)
 - Move MyVD inserts to MyVD [\#139](https://github.com/TremoloSecurity/OpenUnison/issues/139)
 - Support for userinfo in oidc idp [\#140](https://github.com/TremoloSecurity/OpenUnison/issues/140)
 - Add filter to openshift dynamic workflow [\#138](https://github.com/TremoloSecurity/OpenUnison/issues/138)
 - Integrate Kubernetes [\#133](https://github.com/TremoloSecurity/OpenUnison/issues/133)
 - Integrate OIDC IdP [\#132](https://github.com/TremoloSecurity/OpenUnison/issues/132)
 - Add session check to scalejs token [\#136](https://github.com/TremoloSecurity/OpenUnison/issues/136)
 - Integrate OIDC AuthMech [\#131](https://github.com/TremoloSecurity/OpenUnison/issues/131)
 - Integrate MongoDB into OpenUnison [\#130](https://github.com/TremoloSecurity/OpenUnison/issues/130)
 - ScaleJS interface fixes [\#127](https://github.com/TremoloSecurity/OpenUnison/issues/127)
 - create userprincipalname2uid mapper [\#98](https://github.com/TremoloSecurity/OpenUnison/issues/98)

**bugs:**
 - saml auth chain on saml idp fails [\#137](https://github.com/TremoloSecurity/OpenUnison/issues/137)
 - ScaleJS Register Home link [\#129](https://github.com/TremoloSecurity/OpenUnison/issues/129)
 - Approval failures not successful [\#128](https://github.com/TremoloSecurity/OpenUnison/issues/128)

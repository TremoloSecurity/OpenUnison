## 1.0.24-2021110502

**Tasks:**
 - 1.0.24 build [\#556](https://github.com/TremoloSecurity/OpenUnison/issues/556)

**enhancements:**
 - HttpFilter - JavaScript [\#590](https://github.com/TremoloSecurity/OpenUnison/issues/590)
 - ScaleJS Register - JavaScript custom validator [\#592](https://github.com/TremoloSecurity/OpenUnison/issues/592)
 - ScaleJS Register - JavaScript dynamic list [\#591](https://github.com/TremoloSecurity/OpenUnison/issues/591)
 - JavaScript Scheduled Tasks [\#589](https://github.com/TremoloSecurity/OpenUnison/issues/589)
 - ScaleJS Register - Okta groups dynamic lookup [\#588](https://github.com/TremoloSecurity/OpenUnison/issues/588)
 - Move custom tasks from k8s repo into main repo [\#587](https://github.com/TremoloSecurity/OpenUnison/issues/587)
 - Support single logout for kubectl oulogin plugin [\#584](https://github.com/TremoloSecurity/OpenUnison/issues/584)
 - scalejs register - make work better with mix between name and label [\#579](https://github.com/TremoloSecurity/OpenUnison/issues/579)
 - Support group mapping mechanism in k8s [\#577](https://github.com/TremoloSecurity/OpenUnison/issues/577)
 - Add javascript custom tasks for provisioning [\#77](https://github.com/TremoloSecurity/OpenUnison/issues/77)
 - Better GitOps support for secrets [\#582](https://github.com/TremoloSecurity/OpenUnison/issues/582)
 - Kubernetes patch - support json patch [\#581](https://github.com/TremoloSecurity/OpenUnison/issues/581)
 - make myvd cert loading easier [\#578](https://github.com/TremoloSecurity/OpenUnison/issues/578)
 - make changing logos easier [\#576](https://github.com/TremoloSecurity/OpenUnison/issues/576)
 - Add oauth2 token exchange [\#570](https://github.com/TremoloSecurity/OpenUnison/issues/570)
 - Create AMQ connection factory [\#568](https://github.com/TremoloSecurity/OpenUnison/issues/568)
 - Oidc auth - support config by issuer [\#565](https://github.com/TremoloSecurity/OpenUnison/issues/565)
 - Oidc Idp - Support URI different then name [\#564](https://github.com/TremoloSecurity/OpenUnison/issues/564)
 - Rewrite Location response header regardless of case [\#560](https://github.com/TremoloSecurity/OpenUnison/issues/560)
 - Pull github groups into groups attribute [\#559](https://github.com/TremoloSecurity/OpenUnison/issues/559)
 - Create insert to map URI roots [\#557](https://github.com/TremoloSecurity/OpenUnison/issues/557)
 - scalejs main - flag to detect if approvals and reports are enabled [\#555](https://github.com/TremoloSecurity/OpenUnison/issues/555)

**bugs:**
 - Exception when database group has no members [\#586](https://github.com/TremoloSecurity/OpenUnison/issues/586)
 - dynamic jobs not loading on startup [\#585](https://github.com/TremoloSecurity/OpenUnison/issues/585)
 - Java module overlap causing build issuers [\#567](https://github.com/TremoloSecurity/OpenUnison/issues/567)
 - k8s dashboard not generating correct issuer [\#563](https://github.com/TremoloSecurity/OpenUnison/issues/563)
 - GitLab provider - checking wrong attribute for user name [\#562](https://github.com/TremoloSecurity/OpenUnison/issues/562)
 - Unicode characters in request reason causing workflow to fail to write [\#561](https://github.com/TremoloSecurity/OpenUnison/issues/561)
 - Loading AuthMechs and Chains from K8s not updating configuration [\#558](https://github.com/TremoloSecurity/OpenUnison/issues/558)

## 1.0.23-2021053101

**bugs:**
 - k8s watches - broken connections to the API server fails to recover [\#553](https://github.com/TremoloSecurity/OpenUnison/issues/553)
 - post auth redirects - X-FORWARDED-PROTO not honored [\#548](https://github.com/TremoloSecurity/OpenUnison/issues/548)
 - query parameters with no value crashes request [\#551](https://github.com/TremoloSecurity/OpenUnison/issues/551)
 - oidc idp - not honoring X-Forwarded-Proto in issuer [\#549](https://github.com/TremoloSecurity/OpenUnison/issues/549)
 - Saml2 AuthnRequest POST signature verification fails [\#547](https://github.com/TremoloSecurity/OpenUnison/issues/547)
 - CheckK8sProject - not backwards compatible [\#546](https://github.com/TremoloSecurity/OpenUnison/issues/546)
 - BasicDB - ManyToMany groups fails with MySQL 8 if groups table is named "groups" [\#529](https://github.com/TremoloSecurity/OpenUnison/issues/529)
 - OIDC IDP: make scopes configurable [\#543](https://github.com/TremoloSecurity/OpenUnison/issues/543)
 - Remove debug code from the github auth mech [\#533](https://github.com/TremoloSecurity/OpenUnison/issues/533)

**enhancements:**
 - k8s watchers - include params in all read objects [\#552](https://github.com/TremoloSecurity/OpenUnison/issues/552)
 - k8s/openshift target - support expiring "legacy" tokens [\#550](https://github.com/TremoloSecurity/OpenUnison/issues/550)
 - AzureAD invited users slower to provision [\#545](https://github.com/TremoloSecurity/OpenUnison/issues/545)
 - Dynamically load Authentication Mechanisms [\#539](https://github.com/TremoloSecurity/OpenUnison/issues/539)
 - Load queue configuration from CRD [\#544](https://github.com/TremoloSecurity/OpenUnison/issues/544)
 - Dynamically load Applications [\#541](https://github.com/TremoloSecurity/OpenUnison/issues/541)
 - Dynamically load Authentication Chains [\#540](https://github.com/TremoloSecurity/OpenUnison/issues/540)
 - Dynamically Load Custom Authorizations [\#538](https://github.com/TremoloSecurity/OpenUnison/issues/538)
 - Better support for Azure Service Bus [\#536](https://github.com/TremoloSecurity/OpenUnison/issues/536)
 - Load ResultGroups dynamically [\#535](https://github.com/TremoloSecurity/OpenUnison/issues/535)

**Tasks:**
 - 1.0.23 build [\#534](https://github.com/TremoloSecurity/OpenUnison/issues/534)


## 1.0.22-2021041601

**Tasks:**
 - 1.0.22 Build [\#532](https://github.com/TremoloSecurity/OpenUnison/issues/532)

**bugs:**
 - gitlab integration broken [\#525](https://github.com/TremoloSecurity/OpenUnison/issues/525)
 - In some instances, global session cookies not honoring secure and http [\#530](https://github.com/TremoloSecurity/OpenUnison/issues/530)

## 1.0.21-2021031601

**enhancements:**
 - Upgrade to OpenSAML 4 [\#523](https://github.com/TremoloSecurity/OpenUnison/issues/523)
 - Update to Java 11 [\#524](https://github.com/TremoloSecurity/OpenUnison/issues/524)
 - k8s target - more configurable token management [\#491](https://github.com/TremoloSecurity/OpenUnison/issues/491)
 - MyVD - list new attribute types [\#520](https://github.com/TremoloSecurity/OpenUnison/issues/520)
 - Better Okta MyVD support [\#519](https://github.com/TremoloSecurity/OpenUnison/issues/519)
 - k8s - task to clean labels [\#482](https://github.com/TremoloSecurity/OpenUnison/issues/482)
 - oidc idp - pre-process JWT before signing [\#488](https://github.com/TremoloSecurity/OpenUnison/issues/488)
 - k8s - support writing to git [\#481](https://github.com/TremoloSecurity/OpenUnison/issues/481)
 - create dynamic reports [\#487](https://github.com/TremoloSecurity/OpenUnison/issues/487)
 - k8s dynamic queues [\#478](https://github.com/TremoloSecurity/OpenUnison/issues/478)
 - support mattermost provisioning [\#502](https://github.com/TremoloSecurity/OpenUnison/issues/502)
 - support SameSite parameter in cookies [\#483](https://github.com/TremoloSecurity/OpenUnison/issues/483)
 - kubernetes target - support direct certificate configuration [\#480](https://github.com/TremoloSecurity/OpenUnison/issues/480)
 - k8s dynamic jobs [\#477](https://github.com/TremoloSecurity/OpenUnison/issues/477)
 - k8s dynamic provisioning target [\#475](https://github.com/TremoloSecurity/OpenUnison/issues/475)
 - move from openshift 3 to 4 apis [\#508](https://github.com/TremoloSecurity/OpenUnison/issues/508)
 - k8s dynamic workflows [\#476](https://github.com/TremoloSecurity/OpenUnison/issues/476)
 - Provision to remote k8s clusters [\#489](https://github.com/TremoloSecurity/OpenUnison/issues/489)
 - support cdata in filter parameters [\#496](https://github.com/TremoloSecurity/OpenUnison/issues/496)
 - dynamically call workflows [\#479](https://github.com/TremoloSecurity/OpenUnison/issues/479)
 - create k8s watch framework [\#473](https://github.com/TremoloSecurity/OpenUnison/issues/473)

**Tasks:**
 - Remove apacheds-m20 from openunison-webapp [\#521](https://github.com/TremoloSecurity/OpenUnison/issues/521)
 - 1.0.21 build [\#474](https://github.com/TremoloSecurity/OpenUnison/issues/474)

**bugs:**
 - Streaming logs through reverse proxy stops after about 30 seconds [\#517](https://github.com/TremoloSecurity/OpenUnison/issues/517)
 - AzureAD - premature closed connection causing exception [\#516](https://github.com/TremoloSecurity/OpenUnison/issues/516)
 - oauth2 jwt verifier not verifying audiences [\#500](https://github.com/TremoloSecurity/OpenUnison/issues/500)
 - ScaleJS Main - When using an external session (k8s) session check doesn't work [\#501](https://github.com/TremoloSecurity/OpenUnison/issues/501)
 - gitlab provider - searching for username returns all users that start with user [\#495](https://github.com/TremoloSecurity/OpenUnison/issues/495)
 - oidc idp - json errors not returned when expected [\#498](https://github.com/TremoloSecurity/OpenUnison/issues/498)
 - if `#[]` is the first character of a string, it's ignored [\#497](https://github.com/TremoloSecurity/OpenUnison/issues/497)


## 1.0.20-2020082001

**Tasks:**
 - 1.0.20 build [\#458](https://github.com/TremoloSecurity/OpenUnison/issues/458)

**enhancements:**
 - create workflow export utility [\#461](https://github.com/TremoloSecurity/OpenUnison/issues/461)
 - dynamic organizations [\#471](https://github.com/TremoloSecurity/OpenUnison/issues/471)
 - Portal URL - dynamicly load portal URLs [\#464](https://github.com/TremoloSecurity/OpenUnison/issues/464)
 - Oidc Idp  - Dynamic Trusts [\#462](https://github.com/TremoloSecurity/OpenUnison/issues/462)
 - gitlab provisioning target [\#469](https://github.com/TremoloSecurity/OpenUnison/issues/469)
 - ArgoCD Support [\#470](https://github.com/TremoloSecurity/OpenUnison/issues/470)
 - custom task - support content in the tag [\#465](https://github.com/TremoloSecurity/OpenUnison/issues/465)
 - Oidc Idp - support multiple redirectURI values [\#463](https://github.com/TremoloSecurity/OpenUnison/issues/463)
 - create decode lastmile filter [\#460](https://github.com/TremoloSecurity/OpenUnison/issues/460)

**bugs:**
 - azuread provisioning provider - single quote not escaped properly [\#472](https://github.com/TremoloSecurity/OpenUnison/issues/472)
 - OpenShift Target - pull host/port on every call [\#466](https://github.com/TremoloSecurity/OpenUnison/issues/466)
 - K8s saml2 metadata check - namespace tags not supported [\#468](https://github.com/TremoloSecurity/OpenUnison/issues/468)
 - Oidc Auth - Redirect not honoring X-Forwarded-Proto [\#467](https://github.com/TremoloSecurity/OpenUnison/issues/467)
 - SAML2 IdP Fails to load completeFed [\#48](https://github.com/TremoloSecurity/OpenUnison/issues/48)

## 1.0.19-2020062101

**Tasks:**
 - 1.0.19 build [\#449](https://github.com/TremoloSecurity/OpenUnison/issues/449)

**bugs:**
 - OpenID Connect - Better error validation [\#455](https://github.com/TremoloSecurity/OpenUnison/issues/455)
 - WebSockets - subProtocol not sent from the downstream system [\#454](https://github.com/TremoloSecurity/OpenUnison/issues/454)
 - ScaleJS Register - dynamic list validation always fails [\#451](https://github.com/TremoloSecurity/OpenUnison/issues/451)
 - AzureAD provisioning target does not renew credentials [\#450](https://github.com/TremoloSecurity/OpenUnison/issues/450)

**enhancements:**
 - jit task to map remote group to local group [\#453](https://github.com/TremoloSecurity/OpenUnison/issues/453)
 - Create JMS keepalive for queue management [\#411](https://github.com/TremoloSecurity/OpenUnison/issues/411)

## 1.0.18-2020040901

**Tasks:**
 - GittHub login - remove use of `access_token` in api calls [\#440](https://github.com/TremoloSecurity/OpenUnison/issues/440)
 - 1.0.18 build [\#383](https://github.com/TremoloSecurity/OpenUnison/issues/383)
 - Remove undertow subproject [\#448](https://github.com/TremoloSecurity/OpenUnison/issues/448)
 - Remove JBoss 7.x support [\#447](https://github.com/TremoloSecurity/OpenUnison/issues/447)

**enhancements:**
 - CreateK8sObject - support put [\#432](https://github.com/TremoloSecurity/OpenUnison/issues/432)
 - Create better mapping authentication mechanism [\#441](https://github.com/TremoloSecurity/OpenUnison/issues/441)
 - azuread provisioning support [\#446](https://github.com/TremoloSecurity/OpenUnison/issues/446)
 - Create JMS keepalive for queue management [\#411](https://github.com/TremoloSecurity/OpenUnison/issues/411)
 - K8s token - if no cert don't set in kubectl [\#443](https://github.com/TremoloSecurity/OpenUnison/issues/443)
 - Better widows support for kubectl [\#442](https://github.com/TremoloSecurity/OpenUnison/issues/442)
 - SAML2 Auth - Support multiple certificates [\#417](https://github.com/TremoloSecurity/OpenUnison/issues/417)
 - kubernetes - update to oidc should extend session in browser [\#420](https://github.com/TremoloSecurity/OpenUnison/issues/420)
 - Better support for suitecrm [\#430](https://github.com/TremoloSecurity/OpenUnison/issues/430)
 - ScaleJS Register - Add dynamic lookup for LDAP [\#405](https://github.com/TremoloSecurity/OpenUnison/issues/405)
 - k8s impersonation support [\#360](https://github.com/TremoloSecurity/OpenUnison/issues/360)
 - add support for okta apis [\#393](https://github.com/TremoloSecurity/OpenUnison/issues/393)
 - better metrics support [\#400](https://github.com/TremoloSecurity/OpenUnison/issues/400)
 - support patching k8s objects [\#406](https://github.com/TremoloSecurity/OpenUnison/issues/406)
 - LDAP listeners for OpenUnison [\#399](https://github.com/TremoloSecurity/OpenUnison/issues/399)
 - openshift/k8s target - trust ca certificate from pod [\#412](https://github.com/TremoloSecurity/OpenUnison/issues/412)
 - dyanmic workflows - add user data [\#408](https://github.com/TremoloSecurity/OpenUnison/issues/408)
 - ScaleJS Operators - Add way to add filter to search request [\#407](https://github.com/TremoloSecurity/OpenUnison/issues/407)
 - Integrate DUO auth code [\#384](https://github.com/TremoloSecurity/OpenUnison/issues/384)
 - AD Provisioning Target - Add create group support [\#404](https://github.com/TremoloSecurity/OpenUnison/issues/404)
 - OAuth2 JWT auth - Support discovery url [\#403](https://github.com/TremoloSecurity/OpenUnison/issues/403)
 - Validate k8s service accounts [\#387](https://github.com/TremoloSecurity/OpenUnison/issues/387)
 - Add support for PATCH [\#386](https://github.com/TremoloSecurity/OpenUnison/issues/386)
 - Add method to dynamiclly exclude configuration items [\#385](https://github.com/TremoloSecurity/OpenUnison/issues/385)
 - Oauth2 JWT authentication support [\#382](https://github.com/TremoloSecurity/OpenUnison/issues/382)

**bugs:**
 - Oidc: Compare hd to hd attribute from id_token [\#444](https://github.com/TremoloSecurity/OpenUnison/issues/444)
 - Better logging and error reporting on failed logins [\#437](https://github.com/TremoloSecurity/OpenUnison/issues/437)
 - k8s impersonation needs to inject system:authenticated into groups [\#431](https://github.com/TremoloSecurity/OpenUnison/issues/431)
 - ScaleJS Operator - search user with missing attributes fails [\#418](https://github.com/TremoloSecurity/OpenUnison/issues/418)
 - Better error checking in k8s crd user provisioning [\#368](https://github.com/TremoloSecurity/OpenUnison/issues/368)
 - DB provisioning - can't log updates [\#409](https://github.com/TremoloSecurity/OpenUnison/issues/409)
 - Add group to target doesn't respect parameters [\#402](https://github.com/TremoloSecurity/OpenUnison/issues/402)
 - callworkflow task doesn't work when its a subtask [\#273](https://github.com/TremoloSecurity/OpenUnison/issues/273)

## 1.0.17-2019070901

**Tasks:**
 - 1.0.17 Build [\#373](https://github.com/TremoloSecurity/OpenUnison/issues/373)

**bugs:**
 - excessive logging with oidc [\#379](https://github.com/TremoloSecurity/OpenUnison/issues/379)
 - mapping authmech doesn't handle when a source doesn't exist [\#380](https://github.com/TremoloSecurity/OpenUnison/issues/380)

## 1.0.17-2019070801

**Tasks:**
 - 1.0.17 Build [\#373](https://github.com/TremoloSecurity/OpenUnison/issues/373)

**bugs:**
 - check saml idp job doesn't use internal cert store [\#378](https://github.com/TremoloSecurity/OpenUnison/issues/378)



## 1.0.17-2019062401

**Tasks:**
 - 1.0.17 Build [\#373](https://github.com/TremoloSecurity/OpenUnison/issues/373)
 - move prometheus module into main code base [\#366](https://github.com/TremoloSecurity/OpenUnison/issues/366)

**enhancements:**
 - integrate scalejs-operators [\#375](https://github.com/TremoloSecurity/OpenUnison/issues/375)
 - scalejs register - create searchable list control [\#358](https://github.com/TremoloSecurity/OpenUnison/issues/358)
 - oidc idp - flag to sign userinfo response [\#374](https://github.com/TremoloSecurity/OpenUnison/issues/374)
 - Add IBM mq factory to main source code base [\#372](https://github.com/TremoloSecurity/OpenUnison/issues/372)
 - Az Authmech [\#371](https://github.com/TremoloSecurity/OpenUnison/issues/371)
 - GitHub authentication [\#363](https://github.com/TremoloSecurity/OpenUnison/issues/363)
 - Add default options to config parameter replacement [\#370](https://github.com/TremoloSecurity/OpenUnison/issues/370)
 - create drupal 8 provisioning module [\#342](https://github.com/TremoloSecurity/OpenUnison/issues/342)
 - openshift - move off of deprecated apis [\#361](https://github.com/TremoloSecurity/OpenUnison/issues/361)
 - k8s impersonation support [\#360](https://github.com/TremoloSecurity/OpenUnison/issues/360)
 - metadata url for saml2 [\#359](https://github.com/TremoloSecurity/OpenUnison/issues/359)
 - add flags to organizations to determine in what situations they're visible [\#357](https://github.com/TremoloSecurity/OpenUnison/issues/357)
 - Create a dynamic workflow for looking up groups in a db via a provisioning target [\#356](https://github.com/TremoloSecurity/OpenUnison/issues/356)
 - Add launcher for MyVD [\#354](https://github.com/TremoloSecurity/OpenUnison/issues/354)

**bugs:**
 - scalejs register - min characters not checking correctly [\#353](https://github.com/TremoloSecurity/OpenUnison/issues/353)
 - ScaleJS Password - Wrong error report for too many characters [\#351](https://github.com/TremoloSecurity/OpenUnison/issues/351)

## 1.0.16-2019031701

**Tasks:**
 - 1.0.16 Build [\#324](https://github.com/TremoloSecurity/OpenUnison/issues/324)
 - 1.0.15 build [\#312](https://github.com/TremoloSecurity/OpenUnison/issues/312)

**enhancements:**
 - genoidctokens needs host override [\#352](https://github.com/TremoloSecurity/OpenUnison/issues/352)
 - k8s myvd - add flag for always mapping uid [\#349](https://github.com/TremoloSecurity/OpenUnison/issues/349)
 - k8s new project validator [\#345](https://github.com/TremoloSecurity/OpenUnison/issues/345)
 - AWS Services, integrate s3 proxy [\#51](https://github.com/TremoloSecurity/OpenUnison/issues/51)
 - Remove support for alfresco [\#344](https://github.com/TremoloSecurity/OpenUnison/issues/344)
 - better userAccountControl support [\#341](https://github.com/TremoloSecurity/OpenUnison/issues/341)
 - skip sync groups for AD [\#340](https://github.com/TremoloSecurity/OpenUnison/issues/340)
 - OpenShift insert for MyVD [\#339](https://github.com/TremoloSecurity/OpenUnison/issues/339)
 - make oidc idp backend plugable, support CRDs [\#327](https://github.com/TremoloSecurity/OpenUnison/issues/327)
 - MyVD - Support Kubernetes CRD [\#325](https://github.com/TremoloSecurity/OpenUnison/issues/325)
 - CRD provisioning target [\#326](https://github.com/TremoloSecurity/OpenUnison/issues/326)
 - openshift target - pull k8s host from environment variables [\#329](https://github.com/TremoloSecurity/OpenUnison/issues/329)
 - integrate k8s openunison classes [\#334](https://github.com/TremoloSecurity/OpenUnison/issues/334)
 - create way to delete k8s objects on a timer [\#335](https://github.com/TremoloSecurity/OpenUnison/issues/335)
 - Support UPGRADE and websockets [\#332](https://github.com/TremoloSecurity/OpenUnison/issues/332)
 - scalejs k8s token viewer - make kubectl command that includes certs [\#331](https://github.com/TremoloSecurity/OpenUnison/issues/331)
 - make no oidc idp a warning, not an exception [\#330](https://github.com/TremoloSecurity/OpenUnison/issues/330)

**bugs:**
 - support integers in jms factory methods [\#350](https://github.com/TremoloSecurity/OpenUnison/issues/350)
 - multi-valued attributes not loading from claims for oidc auth mech [\#348](https://github.com/TremoloSecurity/OpenUnison/issues/348)
 - custom mappings fail in idp configs [\#347](https://github.com/TremoloSecurity/OpenUnison/issues/347)
 - SAML2 auth mech SLO not working properly [\#346](https://github.com/TremoloSecurity/OpenUnison/issues/346)
 - double groups in db fails to allow login [\#343](https://github.com/TremoloSecurity/OpenUnison/issues/343)
 - speed up openunison builds [\#336](https://github.com/TremoloSecurity/OpenUnison/issues/336)

## 1.0.15-2018070601

**Tasks:**
 - 1.0.15 build [\#312](https://github.com/TremoloSecurity/OpenUnison/issues/312)
 - 1.0.14 build [\#297](https://github.com/TremoloSecurity/OpenUnison/issues/297)

**enhancements:**
 - Support multiple requests with the same password reset email [\#322](https://github.com/TremoloSecurity/OpenUnison/issues/322)
 - reuse myvd db pools in db target [\#311](https://github.com/TremoloSecurity/OpenUnison/issues/311)
 - add support for undertow welcome files [\#317](https://github.com/TremoloSecurity/OpenUnison/issues/317)
 - ScaleJS Main - support textarea and lists for profile updates [\#321](https://github.com/TremoloSecurity/OpenUnison/issues/321)
 - Allow parameters for custom authorizations [\#310](https://github.com/TremoloSecurity/OpenUnison/issues/310)
 - add support for catching error pages [\#315](https://github.com/TremoloSecurity/OpenUnison/issues/315)
 - Check if k8s/openshift objects exist before creation [\#320](https://github.com/TremoloSecurity/OpenUnison/issues/320)
 - create task to copy environment variables into workflow request [\#319](https://github.com/TremoloSecurity/OpenUnison/issues/319)
 - FreeIPA Target - add support for id override [\#318](https://github.com/TremoloSecurity/OpenUnison/issues/318)
 - support case-insensitive routing [\#314](https://github.com/TremoloSecurity/OpenUnison/issues/314)
 - Support trusts with freeipa for provisioning [\#301](https://github.com/TremoloSecurity/OpenUnison/issues/301)
 - provide mechanism for ou to NOT set domain,secure,etc on cookies [\#308](https://github.com/TremoloSecurity/OpenUnison/issues/308)
 - clear all groups provisioning task [\#307](https://github.com/TremoloSecurity/OpenUnison/issues/307)
 - enable http2 support in undertow [\#304](https://github.com/TremoloSecurity/OpenUnison/issues/304)
 - enable unencoded urls in undertow [\#305](https://github.com/TremoloSecurity/OpenUnison/issues/305)
 - Create key cache [\#302](https://github.com/TremoloSecurity/OpenUnison/issues/302)

**bugs:**
 - can't send emails to exchange server that won't allow username and password [\#313](https://github.com/TremoloSecurity/OpenUnison/issues/313)
 - SAML2 - Support multi rp single logout [\#309](https://github.com/TremoloSecurity/OpenUnison/issues/309)

## 1.0.14-2018050402

**Tasks:**
 - 1.0.14 build [\#297](https://github.com/TremoloSecurity/OpenUnison/issues/297)
 - 1.0.13 Build [\#287](https://github.com/TremoloSecurity/OpenUnison/issues/287)
 - Add all attributes from LDAP group to dynamic workflows [\#281](https://github.com/TremoloSecurity/OpenUnison/issues/281)

**enhancements:**
 - add configuration for db connection timeouts [\#299](https://github.com/TremoloSecurity/OpenUnison/issues/299)
 - Add secret key generation to OpenUnison utils [\#296](https://github.com/TremoloSecurity/OpenUnison/issues/296)
 - Add flag for cert data to allow cert to be for CA [\#300](https://github.com/TremoloSecurity/OpenUnison/issues/300)
 - Move from JCEKS to PKCS12 [\#294](https://github.com/TremoloSecurity/OpenUnison/issues/294)
 - Support OpenShift 3.9 [\#298](https://github.com/TremoloSecurity/OpenUnison/issues/298)
 - Support html for email notifications [\#284](https://github.com/TremoloSecurity/OpenUnison/issues/284)
 - saml2 idp eliminate jsp [\#286](https://github.com/TremoloSecurity/OpenUnison/issues/286)
 - "Dev" mode for openid connect to not validate redirect_uri [\#285](https://github.com/TremoloSecurity/OpenUnison/issues/285)

**bugs:**
 - ScaleJS Main - user service does not return attributes in the order they're defined [\#288](https://github.com/TremoloSecurity/OpenUnison/issues/288)

## 1.0.13-2018032401

**Tasks:**
 - 1.0.13 Build [\#287](https://github.com/TremoloSecurity/OpenUnison/issues/287)
 - Add all attributes from LDAP group to dynamic workflows [\#281](https://github.com/TremoloSecurity/OpenUnison/issues/281)

**enhancements:**
 - Support html for email notifications [\#284](https://github.com/TremoloSecurity/OpenUnison/issues/284)
 - saml2 idp eliminate jsp [\#286](https://github.com/TremoloSecurity/OpenUnison/issues/286)
 - "Dev" mode for openid connect to not validate redirect_uri [\#285](https://github.com/TremoloSecurity/OpenUnison/issues/285)
 - Update openshift AddGroupToRole task for openshift 3.7 [\#282](https://github.com/TremoloSecurity/OpenUnison/issues/282)
 - 1.0.12 build [\#243](https://github.com/TremoloSecurity/OpenUnison/issues/243)

**bugs:**
 - ScaleJS Main - user service does not return attributes in the order they're defined [\#288](https://github.com/TremoloSecurity/OpenUnison/issues/288)
 - check for multipart upload breaks multipart application data [\#283](https://github.com/TremoloSecurity/OpenUnison/issues/283)
 - Strip comments from inbound SAML2 assertions [\#279](https://github.com/TremoloSecurity/OpenUnison/issues/279)

## 1.0.12-2018010801
**bugs:**
 - bug in dlq checker [\#276](https://github.com/TremoloSecurity/OpenUnison/issues/276)
 - db provisioning target throws exception when user not found [\#275](https://github.com/TremoloSecurity/OpenUnison/issues/275)
 - if opensession is not named tremoloOpenSession, creates memory leak [\#271](https://github.com/TremoloSecurity/OpenUnison/issues/271)
 - queue listener - no exception if error occurs during initialization [\#269](https://github.com/TremoloSecurity/OpenUnison/issues/269)
 - URLHolder generates exception if proxyTo doesn't contain a '$e [\#267](https://github.com/TremoloSecurity/OpenUnison/issues/267)
 - oidc auth mech doesn't work with context roots off of / [\#266](https://github.com/TremoloSecurity/OpenUnison/issues/266)
 - Header names in HttpFilter implementations not case insensitive [\#34](https://github.com/TremoloSecurity/OpenUnison/issues/34)
 - OpenID Connect - Support client secret in Authorization header [\#264](https://github.com/TremoloSecurity/OpenUnison/issues/264)
 - OpenUnisonOnUndertow - fix configuration of allowed protocols [\#261](https://github.com/TremoloSecurity/OpenUnison/issues/261)
 - Reverse Proxy - configure number of threads per session per route [\#259](https://github.com/TremoloSecurity/OpenUnison/issues/259)
 - Moving OpenUnison to a new root fails to load oidc/saml2 correctly [\#258](https://github.com/TremoloSecurity/OpenUnison/issues/258)
 - HSTS header not correct - sending incorrect max age [\#257](https://github.com/TremoloSecurity/OpenUnison/issues/257)
 - openunison on undertow failing with logging error [\#255](https://github.com/TremoloSecurity/OpenUnison/issues/255)
 - openunison on undertow printing full config to std out [\#254](https://github.com/TremoloSecurity/OpenUnison/issues/254)
 - openunison-utils - export metadata failing [\#240](https://github.com/TremoloSecurity/OpenUnison/issues/240)
 - Class cast exception in freeipa target [\#245](https://github.com/TremoloSecurity/OpenUnison/issues/245)
 - fix register issue with button still showing [\#235](https://github.com/TremoloSecurity/OpenUnison/issues/235)
 - openunison util dlq clearer doesn't work [\#233](https://github.com/TremoloSecurity/OpenUnison/issues/233)
 - saml2 failing  [\#232](https://github.com/TremoloSecurity/OpenUnison/issues/232)
 - certificate auth - CRL check not triggered if client cert chain does not include signer [\#230](https://github.com/TremoloSecurity/OpenUnison/issues/230)
 - Compliance - if uid attribute doesn't exist there's an NPE [\#226](https://github.com/TremoloSecurity/OpenUnison/issues/226)
 - ScaleJS Register - Min/Max values not working [\#221](https://github.com/TremoloSecurity/OpenUnison/issues/221)
 - section 508 scalejs - empty "h" in model dialog [\#216](https://github.com/TremoloSecurity/OpenUnison/issues/216)
 - section 508 scalejs - empty "h1" after "Logging In" [\#212](https://github.com/TremoloSecurity/OpenUnison/issues/212)

**enhancements:**
 - show certificates for k8s and openunison in scalejs token [\#274](https://github.com/TremoloSecurity/OpenUnison/issues/274)
 - 1.0.12 build [\#243](https://github.com/TremoloSecurity/OpenUnison/issues/243)
 - clean up queue management in pre-built jobs [\#272](https://github.com/TremoloSecurity/OpenUnison/issues/272)
 - unexpected closed connections not handled well [\#270](https://github.com/TremoloSecurity/OpenUnison/issues/270)
 - Queue Listeners - support unencrypted messages [\#268](https://github.com/TremoloSecurity/OpenUnison/issues/268)
 - Add support for not requiring a client_secret in oidc idp trust config [\#142](https://github.com/TremoloSecurity/OpenUnison/issues/142)
 - kubernetes - process for creating objects [\#265](https://github.com/TremoloSecurity/OpenUnison/issues/265)
 - Include HttpContext in reverse proxy [\#262](https://github.com/TremoloSecurity/OpenUnison/issues/262)
 - Generate kube config from template [\#152](https://github.com/TremoloSecurity/OpenUnison/issues/152)
 - add context option to openunison on undertow [\#256](https://github.com/TremoloSecurity/OpenUnison/issues/256)
 - Run OpenUnison on Undertow [\#220](https://github.com/TremoloSecurity/OpenUnison/issues/220)
 - Support for multiple fields in password reset auth [\#251](https://github.com/TremoloSecurity/OpenUnison/issues/251)
 - Add LDAP-->JSON support to MyVD [\#250](https://github.com/TremoloSecurity/OpenUnison/issues/250)
 - Add configuration pre-processor [\#252](https://github.com/TremoloSecurity/OpenUnison/issues/252)
 - Add LDAP-->JSON support as a web service [\#249](https://github.com/TremoloSecurity/OpenUnison/issues/249)
 - Support Azure Service Bus for JMS integration [\#253](https://github.com/TremoloSecurity/OpenUnison/issues/253)
 - Add option for scalejs password to be synchronous [\#247](https://github.com/TremoloSecurity/OpenUnison/issues/247)
 - add copy&paste button to scalejs token [\#246](https://github.com/TremoloSecurity/OpenUnison/issues/246)
 - Add textfield to scalejs register [\#237](https://github.com/TremoloSecurity/OpenUnison/issues/237)
 - ScaleJS Register - Make attributes optional [\#223](https://github.com/TremoloSecurity/OpenUnison/issues/223)
 - support for hsts header [\#242](https://github.com/TremoloSecurity/OpenUnison/issues/242)
 - Support httponly flag [\#241](https://github.com/TremoloSecurity/OpenUnison/issues/241)
 - ldap provisioning target - support dynamic DNs [\#239](https://github.com/TremoloSecurity/OpenUnison/issues/239)
 - Support SQS FIFO Queues [\#238](https://github.com/TremoloSecurity/OpenUnison/issues/238)
 - Support multiple task queues [\#234](https://github.com/TremoloSecurity/OpenUnison/issues/234)
 - Add queue listener that triggers a workflow [\#229](https://github.com/TremoloSecurity/OpenUnison/issues/229)
 - LDAP provisioning target - get search base [\#231](https://github.com/TremoloSecurity/OpenUnison/issues/231)
 - Add errors to access.log [\#217](https://github.com/TremoloSecurity/OpenUnison/issues/217)
 - allow oidc to force authentication [\#227](https://github.com/TremoloSecurity/OpenUnison/issues/227)
 - SQS - Support AWS without access keys [\#219](https://github.com/TremoloSecurity/OpenUnison/issues/219)
 - make it easier to use openunison in automated tests [\#225](https://github.com/TremoloSecurity/OpenUnison/issues/225)
 - ScaleJS Register - Add logged in user as parameter to CreateRegisterUser [\#224](https://github.com/TremoloSecurity/OpenUnison/issues/224)
 - build [\#218](https://github.com/TremoloSecurity/OpenUnison/issues/218)




## 1.0.11-2017061801

**bugs:**
 - section 508 scalejs - empty "h" in model dialog [\#216](https://github.com/TremoloSecurity/OpenUnison/issues/216)
 - section 508 scalejs - empty "h1" after "Logging In" [\#212](https://github.com/TremoloSecurity/OpenUnison/issues/212)
 - NPE when clearing the character encoding in Tomcat 8.5 [\#211](https://github.com/TremoloSecurity/OpenUnison/issues/211)

**enhancements:**
 - db provisioning target - add groups [\#209](https://github.com/TremoloSecurity/OpenUnison/issues/209)
 - Add flag to AddAttribute task to add to request instead of user object [\#206](https://github.com/TremoloSecurity/OpenUnison/issues/206)
 - Add source ip and session id to the access log [\#110](https://github.com/TremoloSecurity/OpenUnison/issues/110)

## 1.0.10-2017042901

**bugs:**
 - cacerts ignored [\#205](https://github.com/TremoloSecurity/OpenUnison/issues/205)
 - if an error occurs when creating an authorization AFTER its committed, log the error don't throw an exception [\#204](https://github.com/TremoloSecurity/OpenUnison/issues/204)
 - compliance lockout creates anon user on failed auth [\#202](https://github.com/TremoloSecurity/OpenUnison/issues/202)
 - Approvals for users not in MyVD shows the subject of the approver, not the requestor [\#200](https://github.com/TremoloSecurity/OpenUnison/issues/200)
 - freeipa errors out if no changes are in the request [\#198](https://github.com/TremoloSecurity/OpenUnison/issues/198)
 - guava outdated [\#197](https://github.com/TremoloSecurity/OpenUnison/issues/197)

**enhancements:**
 - Add favicon.ico with the ts shield [\#203](https://github.com/TremoloSecurity/OpenUnison/issues/203)
 - update scale register to act like single-request [\#196](https://github.com/TremoloSecurity/OpenUnison/issues/196)
 - provisioning target to copy/move user attributes to the request object [\#201](https://github.com/TremoloSecurity/OpenUnison/issues/201)
 - single request - pull attributes from authentication object [\#199](https://github.com/TremoloSecurity/OpenUnison/issues/199)
 - Support U2F [\#191](https://github.com/TremoloSecurity/OpenUnison/issues/191)
 - provisioning task for creating projects [\#195](https://github.com/TremoloSecurity/OpenUnison/issues/195)
 - provisioning task to add group to policy [\#194](https://github.com/TremoloSecurity/OpenUnison/issues/194)
 - provisioning custom task to add group [\#193](https://github.com/TremoloSecurity/OpenUnison/issues/193)
 - Create interface for adding/removing groups from provisioning targets [\#192](https://github.com/TremoloSecurity/OpenUnison/issues/192)

## 1.0.9-2017042301

**bugs:**
 - compliance lockout creates anon user on failed auth [\#202](https://github.com/TremoloSecurity/OpenUnison/issues/202)
 - guava outdated [\#197](https://github.com/TremoloSecurity/OpenUnison/issues/197)

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

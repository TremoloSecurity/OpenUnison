# unison-auth-duo

Add DUO to your systems

## Auth Mech

```
<mechanism name="duo">
        <uri>/auth/duo</uri>
        <className>com.tremolosecurity.proxy.auth.DuoSecLogin</className>
        <init>

        </init>
        <params />
</mechanism>
```

## Auth Chain

```
 <authMech>
    <name>duo</name>
    <required>required</required>
    <params>
      <param name="duoIntegrationKey" value="#[DUO_INTEGRATION_KEY]"/>
      <param name="duoSecretKey" value="#[DUO_SECRET_KEY]"/>
      <param name="duoApiHostName" value="#[DUO_API_HOST]"/>
      <param name="duoAKey" value="#[DUO_A_KEY]"/>
      <param name="userNameAttribute" value="uid"/>
    </params>
 </authMech>
 ```

 ## pom.xml

     <dependency>
      <groupId>com.tremolosecurity.unison</groupId>
      <artifactId>unison-auth-duo</artifactId>
      <version>1.0.17</version>
    </dependency>
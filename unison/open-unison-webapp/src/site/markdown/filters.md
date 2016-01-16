# Filter Configuration Reference

## com.tremolosecurity.prelude.filters.LoginTest

This filter will echo the attributes of the currently logged in user. It's a convinient way to test the login process without having to have an application to proxy or an identity provider configured. Configure this filter on a URL and that URL will use this filter to provide content back to the web browser. No filters configured after this filter are executed.

| name | value | Example |
| ---- | ----- | ------- |
| logoutURI | The URI (no host or port) of the logout url | /logout |
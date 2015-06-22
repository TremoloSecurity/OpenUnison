<?xml version="1.0" encoding="UTF-8" ?>
<!-- 
Copyright 2015 Tremolo Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 -->
<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8" import="com.tremolosecurity.proxy.ConfigSys,com.tremolosecurity.config.util.UrlHolder,com.tremolosecurity.proxy.util.ProxyTools,java.util.*,com.tremolosecurity.proxy.auth.RequestHolder,com.tremolosecurity.proxy.auth.AuthFilter,com.tremolosecurity.proxy.auth.AuthSys,java.util.Iterator,com.tremolosecurity.saml.Attribute,com.tremolosecurity.proxy.auth.*,com.tremolosecurity.proxy.auth.*,com.tremolosecurity.proxy.util.*,com.tremolosecurity.config.util.*"  %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>AutoIDM Post Preservation Page</title>
</head>
<body onload="document.autoForm.submit();">
<%
	System.out.println("session : " + session);
	RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();

	Iterator<String> paramNames = reqHolder.getParams().keySet().iterator();
	
	UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
	
	Cookie sessionCookieName = new Cookie("autoIdmSessionCookieName","DNE");
	String domain = ProxyTools.getInstance().getCookieDomain(holder.getApp().getCookieConfig(),request);
	if (domain != null) {
		sessionCookieName.setDomain(domain);
	}
	sessionCookieName.setPath("/");
	sessionCookieName.setMaxAge(0);
	sessionCookieName.setSecure(false);
	response.addCookie(sessionCookieName);
	
	Cookie appCookieName = new Cookie("autoIdmAppName","DNE");
	domain = ProxyTools.getInstance().getCookieDomain(holder.getApp().getCookieConfig(),request);
	if (domain != null) {
		appCookieName.setDomain(domain);
	}
	appCookieName.setPath("/");
	appCookieName.setMaxAge(0);
	appCookieName.setSecure(false);
	response.addCookie(appCookieName);
%>

<form action="<%= reqHolder.getURL() %>" method="post" name="autoForm" id="autoForm" >
	<% while (paramNames.hasNext())  { %>
		<% String paramName = paramNames.next(); 
		   Attribute attr = reqHolder.getParams().get(paramName);
		   Iterator<String> vals = attr.getValues().iterator();
		   while (vals.hasNext()) {
			   String val = vals.next();
		%>
		
			<input type="hidden" name="<%= paramName %>" value="<%= val %>" />
		
		<% } %>
	
	<% } %>

	<input type="submit" value="submit" />

</form>

<script type="javascript">
	document.form.submit();
</script>

</body>
</html>
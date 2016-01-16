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
    pageEncoding="UTF-8"  import="com.tremolosecurity.proxy.auth.*,java.net.*,com.tremolosecurity.config.util.*,com.tremolosecurity.proxy.util.*,com.tremolosecurity.proxy.*,com.tremolosecurity.proxy.util.*,com.tremolosecurity.config.util.*"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title></title>
</head>
<body>
<%
	UrlHolder holder = (UrlHolder) request.getAttribute("AUTO_IDM_CFG");

Cookie sessionCookieName = new Cookie("autoIdmSessionCookieName","DNE");
sessionCookieName.setDomain(ProxyTools.getInstance().getCookieDomain(holder.getApp().getCookieConfig(), request));
sessionCookieName.setPath("/");
sessionCookieName.setMaxAge(0);
sessionCookieName.setSecure(false);
response.addCookie(sessionCookieName);

Cookie appCookieName = new Cookie("autoIdmAppName","DNE");
appCookieName.setDomain(ProxyTools.getInstance().getCookieDomain(holder.getApp().getCookieConfig(), request));
appCookieName.setPath("/");
appCookieName.setMaxAge(0);
appCookieName.setSecure(false);
response.addCookie(appCookieName);

request.getSession().removeAttribute(ProxyConstants.AUTH_CTL);
UnisonConfigManagerImpl cfg = (UnisonConfigManagerImpl) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);


response.sendRedirect(request.getParameter("target"));
%>
</body>
</html>
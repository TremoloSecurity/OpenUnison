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
	pageEncoding="UTF-8"
	import="com.tremolosecurity.saml.Attribute,java.util.*,com.tremolosecurity.proxy.auth.*,java.net.*,com.tremolosecurity.config.util.*,com.tremolosecurity.proxy.util.*,com.tremolosecurity.proxy.*,com.tremolosecurity.proxy.util.*,com.tremolosecurity.config.util.*"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<%
	RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
	String authURL = "/auth/forms/";

	if (reqHolder != null) {
		ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);

		authURL = cfg.getAuthFormsPath();
	}
	
	AuthController auth = (AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL);
%>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />

<meta http-equiv="X-UA-Compatible" content="IE=edge" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="description" content="" />
<meta name="author" content="" />
<title></title>
<!-- Bootstrap core CSS -->
<link href="<%=authURL%>css/bootstrap.min.css" rel="stylesheet" />

<!-- Custom styles for this template -->
<link href="<%=authURL%>jumbotron-narrow.css" rel="stylesheet" />


<!-- IE10 viewport hack for Surface/desktop Windows 8 bug -->
<!-- <script src="<%=authURL%>assets/js/ie10-viewport-bug-workaround.js"></script>  -->

<!-- HTML5 shim and Respond.js IE8 support of HTML5 elements and media queries -->
<!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->
</head>
<body>

	<div class="container-wide">

		<div class="login-header">
			<h3>Login Testing Page</h3>
		</div>
		<div class="jumbotron">
			<img src="<%=authURL%>images/ts_logo.png" />




			<div>
				<h2>Authentication Data</h2>
				<div class="row">
					<div class="col-md-4" style="text-align: left">
						<b>Authenticated User DN</b>
					</div>
					<div class="col-md-8"
						style="text-align: left; word-wrap: break-word;"><%= auth.getAuthInfo().getUserDN() %></div>
				</div>
				<div class="row">
					<div class="col-md-4" style="text-align: left">
						<b>Authentication Level</b>
					</div>
					<div class="col-md-8"
						style="text-align: left; word-wrap: break-word;"><%= auth.getAuthInfo().getAuthLevel() %></div>
				</div>
				<div class="row">
					<div class="col-md-4" style="text-align: left">
						<b>Authentication Chain</b>
					</div>
					<div class="col-md-8"
						style="text-align: left; word-wrap: break-word;"><%= auth.getAuthInfo().getAuthMethod() %></div>
				</div>
				<h4>Attribute Values</h4>
				<%
				for (String attrName : auth.getAuthInfo().getAttribs().keySet()) {
					Attribute attr = auth.getAuthInfo().getAttribs().get(attrName);
					for (String val : attr.getValues()) {
				
				%>
					<div class="row">
					<div class="col-md-4" style="text-align: left">
						<b><%= attrName %></b>
					</div>
					<div class="col-md-8"
						style="text-align: left; word-wrap: break-word;"><%= val %></div>
				</div>			
				<% }
					}%>
				
				<h2>Headers</h2>
				<%
					Enumeration<String> enumer = request.getHeaderNames();
					while (enumer.hasMoreElements()) {
						String headerName = enumer.nextElement();
						Enumeration<String> venumer = request.getHeaders(headerName);
						while (venumer.hasMoreElements()) {
							String val = venumer.nextElement();
				%>
				<div class="row">
					<div class="col-md-4" style="text-align: left">
						<b><%=headerName%></b>
					</div>
					<div class="col-md-8"
						style="text-align: left; word-wrap: break-word;"><%=val%></div>
				</div>

				<%
					}
					}
				%>



				<h2>Cookies</h2>
				<%
					if (request.getCookies() != null) {
						for (Cookie cookie : request.getCookies()) {
				%>
				<div class="row">
					<div class="col-md-4" style="text-align: left">
						<b><%=cookie.getName()%></b>
					</div>
					<div class="col-md-8"
						style="text-align: left; word-wrap: break-word;"><%=cookie.getValue()%></div>
				</div>
				<%
					}
					} else {
				%>
				<div class="alert alert-danger">
					<h3>No cookies sent from the browser</h3>
				</div>
				<%
					}
				%>

				<h2>Request Attributes</h2>
				<%
					enumer = request.getAttributeNames();
					while (enumer.hasMoreElements()) {
						String name = enumer.nextElement();
				%>
				<div class="row">
					<div class="col-md-4" style="text-align: left">
						<b><%=name%></b>
					</div>
					<div class="col-md-8"
						style="text-align: left; word-wrap: break-word;"><%=request.getAttribute(name)%></div>
				</div>
				<%
					}
				%>
				<h2>Session Attributes</h2>
				<%
					enumer = request.getSession().getAttributeNames();
					while (enumer.hasMoreElements()) {
						String name = enumer.nextElement();
				%>
				<div class="row">
					<div class="col-md-4" style="text-align: left">
						<b><%=name%></b>
					</div>
					<div class="col-md-8"
						style="text-align: left; word-wrap: break-word;"><%=request.getSession().getAttribute(name)%></div>
				</div>
				<%
					}
				%>
				<div class="row">
					<a href="<%= request.getAttribute("UNISON_LOGINTEST_LOGOUTURI") %>">Logout</a>
					
				</div>
			</div>
		</div>
	</div>

</body>
</body>
</html>
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
    pageEncoding="UTF-8" import="com.tremolosecurity.proxy.auth.*,com.tremolosecurity.idp.providers.*,com.tremolosecurity.proxy.util.*,com.tremolosecurity.config.util.*"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<%
	RequestHolder reqHolder = (RequestHolder) session.getAttribute(LoginService.ORIG_REQ_HOLDER);
	String targetURL = "";
	String authURL = "/auth/forms/";

	if (request.getSession().getAttribute(Saml2Idp.SAML2_AUTHN_REQ_URL) != null) {
		targetURL = session.getAttribute(Saml2Idp.SAML2_AUTHN_REQ_URL).toString();	
	} else {

		
	
		if (reqHolder != null) {
			ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
	AuthController au = (AuthController) session.getAttribute(ProxyConstants.AUTH_CTL);
	au.setHolder(reqHolder);
	targetURL =  cfg.getAuthManager().getGetRedirectURL(reqHolder).toString();
	authURL = cfg.getAuthFormsPath();
		}
	}
%>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />

    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="description" content="" />
    <meta name="author" content="" />
<title></title>
<!-- Bootstrap core CSS -->
    <link href="<%= authURL %>css/bootstrap.min.css" rel="stylesheet" />

    <!-- Custom styles for this template -->
    <link href="<%= authURL %>jumbotron-narrow.css" rel="stylesheet" />


    <!-- IE10 viewport hack for Surface/desktop Windows 8 bug -->
    <!-- <script src="assets/js/ie10-viewport-bug-workaround.js"></script>  -->

    <!-- HTML5 shim and Respond.js IE8 support of HTML5 elements and media queries -->
    <!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->
</head>
<body>


<div class="container">
		
		<div class="login-header">
			<h3>Login</h3>	
		</div>
		<div class="jumbotron">
			<img src="<%= authURL %>logos/ts_logo.png" />
			<br />
			<div class="alert alert-danger" role="alert">
			<h2>Login Choice Reset</h2>
Once a choice is made this form can not be re-submitted.  For security reasons, your login must be cleared and re-attempted.  Click <a id="rerunlink" href="<%= targetURL %>">here</a> restart the login process.
</div>
			
		</div>
	</div>

</body>
</html>
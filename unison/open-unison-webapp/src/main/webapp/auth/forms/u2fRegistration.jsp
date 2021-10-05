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
    pageEncoding="UTF-8" import="java.util.*,com.tremolosecurity.proxy.auth.*,com.tremolosecurity.proxy.util.*,com.tremolosecurity.config.util.*"%>
    
<%
RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
String targetURL = "";
String auth = "/auth/forms/";
if (reqHolder != null) {
	ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
	targetURL =  cfg.getAuthManager().getGetRedirectURL(reqHolder).toString();
	auth = cfg.getAuthFormsPath();
}
%>
    
    
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />

    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="description" content="" />
    <meta name="author" content="" />
<title></title>
<!-- Bootstrap core CSS -->
    <link href="<%= auth %>css/bootstrap.min.css" rel="stylesheet" />

    <!-- Custom styles for this template -->
    <link href="<%= auth %>jumbotron-narrow.css" rel="stylesheet" />


    <!-- IE10 viewport hack for Surface/desktop Windows 8 bug -->
    <!--  <script src="forms/assets/js/ie10-viewport-bug-workaround.js"></script>  -->

    <!-- HTML5 shim and Respond.js IE8 support of HTML5 elements and media queries -->
    <!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->
<title></title>
</head>
<body>
<script src="<%= auth %>js/u2f-api.js"></script>
<div id="challengeJSON" style="display:none"><%= request.getSession().getAttribute("com.tremolosecurity.unison.u2f.Registration.request_json") %></div>
<div class="container">
<div class="login-header">
			<h3>Register Your U2F Device</h3>	
		</div>
		<div class="jumbotron">
			<img src="<%= auth %>logos/ts_logo.png" />
			<br />
			
			
<br />
<h4>Please insert your U2F device and activate it to register it to your account</h4>

		<form method="post" action="<%= request.getAttribute("com.tremolosecurity.unison.u2f.Registration.url") %>" id="finishRegistration" name="finishRegistration">
			<input type="hidden" id="tokenResponse" name="tokenResponse" />
			<!-- <input type="submit" id="finishRegister" name="finishRegister"  />  --><!--  style="display:none"  -->
			<img src="<%= auth %>images/pixel.png" id="finishRegister" onclick="document.forms['finishRegistration'].submit();" />
		</form>

 <script>
setTimeout(function() {
  var request = <%= request.getSession().getAttribute("com.tremolosecurity.unison.u2f.Registration.request_json") %>;
  console.log("Register: ", request);
  var appId = request.appId;
  var registerRequests = [{version: request.version, challenge: request.challenge}];
 
  console.log(appId, registerRequests);
  u2f.register(appId,registerRequests, [], function(data) {
    console.log("Register callback", data);
    
    document.getElementById('tokenResponse').value = JSON.stringify(data);
    document.forms["finishRegistration"].submit();
  });
}, 1000);
                      </script>
			
		</div>
	</div>
	
	

</body>
</html>
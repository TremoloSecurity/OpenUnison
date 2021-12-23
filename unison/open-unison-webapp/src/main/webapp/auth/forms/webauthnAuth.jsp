<?xml version="1.0" encoding="UTF-8" ?>
<!-- 
Copyright 2021 Tremolo Security, Inc.

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
    <link href="<%= auth %>js/base64url.js" rel="script" />


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


<div class="container">
<div class="login-header">
			<h3>Authenticate With Your WebAuthn Token</h3>	
		</div>
		<div class="jumbotron">
			<img src="<%= auth %>logos/ts_logo.png" />
			<br />
			
			
<br />
<div id="msg" class="h4">Please insert your webauthn key to complete authentication</div>
<button class="btn btn-lg btn-danger btn-block" type="button" name="login" id="login" onclick="javascript:doAuthentication();">Login</button>
<div>
	<form method="post" action="<%= session.getAttribute("TREMOLO_AUTH_URI") %>" id="webauthnResponseForm">
		<input type="hidden" name="webauthnResponse" id="webauthnResponse" />
		<input type="hidden" name="serverProperty" id="serverProperty" />
	</form>
</div>

<script src="<%= auth %>js/base64url.js"></script>

<script>


function doAuthentication() {
	document.getElementById('login').disabled = true;
	var xhr = new XMLHttpRequest();
    xhr.open('GET', "<%= session.getAttribute("TREMOLO_AUTH_URI") %>?requestOptions=true", true);
    xhr.responseType = 'json';
    
    xhr.onload = function() {

        var status = xhr.status;

        if (status == 200) {
        	var resp = xhr.response;
        	
            resp.publicKey.challenge = base64url.decodeBase64url(resp.publicKey.challenge);
            
            // iterate through each credential and update the id
            for (var i = 0;i < resp.publicKey.allowedCredentials.length;i++) {
            	resp.publicKey.allowedCredentials[i].id = base64url.decodeBase64url(resp.publicKey.allowedCredentials[i].id);	
            }
            
             
            
            document.getElementById("serverProperty").value = resp.serverProperty; 
            
            
            
        	navigator.credentials.get(resp).then((pubKeyCredential) => {
        		var response = pubKeyCredential.response;
        	    var clientExtResults = pubKeyCredential.getClientExtensionResults();
        	
        	    
        	    
        	    
        	    authResponse = {
        	    	"credential_id": base64url.encodeBase64url(new Uint8Array(pubKeyCredential.rawId)),
        	    	"clientExtResults": JSON.stringify(pubKeyCredential.getClientExtensionResults()),
        	    	"clientDataJSON": base64url.encodeBase64url(new Uint8Array(pubKeyCredential.response.clientDataJSON)),
        	    	"authenticatorData" : base64url.encodeBase64url(new Uint8Array(pubKeyCredential.response.authenticatorData)),
        	    	"signature" : base64url.encodeBase64url(new Uint8Array(pubKeyCredential.response.signature)),
        	    	"userHandle" : base64url.encodeBase64url(new Uint8Array(pubKeyCredential.response.userHandle)),
        	    };
        	    
        	    
        	    document.getElementById("webauthnResponse").value = JSON.stringify(authResponse);
        	    document.forms[0].submit();
        	    
        	    
        	}).catch(console.error);
        	
        	
        } else {
            alert("error");
        }
    };

    xhr.send();
}


</script>
			
		</div>
	</div>
	
	

</body>
</html>
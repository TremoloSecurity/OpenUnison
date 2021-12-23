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
			<h3>Register Your WebAuthn Device</h3>	
		</div>
		<div class="jumbotron">
			<img src="<%= auth %>logos/ts_logo.png" />
			<br />
			
			
<br />
<div id="msg" class="h4">Please insert your WebAuthn device, choose a label, and click "Register Device"</div>
<input class="form-control" placeholder="Label"  type="text" id="label" name="label"  /><br/>
<button class="btn btn-lg btn-danger btn-block" type="button" name="register" id="register" onclick="javascript:registerKey();">Register Device</button><br/>
<script src="<%= auth %>js/base64url.js"></script>

<script>


function registerKey() {
	document.getElementById('register').disabled = true;
	var xhr = new XMLHttpRequest();
    xhr.open('GET', "<%= request.getAttribute("tremolo.io/webauthn/challengeurl") %>", true);
    xhr.responseType = 'json';
    
    xhr.onload = function() {

        var status = xhr.status;

        if (status == 200) {
        	var resp = xhr.response;
        	
            resp.publicKey.challenge = base64url.decodeBase64url(resp.publicKey.challenge);
            resp.publicKey.user.id = base64url.decodeBase64url(resp.publicKey.user.id); 
            
            var serverProperty = resp.serverProperty;
            
            
        	navigator.credentials.create(resp).then((pubKeyCredential) => {
        		//alert("here");
        		//alert(pubKeyCredential);
        		var response = pubKeyCredential.response;
        	    var clientExtResults = pubKeyCredential.getClientExtensionResults();
        	    //alert(JSON.stringify(clientExtResults));
        	    //alert(base64url.encodeBase64url(pubKeyCredential.response.clientDataJSON));
        	    
        	    registrationResponse = {
        	    	"clientExtResults": JSON.stringify(pubKeyCredential.getClientExtensionResults()),
        	    	"clientDataJSON": base64url.encodeBase64url(pubKeyCredential.response.clientDataJSON),
        	    	"attestationObject" : base64url.encodeBase64url(pubKeyCredential.response.attestationObject),
        	    	"serverProperty": serverProperty,
        	    	"label": document.getElementById("label").value
        	    };
        	    
        	    
        	    var xhr = new XMLHttpRequest();
        	    xhr.open('POST', "<%= request.getAttribute("tremolo.io/webauthn/finishregistration") %>", true);
        	    xhr.setRequestHeader("Content-Type", "application/json");
        	    xhr.responseType = 'json';
        	    
        	    xhr.onload = function() {

        	        var status = xhr.status;

        	        if (status == 200) {
        	        	document.getElementById("msg").innerHTML="Registration complete, you may now login with your WebAuthn device";   	
        	        } else {
        	        	document.getElementById('register').disabled = false;
        	        	document.getElementById("msg").innerHTML = xhr.response.error;
        	        }
        	    }
        	    
        	    xhr.send(JSON.stringify(registrationResponse));
        	    
        	    
        	}).catch(console.error);
        	
        	
        } else {
        	document.getElementById('register').disabled = false;
        	document.getElementById('msg').value = xhr.response.error;
        }
    };

    xhr.send();
}


</script>
			
		</div>
	</div>
	
	

</body>
</html>
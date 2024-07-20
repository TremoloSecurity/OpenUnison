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
    
<!DOCTYPE html>
<html lang="en">
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
    


<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
  <meta http-equiv="x-ua-compatible" content="ie=edge" />
  <title>OpenUnison Login</title>
  <!-- MDB icon -->
  <link rel="icon" href="<%= auth %>img/mdb-favicon.ico" type="image/x-icon" />
  <!-- Font Awesome -->
  <link rel="stylesheet" href="<%= auth %>css-mdb/all.min.css" />
  <!-- Google Fonts Roboto -->
  <link rel="stylesheet" href="<%= auth %>css-mdb/fonts.css" />
  <!-- MDB -->
  <link rel="stylesheet" href="<%= auth %>css-mdb/mdb.min.css" />
</head>

<body>
  <div class="row">
    <div class="col vh-100 d-none d-md-block col-md-5 col-lg-6 col-xl-8 d-inline-block"
      style="background-color: #AC1622;">

    </div>
    <div class="col vh-100 col-md-7 col-lg-6 col-xl-4 d-inline-block d-flex align-items-center ">
      <div class="container">
        <div class="bg-white rounded shadow-5-strong p-5" >
          <div class="row row-cols-1  ">
            <div class="col text-center"><img src="<%= auth %>img/ts_logo.png" class="center-block" /></div>

          </div>
          <div class="row row-cols-1">
            <div class="col text-center"><h1>Register Your WebAuthn Device</h1></div>
          </div>
          <div class="row row-cols-1">
            <div class="col">
              <div class="alert alert-primary" id="msg">
              	Please insert your WebAuthn device, choose a label, and click "Register Device"
              </div>
            </div>
          </div>
          <div class="row row-cols-1">
            <div class="col">
              <div class="form-outline mb-4" data-mdb-input-init>
                <input type="text" id="label" name="label" class="form-control" />
                <label class="form-label" for="user">Label</label>
              </div>
            </div>
          </div>
          <div class="row row-cols-1">
            <div class="col">
              <button type="button" id="register" name="register" class="btn btn-primary btn-block" data-mdb-ripple-init onclick="javascript:registerKey();">Register Device</button>
            </div>
            
          </div>
          <input type="hidden" name="target" id="target" value="<%=targetURL%>" />
        </div>
      </div>

    </div>
  </div>

  <!-- End your project here-->

  <!-- MDB -->
  <script type="text/javascript" src="<%= auth %>js-mdb/mdb.umd.min.js"></script>
  <!-- Custom scripts -->
  <script type="text/javascript"></script>
  
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
</body>

</html>


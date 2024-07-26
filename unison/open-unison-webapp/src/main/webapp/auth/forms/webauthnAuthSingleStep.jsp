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
	pageEncoding="UTF-8"
	import="java.util.*,com.tremolosecurity.proxy.auth.*,com.tremolosecurity.proxy.util.*,com.tremolosecurity.config.util.*"%>
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
    <form class="col vh-100 col-md-7 col-lg-6 col-xl-4 d-inline-block d-flex align-items-center " method="post" action="<%= session.getAttribute("TREMOLO_AUTH_URI") %>" id="webauthnResponseForm">
      <div class="container">
        <div class="bg-white rounded shadow-5-strong p-5" >
          <div class="row row-cols-1  ">
            <div class="col text-center"><img src="<%= auth %>images/ts_logo.png" class="center-block" /></div>

          </div>
          <div class="row row-cols-1">
            <div class="col text-center"><h1>Authenticate With Your WebAuthn Token</h1></div>
          </div>
          <div class="row row-cols-1">
            <div class="col">
              <div class="alert alert-primary" id="msg">
              	Please insert your webauthn key to complete authentication
              </div>
            </div>
          </div>
          
          <div class="row row-cols-1">
            <div class="col">
              <button type="button" id="login" name="login" class="btn btn-primary btn-block" data-mdb-ripple-init onclick="javascript:loginClick();">Login</button>
              <div>
						<input type="hidden" name="webauthnResponse" id="webauthnResponse" />
						<input type="hidden" name="serverProperty" id="serverProperty" />
				</div>
            </div>
            
          </div>
          <div class="row row-cols-1">
            <div class="col">
              <div class="form-outline mb-4" data-mdb-input-init>
                <input type="text" id="username" name="username" class="form-control" autocomplete="username webauthn" />
                <label class="form-label" for="username">User Name</label>
              </div>
            </div>
          </div>
          
          <% if (((Boolean)request.getSession().getAttribute("webauthn.allowpassword"))) { %>
          
          <div class="row row-cols-1">
            <div class="col">
              <div class="form-outline mb-4" data-mdb-input-init>
                <input type="password" id="password" name="password" class="form-control" />
                <label class="form-label" for="password">Password</label>
              </div>
            </div>
          </div>
          
          <% } %>
          
        </div>
      </div>

    </form>
  </div>

  <!-- End your project here-->

  <!-- MDB -->
  <script type="text/javascript" src="<%= auth %>js-mdb/mdb.umd.min.js"></script>
  <!-- Custom scripts -->
  <script type="text/javascript"></script>
  
  <script src="<%= auth %>js/base64url.js"></script>

<script>
//initialize the webauthn process and generate a promise

(async () => {
    if (
      typeof window.PublicKeyCredential !== 'undefined'
      && typeof window.PublicKeyCredential.isConditionalMediationAvailable === 'function'
    ) {
      const available = await PublicKeyCredential.isConditionalMediationAvailable();

      if (available) {
        try {
          doAuthentication();
        } catch (err) {
          console.error('Error with conditional UI:', err);
        }
      }
    }
  })();

function loginClick() {
	
	//check to see if a password is set for legacy authentication
	if (document.getElementById("username").value != "" && document.getElementById("password") && document.getElementById("password").value != "") {
		
		document.getElementById("webauthnResponse").value = "";
	    document.forms[0].submit();
	    
		
	} else {
		doAuthentication();
	}
	
}

function doAuthentication() {
	
	var xhr = new XMLHttpRequest();
    xhr.open('GET', "<%= session.getAttribute("TREMOLO_AUTH_URI") %>?requestOptions=true", true);
    xhr.responseType = 'json';
    
    xhr.onload = function() {

        var status = xhr.status;

        if (status == 200) {
        	var resp = xhr.response;
        	
            resp.publicKey.challenge = base64url.decodeBase64url(resp.publicKey.challenge);
            
            // iterate through each credential and update the id
            if (resp.publicKey.allowedCredentials) {
	            for (var i = 0;i < resp.publicKey.allowedCredentials.length;i++) {
	            	resp.publicKey.allowedCredentials[i].id = base64url.decodeBase64url(resp.publicKey.allowedCredentials[i].id);	
	            }
            }
            
             
            
            document.getElementById("serverProperty").value = resp.serverProperty; 
            
            var authResp = {};
            authResp.serverProperty = resp.serverProperty;
            
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
        	    
        	    authResp.webauthnResponse = authResponse;
        	    
        	    
        	    
        	    
        	    
        	    var postAuth = new XMLHttpRequest();
        	    postAuth.open('POST',"<%= session.getAttribute("TREMOLO_AUTH_URI") %>", true);
        	    postAuth.setRequestHeader("Content-Type","application/json; charset=UTF-8");
        	    postAuth.onload = function() {
        	    	if (postAuth.status == 200) {
        	    		document.forms[0].submit();
        	    		return;
        	    	} else if (postAuth.status == 401) {
        	    		//do nothing.  this means the credential id wasn't found
        	    	} else if (postAuth.status == 302) {
        	    		//redirect to the error page
        	    		window.location = postAuth.getResponseHeader("Location");
        	    		return;
        	    	}
        	    }
        	    postAuth.send(JSON.stringify(authResp));
        	    
        	}).catch(console.error);
        	
        	
        } else {
            alert("error");
        }
    };

    xhr.send();
}

</script>
</body>

</html>  

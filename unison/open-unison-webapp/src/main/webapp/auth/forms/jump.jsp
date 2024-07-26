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
    pageEncoding="UTF-8" import="java.util.*,com.tremolosecurity.proxy.auth.*,com.tremolosecurity.proxy.util.*,com.tremolosecurity.config.util.*" %>
<!DOCTYPE html>
<html lang="en"><!DOCTYPE html>
<html lang="en">
		<% 
		String auth = "/auth/forms/";
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		String authURL = "/auth/forms/";
		
		if (reqHolder != null) {
			ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
			
			authURL = cfg.getAuthFormsPath();
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

<body onload="var seconds = 5;window.setInterval(function redirect(){if (seconds > 0) {seconds -= 1;document.getElementById('num').innerHTML=seconds; } else {window.location.href = '<%= session.getAttribute("SAML2_JUMPPAGE")%>';}},1000);">
  <div class="row">
    <div class="col vh-100 d-none d-md-block col-md-5 col-lg-6 col-xl-8 d-inline-block"
      style="background-color: #AC1622;">

    </div>
    <div class="col vh-100 col-md-7 col-lg-6 col-xl-4 d-inline-block d-flex align-items-center ">
      <div class="container">
        <div class="bg-white rounded shadow-5-strong p-5" action="<%=session.getAttribute("TREMOLO_AUTH_URI")%>" method="post">
          <div class="row row-cols-1  ">
            <div class="col text-center"><img src="<%= auth %>images/ts_logo.png" class="center-block" /></div>

          </div>
          <div class="row row-cols-1">
            <div class="col text-center"><h1>You Are Being Redirected to Authenticate</h1></div>
          </div>
          <div class="row row-cols-1">
            <div class="col">
              <div class="alert alert-primary">
              	You will be redirected in <span id="num">5</span> seconds.<br />If you are not redirected, click <a id="next" href="<%= session.getAttribute("SAML2_JUMPPAGE")%>">here</a>
              </div>
            </div>
          </div>
          
        </div>
      </div>

    </div>
  </div>

  <!-- End your project here-->

  <!-- MDB -->
  <script type="text/javascript" src="<%= auth %>js-mdb/mdb.umd.min.js"></script>
  <!-- Custom scripts -->
  <script type="text/javascript"></script>
</body>

</html>

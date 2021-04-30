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
    pageEncoding="UTF-8" import="com.tremolosecurity.proxy.auth.*,com.tremolosecurity.proxy.util.*,com.tremolosecurity.config.util.*"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

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

<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title></title>

</head>
<body>


			<form  role="form" action="<%= session.getAttribute("TREMOLO_AUTH_URI") %>" method="post">
				<input class="form-control" placeholder="User Name"  type="text" id="user" name="user"  />
<br/>
        <input  class="form-control" placeholder="Password"  type="password" id="pwd" name="pwd" />
<br/>
        <button class="btn btn-lg btn-danger btn-block" type="submit" name="submit" id="submit">Sign in</button>
        <input type="hidden" name="target" id="target" value="<%= targetURL %>" />
      </form>

</body>
</html>
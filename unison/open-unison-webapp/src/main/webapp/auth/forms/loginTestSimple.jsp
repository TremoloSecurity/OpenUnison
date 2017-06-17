<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"
	import="com.tremolosecurity.saml.Attribute,java.util.*,com.tremolosecurity.proxy.auth.*,java.net.*,com.tremolosecurity.config.util.*,com.tremolosecurity.proxy.util.*,com.tremolosecurity.proxy.*,com.tremolosecurity.proxy.util.*,com.tremolosecurity.config.util.*"%>
<%
	RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
	String authURL = "/auth/forms/";

	if (reqHolder != null) {
		ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);

		authURL = cfg.getAuthFormsPath();
	}
	
	AuthController auth = (AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL);
	response.setContentType("application/json");
%>
{
	"alive":true,
	"user_dn":"<%= auth.getAuthInfo().getUserDN() %>",
	"auth_level":"<%= auth.getAuthInfo().getAuthLevel() %>",
	"auth_chain":"<%= auth.getAuthInfo().getAuthMethod() %>"
}

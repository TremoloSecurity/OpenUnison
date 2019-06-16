package com.tremolosecurity.proxy.auth;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.StringTokenizer;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.az.AzRule;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class AuthorizationAuthMech implements AuthMechanism {

	AzSys azSys;
	ApplicationType at;
	@Override
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {
		this.azSys = new AzSys();
		this.at = new ApplicationType();
		this.at.setAzTimeoutMillis(3000L);
		
		

	}

	@Override
	public String getFinalURL(HttpServletRequest request, HttpServletResponse response) {
		return null;
	}

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		HttpSession session = ((HttpServletRequest) request).getSession(); 
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		if (holder == null) {
			throw new ServletException("Holder is null");
		}
		
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		
		AuthController ac = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL));
		
		Attribute rulesCfg = authParams.get("rules");
		
		List<AzRule> rules = new ArrayList<AzRule>();
		
		for (String val : rulesCfg.getValues()) {
			StringTokenizer toker = new StringTokenizer(val,";",false);
			toker.hasMoreTokens();
			String scope = toker.nextToken();
			toker.hasMoreTokens();
			String constraint = toker.nextToken();
			
			try {
				AzRule rule = new AzRule(scope,constraint,null,GlobalEntries.getGlobalEntries().getConfigManager(),null);
				rules.add(rule);
			} catch (ProvisioningException e) {
				throw new ServletException("Could not create az rule",e);
			}
		}
		
		
		
		as.setSuccess(azSys.checkRules(ac.getAuthInfo(), GlobalEntries.getGlobalEntries().getConfigManager(), rules, new HashMap<String,Object>()));
		holder.getConfig().getAuthManager().nextAuth(request, response,session,false);

	}

	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doPut(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doHead(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doOptions(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doDelete(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

}

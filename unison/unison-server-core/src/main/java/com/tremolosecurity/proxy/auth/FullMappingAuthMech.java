package com.tremolosecurity.proxy.auth;

import java.io.IOException;
import java.util.HashMap;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.TargetAttributeType;
import com.tremolosecurity.config.xml.TargetType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;

public class FullMappingAuthMech implements AuthMechanism {

	@Override
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {
		// TODO Auto-generated method stub

	}

	@Override
	public String getFinalURL(HttpServletRequest request, HttpServletResponse response) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response, AuthStep step)
			throws IOException, ServletException {
		HttpSession session = ((HttpServletRequest) request).getSession(); 
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		if (holder == null) {
			throw new ServletException("Holder is null");
		}
		
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		
		
		
		TargetType tt = new TargetType();
		
		
		Attribute map = authParams.get("map");
		for (String mapping : map.getValues()) {
			int firstPipe = mapping.indexOf('|');
			int secondPipe = mapping.indexOf('|',firstPipe + 1);
			String destAttr = mapping.substring(0,firstPipe);
			String type = mapping.substring(firstPipe + 1,secondPipe);
			String value = mapping.substring(secondPipe + 1);
			
			TargetAttributeType tat = new TargetAttributeType();
			tat.setName(destAttr);
			tat.setSourceType(type);
			tat.setSource(value);
			
			tt.getTargetAttribute().add(tat);
		}
		
		try {
			MapIdentity mapper = new MapIdentity(tt);
			AuthController ac = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL));
			
			User orig = new User(ac.getAuthInfo().getUserDN());
			orig.getAttribs().putAll(ac.getAuthInfo().getAttribs());
			User mapped = mapper.mapUser(orig);
			ac.getAuthInfo().getAttribs().clear();
			ac.getAuthInfo().getAttribs().putAll(mapped.getAttribs());
			
		} catch (ProvisioningException e) {
			throw new ServletException("Could not map user",e);
		}
		
		step.setSuccess(true);
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

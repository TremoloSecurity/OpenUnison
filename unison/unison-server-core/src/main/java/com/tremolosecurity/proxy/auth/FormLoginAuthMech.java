/*
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
*/


package com.tremolosecurity.proxy.auth;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequestWrapper;
import javax.servlet.ServletResponseWrapper;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import javax.servlet.http.HttpSession;

import org.apache.logging.log4j.Logger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.auth.util.AuthUtil;
import com.tremolosecurity.proxy.ProxyRequest;
import com.tremolosecurity.proxy.TremoloHttpSession;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.*;



public class FormLoginAuthMech implements AuthMechanism {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(FormLoginAuthMech.class);
	
	public static final String LOGIN_JSP = "FORMLOGIN_JSP";
	
	ConfigManager cfgMgr;
	
	@Override
	public void doGet(HttpServletRequest req, HttpServletResponse resp,AuthStep as)
			throws ServletException, IOException {
		
		//HttpSession session = SharedSession.getSharedSession().getSession(req.getSession().getId());
		HttpSession session = ((HttpServletRequest) req).getSession();
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		ConfigManager cfg = (ConfigManager) req.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		String formURI = authParams.get(LOGIN_JSP).getValues().get(0);
		
		HttpServletRequestWrapper reqWrapper = new HttpServletRequestWrapper(req);
		HttpServletResponseWrapper respWrapper = new HttpServletResponseWrapper(resp);
		
		//reqWrapper.getRequestDispatcher(formURI).forward(reqWrapper, respWrapper);
		
		//TODO: fix redirect issue
		
		//StringBuffer b = new StringBuffer();
		//b.append(cfg.getAuthPath()).append(formURI.substring(1));
		
		resp.sendRedirect(formURI);
	}

	@Override
	public void doPost(HttpServletRequest req, HttpServletResponse resp,AuthStep as)
			throws ServletException, IOException {
		
		String userDN = null;
		
		MyVDConnection myvd = cfgMgr.getMyVD();
		//HttpSession session = (HttpSession) req.getAttribute(ConfigFilter.AUTOIDM_SESSION);//((HttpServletRequest) req).getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
		HttpSession session = ((HttpServletRequest) req).getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
		UrlHolder holder = (UrlHolder) req.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		if (holder == null) {
			throw new ServletException("Holder is null");
		}
		
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		String uidAttr = "uid";
		if (authParams.get("uidAttr") != null) {
			uidAttr = authParams.get("uidAttr").getValues().get(0);
		}
		
		
		boolean uidIsFilter = false;
		if (authParams.get("uidIsFilter") != null) {
			uidIsFilter = authParams.get("uidIsFilter").getValues().get(0).equalsIgnoreCase("true");
		}
		
		String filter = "";
		if (uidIsFilter) {
			StringBuffer b = new StringBuffer();
			int lastIndex = 0;
			int index = uidAttr.indexOf('$');
			while (index >= 0) {
				b.append(uidAttr.substring(lastIndex,index));
				lastIndex = uidAttr.indexOf('}',index) + 1;
				String reqName = uidAttr.substring(index + 2,lastIndex - 1);
				b.append(req.getParameter(reqName));
				index = uidAttr.indexOf('$',index+1);
			}
			b.append(uidAttr.substring(lastIndex));
			filter = b.toString();
		
		} else {
			StringBuffer b = new StringBuffer();
			String userParam = req.getParameter("user");
			b.append('(').append(uidAttr).append('=').append(userParam).append(')');
			if (userParam == null) {
				filter = "(!(objectClass=*))";
			} else {
				filter = equal(uidAttr,userParam).toString();
			}
		}
		
		
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
		
		
		
		
		AuthMechType amt = act.getAuthMech().get(as.getId());
		
		String password = req.getParameter("pwd");
		if (password == null || password.trim().length() == 0) {
			
				
				as.setSuccess(false);
				
				holder.getConfig().getAuthManager().nextAuth(req, resp,session,false);
				return;
			
		}
		
		try {
			LDAPSearchResults res = myvd.search(AuthUtil.getChainRoot(cfgMgr,act), 2, filter, new ArrayList<String>());
			
			if (res.hasMore()) {
				LDAPEntry entry = res.next();
				userDN = entry.getDN();
				myvd.bind(entry.getDN(), req.getParameter("pwd"));
				
				Iterator<LDAPAttribute> it = entry.getAttributeSet().iterator();
				AuthInfo authInfo = new AuthInfo(entry.getDN(),(String) session.getAttribute(ProxyConstants.AUTH_MECH_NAME),act.getName(),act.getLevel());
				((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).setAuthInfo(authInfo);
				
				while (it.hasNext()) {
					LDAPAttribute attrib = it.next();
					Attribute attr = new Attribute(attrib.getName());
					String[] vals = attrib.getStringValueArray();
					for (int i=0;i<vals.length;i++) {
						attr.getValues().add(vals[i]);
					}
					authInfo.getAttribs().put(attr.getName(), attr);
				}
				
				
				
				as.setSuccess(true);
				
				
				
			} else {
				req.setAttribute(ProxyConstants.AUTH_FAILED_USER_DN, userDN);
				as.setSuccess(false); 
			}
			
		} catch (LDAPException e) {
			if (e.getResultCode() != LDAPException.INVALID_CREDENTIALS) {
				logger.error("Could not authenticate user",e);
			} 
			
			req.setAttribute(ProxyConstants.AUTH_FAILED_USER_DN, userDN);
			as.setSuccess(false);
		}
		
		
		
		String redirectToURL = req.getParameter("target");
		if (redirectToURL != null && ! redirectToURL.isEmpty()) {
			reqHolder.setURL(redirectToURL);
		}
		
		ProxyRequest pr = (ProxyRequest) req;
		pr.removeParameter("pwd");
		pr.removeParameter("user");
		
		holder.getConfig().getAuthManager().nextAuth(req, resp,session,false);
		
	}

	@Override
	public void doPut(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void doHead(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void doOptions(HttpServletRequest request,
			HttpServletResponse response,AuthStep as) throws IOException, ServletException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void doDelete(HttpServletRequest request,
			HttpServletResponse response,AuthStep as) throws IOException, ServletException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {
		this.cfgMgr = (ConfigManager) ctx.getAttribute(ProxyConstants.TREMOLO_CONFIG);
		
	}

	@Override
	public String getFinalURL(HttpServletRequest request,
			HttpServletResponse response) {
		return request.getParameter("target");
	}

}

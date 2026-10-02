/*
Copyright 2015, 2016 Tremolo Security, Inc.

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

import java.io.IOException;
import java.util.*;

import com.google.gson.Gson;
import com.novell.ldap.util.ByteArray;
import com.tremolosecurity.proxy.auth.util.ReCaptchaResponse;
import com.tremolosecurity.server.GlobalEntries;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.http.NameValuePair;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.impl.conn.SystemDefaultRoutePlanner;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.Logger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.proxy.ProxyUtil;

import com.tremolosecurity.proxy.TremoloHttpSession;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.auth.util.AuthUtil;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.proxy.util.ProxyTools;
import com.tremolosecurity.saml.*;



public class UserOnlyAuthMech implements AuthMechanism {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(UserOnlyAuthMech.class);
	
	public static final String LOGIN_JSP = "loginJSP";
	static Gson gson = new Gson();
	ConfigManager cfgMgr;
	
	@Override
	public void doGet(HttpServletRequest req, HttpServletResponse resp,AuthStep as)
			throws ServletException, IOException {
		
		//HttpSession session = SharedSession.getSharedSession().getSession(req.getSession().getId());
		HttpSession session = ((HttpServletRequest) req).getSession();
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		
		String formURI = authParams.get(LOGIN_JSP).getValues().get(0);

		if (authParams.containsKey("recaptchaSiteKey")) {
			Attribute recaptchaSiteKey = authParams.get("recaptchaSiteKey");
			session.setAttribute("tremolo.io/rccaptchasitekey", recaptchaSiteKey.getValues().get(0));
		}
		
		resp.sendRedirect(ProxyTools.getInstance().getFqdnUrl(formURI, req));
	}

	@Override
	public void doPost(HttpServletRequest req, HttpServletResponse resp,AuthStep as)
			throws ServletException, IOException {
		
		
		MyVDConnection myvd = cfgMgr.getMyVD();
		//HttpSession session = (HttpSession) req.getAttribute(ConfigFilter.AUTOIDM_SESSION);//((HttpServletRequest) req).getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
		HttpSession session = ((HttpServletRequest) req).getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
		UrlHolder holder = (UrlHolder) req.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);

		UserNameLookupLogger lookupLogger = null;

		Attribute portLookupLoggerClassName =  authParams.get("postLookupLogger");
		if (portLookupLoggerClassName != null) {
            try {
                lookupLogger = (UserNameLookupLogger) Class.forName(portLookupLoggerClassName.getValues().get(0)).newInstance();
            } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
                throw new ServletException("Could not initialize lookup logger",e);
            }
        }


		if (authParams.containsKey("recaptchaSecret")) {
			Attribute recaptchaSecret = authParams.get("recaptchaSecret");
			String challengeResponse = req.getParameter("g-recaptcha-response");

			if (challengeResponse == null) {
				as.setSuccess(false);
				as.setExecuted(true);
				holder.getConfig().getAuthManager().nextAuth(req, resp,session,false);
				return;
			}

			BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(GlobalEntries.getGlobalEntries().getConfigManager().getHttpClientSocketRegistry());
			RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).build();
			CloseableHttpClient http = HttpClients.custom().setConnectionManager(bhcm).setDefaultRequestConfig(rc).setRoutePlanner(new SystemDefaultRoutePlanner(null)).build();
			try {

				HttpPost httppost = new HttpPost("https://www.google.com/recaptcha/api/siteverify");

				List<NameValuePair> formparams = new ArrayList<NameValuePair>();
				formparams.add(new BasicNameValuePair("secret", recaptchaSecret.getValues().get(0)));
				formparams.add(new BasicNameValuePair("response", challengeResponse));
				UrlEncodedFormEntity entity = new UrlEncodedFormEntity(formparams, "UTF-8");


				httppost.setEntity(entity);

				CloseableHttpResponse httpresp = http.execute(httppost);



				ReCaptchaResponse res = gson.fromJson(EntityUtils.toString(httpresp.getEntity()), ReCaptchaResponse.class);

				if (! res.isSuccess()) {
					logger.warn("Failed recaptcha");
					as.setSuccess(false);
					as.setExecuted(true);
					holder.getConfig().getAuthManager().nextAuth(req, resp,session,false);
					return;
				}
			} finally {
				if (http != null) {
					http.close();
				}

				if (bhcm != null) {
					bhcm.close();
				}

			}




		}



		String uidAttr = "uid";
		if (authParams.get("uidAttr") != null) {
			uidAttr = authParams.get("uidAttr").getValues().get(0);
		}
		
		
		boolean uidIsFilter = false;
		if (authParams.get("uidIsFilter") != null) {
			uidIsFilter = authParams.get("uidIsFilter").getValues().get(0).equalsIgnoreCase("true");
		}
		
		String noUserJSP = authParams.get("noUserJSP").getValues().get(0);
		
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
			b.append("(").append(uidAttr).append("=").append(req.getParameter("user")).append(")");
			filter = b.toString();
		}
		
		
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
		
		
		
		
		AuthMechType amt = act.getAuthMech().get(as.getId());
		
		
		
		try {
			LDAPSearchResults res = myvd.search(AuthUtil.getChainRoot(cfgMgr,act), 2, filter, new ArrayList<String>());
			
			if (res.hasMore()) {
				LDAPEntry entry = res.next();
				while (res.hasMore()) res.next();
				
				Iterator<LDAPAttribute> it = entry.getAttributeSet().iterator();
				AuthInfo authInfo = new AuthInfo(entry.getDN(),(String) session.getAttribute(ProxyConstants.AUTH_MECH_NAME),act.getName(),act.getLevel(),(TremoloHttpSession) session);
				((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).setAuthInfo(authInfo);
				
				while (it.hasNext()) {
					LDAPAttribute attrib = it.next();
					Attribute attr = new Attribute(attrib.getName());
					LinkedList<ByteArray> vals = attrib.getAllValues();
					for (ByteArray ba : vals) {
						String val = new String(ba.getValue());
						attr.getValues().add(val);
					}
					authInfo.getAttribs().put(attr.getName(), attr);
				}
				
				
				if (lookupLogger != null) {
					lookupLogger.logResult(req,resp,true);
				}
				as.setSuccess(true);
				
				
			} else {
				if (lookupLogger != null) {
					lookupLogger.logResult(req,resp,false);
				}
				as.setSuccess(false);
				
				resp.sendRedirect(noUserJSP);
				return;
			}
			
		} catch (LDAPException e) {
			logger.error("Could not find user",e);

			if (lookupLogger != null) {
				lookupLogger.logResult(req,resp,false);
			}
			as.setSuccess(false);
			
			
			
			resp.sendRedirect(noUserJSP);
			return;
		}
		
		
		
		String redirectToURL = req.getParameter("target");
		if (redirectToURL != null && ! redirectToURL.isEmpty()) {
			reqHolder.setURL(redirectToURL);
		}
		
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
		// TODO Auto-generated method stub
		return null;
	}

}

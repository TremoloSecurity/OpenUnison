/*
Copyright 2015, 2017 Tremolo Security, Inc.

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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URLEncoder;
import java.util.HashMap;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.logging.log4j.Logger;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.restfb.DefaultFacebookClient;
import com.restfb.FacebookClient;
import com.restfb.types.User;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.proxy.TremoloHttpSession;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;

public class FacebookLogin implements AuthMechanism {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(FacebookLogin.class);
	
	public static final String FB_APP_ID = "faceBookAppID";
	public static final String FB_APP_SECRET = "faceBookAppSecret";
	public static final String FB_REDIR_URL = "faceBookRedirURL";
	public static final String FB_DN_PATTERN = "faceBookDNPattern";
	
	ConfigManager cfgMgr;
	
	static Gson gson = new GsonBuilder()
		    .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
		    .create();
	
	@Override
	public void doGet(HttpServletRequest req, HttpServletResponse resp,AuthStep as)
			throws ServletException, IOException {
		
		try {
		doFB(req, resp,as);
		} catch (Throwable t) {
			logger.error("Error performing login",t);
		}
		
	}

	protected void doFB(HttpServletRequest req, HttpServletResponse resp,AuthStep as)
			throws IOException, ServletException {
		HttpSession session = ((HttpServletRequest) req).getSession();
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		
		
		MyVDConnection myvd = cfgMgr.getMyVD();
		UrlHolder holder = (UrlHolder) req.getAttribute(ProxyConstants.AUTOIDM_CFG);
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(urlChain);
		String httpClientManager = null;
		
		if (authParams.containsKey("httpConnectionManager")) {
			httpClientManager = authParams.get("httpConnectionManager").getValues().get(0);
		}
		
		
		
		AuthMechType amt = act.getAuthMech().get(as.getId());
		
		String applicationID = authParams.get(FB_APP_ID).getValues().get(0);
		String applicationSecret = authParams.get(FB_APP_SECRET).getValues().get(0);
		String redirectURL = URLEncoder.encode(authParams.get(FB_REDIR_URL).getValues().get(0));
		String faceBookDN = authParams.get(FB_DN_PATTERN).getValues().get(0);
		String scope = authParams.get("scope").getValues().get(0);
		
		if (session.getAttribute("AUTOIDM_FB_GETCODE") == null) {
			StringBuffer url = new StringBuffer("https://graph.facebook.com/oauth/authorize?client_id=").append(URLEncoder.encode(applicationID,"UTF-8")).append("&redirect_uri=").append(redirectURL).append("&scope=").append(URLEncoder.encode(scope,"UTF-8"));
			session.setAttribute("AUTOIDM_FB_GETCODE","");
			
			
			
			resp.sendRedirect(url.toString());
		} else {
			try {
			session.removeAttribute("AUTOIDM_FB_GETCODE");
			String accessToken = getFBAccessToken(req, applicationID, applicationSecret, redirectURL,httpClientManager,as);
			FacebookClient facebookClient = new DefaultFacebookClient(accessToken);
			
				User user = facebookClient.fetchObject("me", User.class);
				
				String dn = faceBookDN.replace("%", user.getId());
				
				
				
				AuthInfo authInfo = new AuthInfo(dn,(String) session.getAttribute(ProxyConstants.AUTH_MECH_NAME),act.getName(),act.getLevel());
				((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).setAuthInfo(authInfo);
				
				Attribute attr = new Attribute("id",user.getId());
				authInfo.getAttribs().put(attr.getName(), attr);
				
				if (user.getAbout() != null) {
					attr = new Attribute("fbAbout",user.getAbout());
					authInfo.getAttribs().put(attr.getName(), attr);
				}
				
				if (user.getBirthday() != null) {
					attr = new Attribute("fbBirthDay",user.getBirthday());
					authInfo.getAttribs().put(attr.getName(), attr);
				}
				
				if (user.getEmail() != null) {
					attr = new Attribute("mail",user.getEmail());
					authInfo.getAttribs().put(attr.getName(), attr);
				}
				
				if (user.getFirstName() != null) {
					attr = new Attribute("givenName",user.getFirstName());
					authInfo.getAttribs().put(attr.getName(), attr);
				}
				
				if (user.getGender() != null) {
					attr = new Attribute("fbGender",user.getGender());
					authInfo.getAttribs().put(attr.getName(), attr);
				}
				
				if (user.getLastName() != null) {
					attr = new Attribute("sn",user.getAbout());
					authInfo.getAttribs().put(attr.getName(), attr);
				}
				
				if (user.getLink() != null) {
					attr = new Attribute("fbLink",user.getLink());
					authInfo.getAttribs().put(attr.getName(), attr);
				}
				
				if (user.getLocale() != null) {
					attr = new Attribute("fbLocale",user.getLocale());
					authInfo.getAttribs().put(attr.getName(), attr);
				}
				
				if (user.getName() != null) {
					attr = new Attribute("cn",user.getName());
					authInfo.getAttribs().put(attr.getName(), attr);
				}
				
				as.setSuccess(true);
				
				
				holder.getConfig().getAuthManager().nextAuth(req, resp,session,false);
				
			} catch (Exception e) {
				throw new ServletException(e);
			}
			
		}
	}

	private String getFBAccessToken(HttpServletRequest req, String applicationID,
			String applicationSecret, String redirectURL,String httpConnectionManager,AuthStep as) throws IOException,
			Exception {
		String code = URLEncoder.encode(req.getParameter("code"));
		StringBuffer url = new StringBuffer("https://graph.facebook.com/oauth/access_token?client_id=").append(applicationID).append("&redirect_uri=").append(redirectURL).append("&client_secret=").append(applicationSecret).append("&code=").append(code);
		
		
		
		
		HttpClient httpclient = null;
		
		if (httpConnectionManager != null) {
			
				ClientConnectionManager conMgr = (ClientConnectionManager) this.getClass().forName(httpConnectionManager).newInstance();
				httpclient = new DefaultHttpClient(conMgr,null);
		} else {
			httpclient = new DefaultHttpClient();
		}
		
		
		HttpGet httpget = new HttpGet(url.toString());
		HttpResponse response = httpclient.execute(httpget);
		
		BufferedReader in = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
		String line = null;
		StringBuffer str = new StringBuffer();
		while ((line = in.readLine()) != null) {
			str.append(line);
		}
		
		
		
		httpget.abort();
		
		String accessToken = str.toString();
		
		accessToken = gson.fromJson(accessToken, TokenType.class).getAccessToken();
		
		//accessToken = accessToken.substring(accessToken.indexOf('=')+1,accessToken.indexOf('&'));
		
		return accessToken;
	}

	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);
		
	}

	@Override
	public void doPut(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);
		
	}

	@Override
	public void doHead(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);
		
	}

	@Override
	public void doOptions(HttpServletRequest request,
			HttpServletResponse response,AuthStep as) throws IOException, ServletException {
		this.doGet(request, response, as);
		
	}

	@Override
	public void doDelete(HttpServletRequest request,
			HttpServletResponse response,AuthStep as) throws IOException, ServletException {
		this.doGet(request, response, as);
		
	}

	@Override
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {
		this.cfgMgr = (ConfigManager) ctx.getAttribute(ProxyConstants.TREMOLO_CONFIG);
		
	}

	@Override
	public String getFinalURL(HttpServletRequest request,
			HttpServletResponse response) {
		
		return null;
	}
	
	
	
}

class TokenType {
	String accessToken;

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}
	
	
}

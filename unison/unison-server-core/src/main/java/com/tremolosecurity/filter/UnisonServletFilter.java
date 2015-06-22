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


package com.tremolosecurity.filter;

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.Provider;
import java.security.Security;
import java.sql.Date;
import java.util.HashMap;
import java.util.Properties;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UnisonConfigManagerImpl;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;

import com.tremolosecurity.embedd.LocalSessionRequest;
import com.tremolosecurity.embedd.NextEmbSys;
import com.tremolosecurity.proxy.ProxyRequest;
import com.tremolosecurity.proxy.ProxyUtil;
import com.tremolosecurity.proxy.SessionManager;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthMechanism;
import com.tremolosecurity.proxy.auth.RequestHolder;
import com.tremolosecurity.proxy.auth.RequestHolder.HTTPMethod;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.proxy.util.ProxyTools;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public abstract class UnisonServletFilter implements Filter {

static Logger logger = Logger.getLogger(UnisonServletFilter.class);
	
	FilterConfig cfg;
	boolean passOn;

	private ServletContext ctx;
	
	
	@Override
	public void destroy() {
		// TODO Auto-generated method stub

	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {
		
		HttpServletRequest req = new LocalSessionRequest((HttpServletRequest) request);
		HttpServletResponse resp = (HttpServletResponse) response;
		ConfigManager cfg = (ConfigManager) ctx.getAttribute(ProxyConstants.TREMOLO_CONFIG);
		SessionManager sessionMgr = (SessionManager) ctx.getAttribute(ProxyConstants.TREMOLO_SESSION_MANAGER);
		ProxyRequest pr = null;
		
		try {
			pr = new ProxyRequest((HttpServletRequest) req);
		} catch (Exception e1) {
			logger.error("Unable to create request",e1);
			throw new IOException("Could not create request");
		}
		
		
		
		try {
			NextEmbSys embSys = new NextEmbSys(this.cfg.getServletContext(),chain,passOn);
			 
			
			/*System.err.println("*** Begin Request ****");
			System.err.println("url = '" + ((HttpServletRequest)req).getRequestURL() + "'");
			Cookie[] cookies = ((HttpServletRequest) req).getCookies();
			if (cookies != null) {
				for (Cookie cookie : cookies) {
					System.err.println("'" + cookie.getName() + "'='" + cookie.getValue() + "'");
				}
			}
			System.err.println("*** End Request ****");*/
			
			
			String fwdProto = req.getHeader("X-Forwarded-Proto");
			
			
			boolean toSSL = false;
			if (cfg.isForceToSSL()) {
				if (fwdProto != null) {
					toSSL = fwdProto.equalsIgnoreCase("http");
				} else {
					toSSL = ! req.getRequestURL().toString().toLowerCase().startsWith("https");
				}
			}
			
			if (toSSL) {
				StringBuffer redirURL = new StringBuffer();
				URL reqURL = new URL(req.getRequestURL().toString());
				redirURL.append("https://").append(reqURL.getHost());
				if (cfg.getExternalSecurePort() != 443) {
					redirURL.append(":").append(cfg.getSecurePort());
				}
				redirURL.append(reqURL.getPath());
				
				if (reqURL.getQuery() != null) {
					redirURL.append('?').append(reqURL.getQuery());
				}
				
				resp.sendRedirect(redirURL.toString());
				return;
			}
			
			
			
			
			req.setAttribute(ProxyConstants.TREMOLO_CFG_OBJ, cfg);
			
			HttpServletRequest servReq = (HttpServletRequest)req;
			String URL;
			HttpSession sharedSession = null; 
			UrlHolder holder = null; 
			
			URL = servReq.getRequestURL().toString();
			
			
			
			holder = cfg.findURL(URL);
			
			boolean isForcedAuth = false;
			RequestHolder reqHolder = null;
			
			String sessionCookieName = req.getParameter("sessionCookie");
			
			if (sessionCookieName == null) {
				Cookie[] cookies = ((HttpServletRequest) req).getCookies();
				if (cookies != null) {
					for (int i=0;i<cookies.length;i++) {
						if (cookies[i].getName().equals("autoIdmSessionCookieName")) {
							sessionCookieName = cookies[i].getValue();
						}
					}
				}
			}
			
			if (sessionCookieName == null) {
				
			} else {
				
			}
			

			
			
			if (holder == null) {
				//check the session
				
				
				
				
				sharedSession = sessionMgr.getSession(sessionCookieName,holder,((HttpServletRequest) req),((HttpServletResponse) resp),this.ctx);
				
				
				if (sharedSession != null) {
					AuthController actl = (AuthController) sharedSession.getAttribute(ProxyConstants.AUTH_CTL);
					if (actl.getHolder() != null) {
						URL = ((AuthController) sharedSession.getAttribute(ProxyConstants.AUTH_CTL)).getHolder().getURL();
						holder = cfg.findURL(URL);
					}
				}
			} else {
			
				
					sharedSession = sessionMgr.getSession(holder,((HttpServletRequest) req),((HttpServletResponse) resp),this.ctx);
				
			}
			
			//LocalSessionRequest lsr = new LocalSessionRequest((HttpServletRequest)req,sharedSession);
			if (sharedSession != null) {
				pr.setSession(sharedSession);
			}
			
			if ((holder == null || holder.getUrl().getUri().equalsIgnoreCase("/")) && req.getRequestURI().startsWith(cfg.getAuthPath()) && sessionCookieName == null) {
				//if (req.getRequestURI().startsWith("/auth/")) {
					AuthMechanism authMech = cfg.getAuthMech(((HttpServletRequest) req).getRequestURI());
					
					if (authMech != null) {
						String finalURL = authMech.getFinalURL(pr, resp);
						
						if (finalURL != null) {
						
							holder = cfg.findURL(finalURL);
							String urlChain = holder.getUrl().getAuthChain();
							AuthChainType act = holder.getConfig().getAuthChains().get(urlChain);
							
							HashMap<String,Attribute> params = new HashMap<String,Attribute>();
							ProxyUtil.loadParams(req, params);
							
							if (req instanceof ProxyRequest) {
								reqHolder = new RequestHolder(HTTPMethod.GET,params,finalURL,true,act.getName(),((ProxyRequest) req).getQueryStringParams());
							} else {
								reqHolder = new RequestHolder(HTTPMethod.GET,params,finalURL,true,act.getName(),((com.tremolosecurity.embedd.LocalSessionRequest) req).getQueryStringParams());
							}
							
							
							isForcedAuth = true;
							
							sharedSession = sessionMgr.getSession(holder,((HttpServletRequest) req),((HttpServletResponse) resp),this.ctx);
							if (sharedSession != null) {
								pr.setSession(sharedSession);
							}
							
							Cookie lsessionCookieName = new Cookie("autoIdmSessionCookieName",holder.getApp().getCookieConfig().getSessionCookieName());
							String domain = ProxyTools.getInstance().getCookieDomain(holder.getApp().getCookieConfig(), req);
							if (domain != null) {
								lsessionCookieName.setDomain(domain);
							}
							lsessionCookieName.setPath("/");
							lsessionCookieName.setMaxAge(-1);
							lsessionCookieName.setSecure(false);
							resp.addCookie(lsessionCookieName);
							
							Cookie appCookieName = new Cookie("autoIdmAppName",URLEncoder.encode(holder.getApp().getName(),"UTF-8"));
							if (domain != null) {
								appCookieName.setDomain(domain);
							}
							appCookieName.setPath("/");
							appCookieName.setMaxAge(-1);
							appCookieName.setSecure(false);
							
							resp.addCookie(appCookieName);
							
						}
					}
					
				}
			
			req.setAttribute(ProxyConstants.AUTOIDM_CFG, holder);
			req.setAttribute(ProxyConstants.TREMOLO_IS_FORCED_AUTH, isForcedAuth);
			req.setAttribute(ProxyConstants.TREMOLO_REQ_HOLDER, reqHolder);
			
			embSys.nextSys(pr, (HttpServletResponse)resp);
		
		} catch (Exception e) {
			req.setAttribute("TREMOLO_ERROR_REQUEST_URL", req.getRequestURL().toString());
			req.setAttribute("TREMOLO_ERROR_EXCEPTION", e);
			logger.error("Could not process request",e);
			StringBuffer b = new StringBuffer();
			b.append(cfg.getAuthFormsPath()).append("error.jsp");
			req.getRequestDispatcher(b.toString()).forward(pr, resp);
		}
		

	}

	@Override
	public void init(FilterConfig filterCfg) throws ServletException {
		
		
		
		this.ctx = filterCfg.getServletContext();
		
		Properties loggingProps = new Properties();
		try {
			loggingProps.load(filterCfg.getServletContext().getResourceAsStream("/WEB-INF/log4j.properties"));
			PropertyConfigurator.configure(loggingProps);
		} catch (Exception e1) {
			//throw new ServletException(e1);
		}
		
		
		//TODO This needs to be replaced with configurable code
		try {

			Security.addProvider((Provider) Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider").newInstance());

		} catch (InstantiationException e1) {
			throw new ServletException("Could not load bouncycastle",e1);
		} catch (IllegalAccessException e1) {
			throw new ServletException("Could not load bouncycastle",e1);
		} catch (ClassNotFoundException e1) {
			throw new ServletException("Could not load bouncycastle",e1);
		}
		
		this.cfg = filterCfg;

		String tmp = filterCfg.getInitParameter("mode");
		if (tmp == null || tmp.equalsIgnoreCase("embedded")) {
			this.passOn = false;
		} else {
			this.passOn = true;
		}
		
		ConfigManager cfg = null;
		try {
			
			String registryName = filterCfg.getInitParameter("registryName");
			if (registryName == null) {
				registryName = "proxy";
			}
			
			cfg = loadConfiguration(filterCfg,registryName);
			
			
				
			
			
			cfg.initialize(registryName);
			cfg.loadFilters();
			
			
			
			
			
			filterCfg.getServletContext().setAttribute(ProxyConstants.TREMOLO_CONFIG,cfg);
			
			cfg.loadAuthMechs();
			
			
			
			
			
			
			String userPrinicialAttribute = filterCfg.getInitParameter("userPrincipalAttribute");
			String roleAttribute = filterCfg.getInitParameter("roleAttribute");
			
			cfg.setPaasUserPrinicipalAttribute(userPrinicialAttribute);
			cfg.setPaasRoleAttribute(roleAttribute);
			
			boolean forceToSSL = filterCfg.getInitParameter("forceToSSL") != null && filterCfg.getInitParameter("forceToSSL").equalsIgnoreCase("true");
			
			GlobalEntries.getGlobalEntries().set(registryName + "_" + ProxyConstants.FORCE_TO_SSL, forceToSSL);
			
			
			this.postLoadConfiguration(filterCfg, registryName, cfg);
			
		} catch (Exception e) {
			e.printStackTrace();
			throw new ServletException(e);
		}
		
		
	}

	public abstract ConfigManager loadConfiguration(FilterConfig filterCfg, String registryName) throws Exception;
	
	public abstract void postLoadConfiguration(FilterConfig filterCfg, String registryName,ConfigManager cfgMgr);

}

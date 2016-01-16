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


package com.tremolosecurity.proxy;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.http.ConnectionClosedException;
import org.apache.http.HttpEntity;
import org.apache.log4j.Logger;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.log.AccessLog;
import com.tremolosecurity.log.AccessLog.AccessEvent;
import com.tremolosecurity.proxy.auth.AnonAuth;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AuthMechanism;
import com.tremolosecurity.proxy.auth.AuthSys;
import com.tremolosecurity.proxy.auth.RequestHolder;
import com.tremolosecurity.proxy.auth.RequestHolder.HTTPMethod;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterChainImpl;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.filter.PostProcess;
import com.tremolosecurity.proxy.logout.LogoutHandler;
import com.tremolosecurity.proxy.logout.LogoutUtil;
import com.tremolosecurity.proxy.util.NextSys;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;

public class ConfigSys  {

	static Logger logger = Logger.getLogger(ConfigSys.class);
	
	boolean fromRequest;
	
	ConfigManager cfg;
	
	ServletContext ctx;

	
	
	@Deprecated
	public static final String AUTOIDM_CFG = "AUTO_IDM_CFG";
	
	@Deprecated
	public static final String TREMOLO_CFG_OBJ = "TREMOLO_CONFIG_OBJ";
 
	
	public ConfigSys(ConfigManager cfg,boolean fromRequest,ServletContext ctx) {
		this.cfg = cfg;
		this.fromRequest = fromRequest;
		this.ctx = ctx;
		
		
		
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.ConfigSys#doConfig(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, com.tremolosecurity.proxy.util.NextSys)
	 */
	
	public void doConfig(HttpServletRequest req,HttpServletResponse resp,NextSys nextSys) throws IOException, ServletException {
		try {
			
			
			
			SessionManager sessionManager = (SessionManager) this.ctx.getAttribute(ProxyConstants.TREMOLO_SESSION_MANAGER);
			
			boolean setSessionCookie = false;
			boolean checkLogout = false;
			
			RequestHolder reqHolder = (RequestHolder) req.getAttribute(ProxyConstants.TREMOLO_REQ_HOLDER);
			UrlHolder holder = (UrlHolder) req.getAttribute(ProxyConstants.AUTOIDM_CFG);
			boolean isForcedAuth = req.getAttribute(ProxyConstants.TREMOLO_IS_FORCED_AUTH) != null ? (Boolean) req.getAttribute(ProxyConstants.TREMOLO_IS_FORCED_AUTH) : false;
			
			
			
			
			checkLogout =true;
			
			StringBuffer resetsb = new StringBuffer(cfg.getAuthPath()).append("resetChain");
			
			HttpSession sharedSession = req.getSession();
			
			if (sharedSession != null) {
				AuthController actl = (AuthController) sharedSession.getAttribute(ProxyConstants.AUTH_CTL);
				
				if (actl != null && actl.getHolder() != null) {
					
					RequestHolder presentHolder = actl.getHolder();
					AuthInfo authdata = actl.getAuthInfo();
					if (! req.getRequestURI().startsWith(cfg.getAuthPath()) /*&&  ! presentHolder.getUrlNoQueryString().equalsIgnoreCase(req.getRequestURL().toString())*/ && (authdata == null || ! authdata.isAuthComplete())) {
						//we're going to ignore requests for favicon.ico
						if (! req.getRequestURI().endsWith("/favicon.ico") && ! req.getRequestURI().endsWith("/apple-touch-icon-precomposed.png") && ! req.getRequestURI().endsWith("/apple-touch-icon.png") ) {
							sharedSession.removeAttribute(ProxyConstants.AUTH_CTL);
							this.cfg.createAnonUser(sharedSession);
						}
						
					} else if (req.getRequestURI().equalsIgnoreCase(resetsb.toString())) {
						sharedSession.removeAttribute("TREMOLO_AUTH_URI");
						for (AuthStep step : actl.getAuthSteps()) {
							step.setExecuted(false);
							step.setSuccess(false);
						}
						
						
						actl.setCurrentStep(actl.getAuthSteps().get(0));
						
						
						String chainName = holder.getUrl().getAuthChain();
						AuthChainType chain = cfg.getAuthChains().get(chainName);
						String mech = chain.getAuthMech().get(0).getName();
						String uri = cfg.getAuthMechs().get(mech).getUri();
						
						holder.getConfig().getAuthManager().loadAmtParams(sharedSession, chain.getAuthMech().get(0));
						
						
						String redirectURI = "";
						if (holder.getConfig().getContextPath().equalsIgnoreCase("/")) {
							redirectURI = uri;
						} else {
							
							redirectURI = new StringBuffer().append(holder.getConfig().getContextPath()).append(uri).toString();
						}
						
						sharedSession.setAttribute("TREMOLO_AUTH_URI", redirectURI);
						
						resp.sendRedirect(redirectURI);
						return;
						
						
					}
				}
				
				if (isForcedAuth) {
					
					
					actl.setHolder(reqHolder);
					
					
					
					String authChain = holder.getUrl().getAuthChain();
					AuthChainType act = cfg.getAuthChains().get(authChain);
					holder.getConfig().getAuthManager().loadAmtParams(sharedSession, act.getAuthMech().get(0));
				}
			}
			
			
			
			
			
			
			
			
			if (holder == null) {
				

					if (req.getRequestURI().startsWith(cfg.getAuthPath())) {
						
						req.setAttribute(ProxyConstants.AUTOIDM_MYVD, cfg.getMyVD());
						
						ProxyResponse presp = new ProxyResponse((HttpServletResponse) resp,(HttpServletRequest) req);
						
						//we still need a holder
						
						/*AuthController actl = (AuthController) sharedSession.getAttribute(AuthSys.AUTH_CTL);
						if (actl != null) {
							holder = cfg.findURL(actl.getHolder().getUrlNoQueryString());
							req.setAttribute(ConfigSys.AUTOIDM_CFG, holder);
						} else {*/
							AuthMechanism authMech = cfg.getAuthMech(((HttpServletRequest) req).getRequestURI());
						
							if (authMech != null) {
								String finalURL = authMech.getFinalURL(req, resp);
								
								if (finalURL != null) {
								
									holder = cfg.findURL(finalURL);
									
								} else {
									//throw new ServletException("Can not generate holder");
								}
							} else {
								//throw new ServletException("Can not generate holder");
							}
							
							//no holder should be needed beyond this point
							
							
						//}
						
						/*
						
						
								String urlChain = holder.getUrl().getAuthChain();
								AuthChainType act = holder.getConfig().getAuthChains().get(urlChain);
								
								HashMap<String,Attribute> params = new HashMap<String,Attribute>();
								ProxyUtil.loadParams(req, params);
								reqHolder = new RequestHolder(HTTPMethod.GET,params,finalURL,true,act.getName());
								
								isForcedAuth = true;
								req.setAttribute(ConfigSys.AUTOIDM_CFG, holder);
								
								String chainName = holder.getUrl().getAuthChain();
								AuthChainType chain = cfg.getAuthChains().get(chainName);
								String mech = chain.getAuthMech().get(0).getName();
								String uri = cfg.getAuthMechs().get(mech).getUri();
								
								AuthSys.loadAmtParams(sharedSession, chain.getAuthMech().get(0));
							}
						} 
							
						
						if (holder == null) {
							resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
							AccessLog.log(AccessEvent.NotFound, null, req, null, "Resource Not Found");
							return;
						}*/
						
						
						
					
						nextSys.nextSys(req, presp);
						presp.pushHeadersAndCookies(null);
					} else {
						resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
						AccessLog.log(AccessEvent.NotFound, null, req, null, "Resource Not Found");
						
					}
				
				
			} else {
				req.setAttribute(ProxyConstants.AUTOIDM_CFG, holder);
				req.setAttribute(ProxyConstants.AUTOIDM_MYVD, cfg.getMyVD());
				
				ProxyResponse presp = new ProxyResponse((HttpServletResponse) resp,(HttpServletRequest) req);
				
				ProxyData pd = null;
				
				try {
					nextSys.nextSys(req, presp);
					
					 pd = (ProxyData) req.getAttribute(ProxyConstants.TREMOLO_PRXY_DATA);
					
					
					if (holder.getApp().getCookieConfig() != null) {
						String logouturi = holder.getApp().getCookieConfig().getLogoutURI();
						
						
						AuthController actl = (AuthController) sharedSession.getAttribute(ProxyConstants.AUTH_CTL);
						
						if (actl != null) {
							
							AuthInfo authdata = actl.getAuthInfo();
					
						 	if ((req.getRequestURI().equalsIgnoreCase(logouturi) || (pd != null && pd.isLogout())) && (authdata != null)) { 
						 		
						 		
						 		//Execute logout handlers
						 		ArrayList<LogoutHandler> logoutHandlers = (ArrayList<LogoutHandler>) sharedSession.getAttribute(LogoutUtil.LOGOUT_HANDLERS);
						 		if (logoutHandlers != null) {
						 			for (LogoutHandler h : logoutHandlers) {
						 				h.handleLogout(req, presp);
						 			}
						 		}
						 				
						 		sessionManager.clearSession(holder,sharedSession,(HttpServletRequest) req, (HttpServletResponse) resp);
						 	}
						}
					}
					
					presp.pushHeadersAndCookies(holder);
					
					if (pd != null && pd.getIns() != null) {
						
						
						if (pd.getResponse() == null) {
							this.procData(resp,holder, pd.isText(), pd.getIns());
						} else {
							this.procData(pd.getRequest(), pd.getResponse(), holder, pd.isText(), pd.getIns(), pd.getPostProc());
						}
						
					 	
						
					}
				
				} finally {
					if (pd != null && pd.getHttpRequestBase() != null) {
						pd.getHttpRequestBase().releaseConnection();
						if (! resp.isCommitted()) {
							resp.getOutputStream().flush();
							resp.getOutputStream().close();
						}
					}
 				}
				
				
				
				
				
				
			}
		} catch (Exception e) {
			req.setAttribute("TREMOLO_ERROR_REQUEST_URL", req.getRequestURL().toString());
			req.setAttribute("TREMOLO_ERROR_EXCEPTION", e);
			logger.error("Could not process request",e);
			
			StringBuffer b = new StringBuffer();
			b.append(cfg.getAuthFormsPath()).append("error.jsp");
			req.getRequestDispatcher(b.toString()).forward(req, resp);
		}
	}

	

	private void procData(HttpFilterRequest req, HttpFilterResponse resp,
			UrlHolder holder, boolean isText, InputStream ins,PostProcess proc)
			throws IOException, Exception {
		byte[] buffer = new byte[10240];
		//InputStream in = entity.getContent();
		int len;
		
		
		
		
		
		
		
		
		
		
			if (isText) {
				
				
				
				
				BufferedReader in = new BufferedReader(new InputStreamReader(ins));
				
				PrintWriter out = resp.getWriter();
				//OutputStream out = resp.getOutputStream();
				
				
				
				String line;
				
				
				HttpFilterChain chain = new HttpFilterChainImpl(holder,proc);
				StringBuffer lineBuff = new StringBuffer();
				StringBuffer data = new StringBuffer();
				
				while ((line = in.readLine()) != null) {
				
					lineBuff.setLength(0);
					lineBuff.append(line);
					
					if (resp != null) {
						chain.nextFilterResponseText(req, resp, chain, lineBuff);
						chain.reload();
					}
					
					try {
						out.println(lineBuff.toString());
						//out.write(line.getBytes("UTF-8"));
						//out.write("\n".getBytes("UTF-8"));
					} catch (Exception e) {
						//do nothing
					}
					//out.flush();
					
					
				}
				
				
				
				
				//out.flush();
				//out.close();
				
				
			} else {
				
				//req.setAttribute(ProxySys.TREMOLO_BINARY_DATA, baos.toByteArray());
				
				
				//InputStream in = entity.getContent();
				
				OutputStream out = resp.getOutputStream();
				
				try {
					while ((len = ins.read(buffer)) != -1) {
						try {
							out.write(buffer, 0, len);
							out.flush();
						} catch (Throwable t) {
							//ignore write errors
						}
					}
				} catch (ConnectionClosedException e) {
					logger.warn("Connection closed prematurely",e);
				}
				
				
				//out.flush();
				//out.close();
			}
	}
	
	private void procData(HttpServletResponse resp,
			UrlHolder holder, boolean isText, InputStream ins)
			throws IOException, Exception {
		byte[] buffer = new byte[1024];
		//InputStream in = entity.getContent();
		int len;
		
		
		
		
		
		
		
		
		
		
			if (isText) {
				
				
				
				
				BufferedReader in = new BufferedReader(new InputStreamReader(ins));
				
				PrintWriter out = resp.getWriter();
				//OutputStream out = resp.getOutputStream();
				
				
				
				String line;
				
				
				
				StringBuffer lineBuff = new StringBuffer();
				StringBuffer data = new StringBuffer();
				
				
					while ((line = in.readLine()) != null) {
					
						lineBuff.setLength(0);
						lineBuff.append(line);
						
						
						
						try {
							out.println(line);
							//out.write(line.getBytes("UTF-8"));
							//out.write("\n".getBytes("UTF-8"));
						} catch (Exception e) {
							//do nothing
						}
						//out.flush();
						
						
					} 
				
				
				
				
				
				
				
				
			} else {
				
				//req.setAttribute(ProxySys.TREMOLO_BINARY_DATA, baos.toByteArray());
				
				
				//InputStream in = entity.getContent();
				
				OutputStream out = resp.getOutputStream();
				
				while ((len = ins.read(buffer)) != -1) {
					out.write(buffer, 0, len);
				}
				
				
				
				//out.close();
			}
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.ConfigSys#getConfigManager()
	 */
	
	public ConfigManager getConfigManager() {
		return this.cfg;
	}
}

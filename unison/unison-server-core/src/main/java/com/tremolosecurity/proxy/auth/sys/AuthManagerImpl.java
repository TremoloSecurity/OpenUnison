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


package com.tremolosecurity.proxy.auth.sys;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResult;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.config.xml.MechanismType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.log.AccessLog;
import com.tremolosecurity.log.AccessLog.AccessEvent;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningParams;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.proxy.ProxyData;
import com.tremolosecurity.proxy.ProxyRequest;
import com.tremolosecurity.proxy.ProxyResponse;
import com.tremolosecurity.proxy.ProxyUtil;
import com.tremolosecurity.proxy.auth.AnonAuth;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AuthMechanism;
import com.tremolosecurity.proxy.auth.AuthMgrSys;
import com.tremolosecurity.proxy.auth.AuthSys;
import com.tremolosecurity.proxy.auth.RequestHolder;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.util.NextSys;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.proxy.util.ProxyTools;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.util.NVP;

public class AuthManagerImpl implements AuthManager {
	
	static transient Logger logger = org.apache.logging.log4j.LogManager.getLogger(AuthManager.class.getName());
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.auth.sys.AuthManager#nextAuth(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, javax.servlet.http.HttpSession, boolean)
	 */
	@Override
	public boolean nextAuth(HttpServletRequest req, HttpServletResponse resp,
			HttpSession session, boolean jsRedirect) throws ServletException,
			IOException {
		return nextAuth(req, resp, session, jsRedirect, null);
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.auth.sys.AuthManager#nextAuth(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, javax.servlet.http.HttpSession, boolean, com.tremolosecurity.proxy.util.NextSys)
	 */
	@Override
	public boolean nextAuth(HttpServletRequest req, HttpServletResponse resp,
			HttpSession session, boolean jsRedirect, NextSys next)
			throws ServletException, IOException {

		if (next == null) {
			next = (NextSys) req.getAttribute(NEXT_SYS);
			if (next == null) {
				throw new ServletException("Unknown state");
			}
		}

		// HttpSession session = req.getSession(true);

		AuthController actl = (AuthController) req.getSession().getAttribute(
				ProxyConstants.AUTH_CTL);
		RequestHolder reqHolder = actl.getHolder();

		String actName = "";
		UrlHolder holder = (UrlHolder) req
				.getAttribute(ProxyConstants.AUTOIDM_CFG);
		if (reqHolder != null) {
			actName = reqHolder.getAuthChainName();
		} else {

			actName = holder.getUrl().getAuthChain();

		}

		AuthChainType act = holder.getConfig().getAuthChains().get(actName);
		
		if (act == null) {
			act = holder.getConfig().getAuthFailChain();
		}

		/*
		 * if (reqHolder != null && ! mt.getUri().equals(req.getRequestURI())) {
		 * step = new Integer(step.intValue() - 1); }
		 */

		return execAuth(req, resp, session, jsRedirect, holder, act, req
				.getRequestURL().toString(), next);
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.auth.sys.AuthManager#execAuth(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, javax.servlet.http.HttpSession, boolean, com.tremolosecurity.config.util.UrlHolder, com.tremolosecurity.config.xml.AuthChainType, java.lang.String)
	 */
	@Override
	public boolean execAuth(HttpServletRequest req, HttpServletResponse resp,
			HttpSession session, boolean jsRedirect, UrlHolder holder,
			AuthChainType act, String finalURL) throws IOException,
			ServletException {

		return execAuth(req, resp, session, jsRedirect, holder, act, finalURL,
				null);

	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.auth.sys.AuthManager#execAuth(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, javax.servlet.http.HttpSession, boolean, com.tremolosecurity.config.util.UrlHolder, com.tremolosecurity.config.xml.AuthChainType, java.lang.String, com.tremolosecurity.proxy.util.NextSys)
	 */
	@Override
	public boolean execAuth(HttpServletRequest req, HttpServletResponse resp,
			HttpSession session, boolean jsRedirect, UrlHolder holder,
			AuthChainType act, String finalURL, NextSys next)
			throws IOException, ServletException {

		boolean shortCircut = false;
		ConfigManager cfg = (ConfigManager) req
				.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);

		if (act.getLevel() == 0 && (act != cfg.getAuthFailChain())) {
			AuthController actl = (AuthController) session
					.getAttribute(ProxyConstants.AUTH_CTL);

			// there's no need to go through the process
			String anonMechName = act.getAuthMech().get(0).getName();
			MechanismType mt = holder.getConfig().getAuthMechs()
					.get(anonMechName);
			AnonAuth anonAuth = (AnonAuth) holder.getConfig().getAuthMech(
					mt.getUri());
			anonAuth.createSession(session, act);

			return finishSuccessfulLogin(req, resp, holder, act,
					actl.getHolder(), actl, next);
		}

		RequestHolder reqHolder;

		int step = -1;

		AuthController actl = (AuthController) req.getSession().getAttribute(
				ProxyConstants.AUTH_CTL);

		ArrayList<AuthStep> auths = actl.getAuthSteps();
		if (auths.size() == 0) {

			int id = 0;
			for (AuthMechType amt : act.getAuthMech()) {
				AuthStep as = new AuthStep();
				as.setId(id);
				as.setExecuted(false);
				as.setRequired(amt.getRequired().equals("required"));

				as.setSuccess(false);
				auths.add(as);
				id++;
			}

			boolean anyRequired = false;
			for (AuthStep as : auths) {
				if (as.isRequired()) {
					anyRequired = true;
					break;
				}
			}

			if (!anyRequired) {
				act.setFinishOnRequiredSucess(true);
			}

			step = 0;
			
			HashMap<String, Attribute> params = new HashMap<String, Attribute>();
			ProxyUtil.loadParams(req, params);
			try {
				reqHolder = new RequestHolder(RequestHolder.getMethod(req
						.getMethod()), params, finalURL, act.getName(),((ProxyRequest) req).getQueryStringParams());
				actl.setHolder(reqHolder);
			} catch (Exception e) {
				throw new ServletException("Error creating request holder", e);
			}

		} else {
			reqHolder = actl.getHolder();
			boolean clearAllNotRequired = false;

			// determine the step
			for (AuthStep as : auths) {

				if (as.isSuccess()) {
					
					//TODO Check to see if the user is locked out
					if (act.getCompliance() != null && act.getCompliance().isEnabled()) {
						Attribute lastFailed = actl.getAuthInfo().getAttribs().get(act.getCompliance().getLastFailedAttribute());
						Attribute numFailures = actl.getAuthInfo().getAttribs().get(act.getCompliance().getNumFailedAttribute());
						
						if (logger.isDebugEnabled()) {
							logger.debug("lastFailed Attribute : '" + lastFailed + "'");
							logger.debug("numFailures Attribute : '" + numFailures + "'");
						}
						
						if (lastFailed != null && numFailures != null) {
							
							long lastFailedTS = lastFailed.getValues().size() > 0 ? Long.parseLong(lastFailed.getValues().get(0)) : 0;
							int numPrevFailures = Integer.parseInt(numFailures.getValues().size() > 0 ? numFailures.getValues().get(0) : "0");
							long now = new DateTime(DateTimeZone.UTC).getMillis();
							long lockedUntil = lastFailedTS + act.getCompliance().getMaxLockoutTime();
							
							if (logger.isDebugEnabled()) {
								logger.debug("Num Failed : " + numPrevFailures);
								logger.debug("Last Failed : '" + lastFailedTS + "'");
								logger.info("Now : '" + now + "'");
								logger.info("Locked Until : '" + lockedUntil + "'");
								logger.info("locked >= now? : '" + (lockedUntil >= now) + "'");
								logger.info("max fails? : '" + act.getCompliance().getMaxFailedAttempts() + "'");
								logger.info("too many fails : '" + (numPrevFailures >= act.getCompliance().getMaxFailedAttempts()) + "'");
							}
							
							
							
							if (lockedUntil >= now && numPrevFailures >= act.getCompliance().getMaxFailedAttempts()) {
								try {
									failAuthentication(req, resp, holder, act);
								} catch (Exception e) {
									throw new ServletException("Could not complete authentication failure",e);
								}
								return false;
							}
						}
						
					}
					
					if (act.isFinishOnRequiredSucess()) {
						step = -1;
						clearAllNotRequired = true;
					}
				} else {

					if (as.isRequired()) {

						if (as.isExecuted()) {
							
							
							//TODO update the user's account to show a failed auth
							
							
							
							
							try {
								failAuthentication(req, resp, holder, act);
							} catch (Exception e) {
								throw new ServletException("Could not complete authentication failure",e);
							}

							return false;
						} else {
							step = as.getId();
							break;
						}

					} else {
						if (clearAllNotRequired) {
							as.setExecuted(true);
							as.setSuccess(true);
						} else {
							if (as.isExecuted()) {

							} else {
								step = as.getId();
								break;
							}
						}

					}
				}

			}
		}

		if (step != -1) {

			/*if (jsRedirect && step < auths.size()) {
				step++;
			}*/

			AuthStep curStep = auths.get(step);

			actl.setCurrentStep(curStep);

			AuthMechType amt = act.getAuthMech().get(step);

			loadAmtParams(session, amt);

			// req.getRequestDispatcher(authFilterURI).forward(req, resp);

			Cookie sessionCookieName = new Cookie("autoIdmSessionCookieName",
					holder.getApp().getCookieConfig().getSessionCookieName());
			String domain = ProxyTools.getInstance().getCookieDomain(
					holder.getApp().getCookieConfig(), req);
			if (domain != null) {
				sessionCookieName.setDomain(domain);
			}
			sessionCookieName.setPath("/");
			sessionCookieName.setMaxAge(-1);
			sessionCookieName.setSecure(false);
			//resp.addCookie(sessionCookieName);
			
			if ((holder.getApp() == null || holder.getApp().getCookieConfig() == null || holder.getApp().getCookieConfig() == null || holder.getApp().getCookieConfig().isCookiesEnabled() == null)  || holder.getApp().getCookieConfig().isCookiesEnabled()) {
				ProxyResponse.addCookieToResponse(holder, sessionCookieName, (HttpServletResponse)((ProxyResponse)resp).getResponse());
			}

			Cookie appCookieName = new Cookie("autoIdmAppName",
					URLEncoder.encode(holder.getApp().getName(), "UTF-8"));
			if (domain != null) {
				appCookieName.setDomain(domain);
			}
			appCookieName.setPath("/");
			appCookieName.setMaxAge(-1);
			appCookieName.setSecure(false);

			if ((holder.getApp() == null || holder.getApp().getCookieConfig() == null || holder.getApp().getCookieConfig() == null || holder.getApp().getCookieConfig().isCookiesEnabled() == null)  || holder.getApp().getCookieConfig().isCookiesEnabled()) {
				ProxyResponse.addCookieToResponse(holder, appCookieName, (HttpServletResponse)((ProxyResponse)resp).getResponse());
			}
			//resp.addCookie(appCookieName);

			String redirectURI = "";

			MechanismType nextAuthConfiguration = null;
			
			if (holder.getConfig().getContextPath().equalsIgnoreCase("/")) {
				nextAuthConfiguration = holder.getConfig().getAuthMechs()
						.get(amt.getName());
				
				if (nextAuthConfiguration == null) {
					StringBuilder sb = new StringBuilder().append("Authentication mechanism '").append(amt.getName()).append("' does not exist, will always fail");
					logger.warn(sb.toString());
					nextAuthConfiguration = holder.getConfig().getAuthFailMechanism();
				}
				
				redirectURI = nextAuthConfiguration.getUri();
			} else {
				nextAuthConfiguration = holder.getConfig().getAuthMechs()
						.get(amt.getName());
				
				if (nextAuthConfiguration == null) {
					StringBuilder sb = new StringBuilder().append("Authentication mechanism '").append(amt.getName()).append("' does not exist, will always fail");
					logger.warn(sb.toString());
					nextAuthConfiguration = holder.getConfig().getAuthFailMechanism();
				}
				
				redirectURI = new StringBuffer()
						.append(holder.getConfig().getContextPath())
						.append(nextAuthConfiguration.getUri()).toString();
			}

			req.getSession().setAttribute("TREMOLO_AUTH_URI", redirectURI);

			if (jsRedirect) {

				StringBuffer b = new StringBuffer();
				b.append("<html><head></head><body onload=\"window.location='")
						.append(ProxyTools.getInstance().getFqdnUrl(
								redirectURI, req))
						.append("';\"></body></html>");
				String respHTML = b.toString();

				ProxyData pd = new ProxyData();

				pd.setHolder(holder);
				pd.setIns(new ByteArrayInputStream(respHTML.getBytes("UTF-8")));
				pd.setPostProc(null);
				pd.setRequest(null);
				pd.setResponse(null);
				pd.setText(true);
				pd.setLogout(false);

				req.setAttribute(ProxyConstants.TREMOLO_PRXY_DATA, pd);

				// req.setAttribute(ProxySys.AUTOIDM_STREAM_WRITER,true);
				// req.setAttribute(ProxySys.TREMOLO_TXT_DATA, new
				// StringBuffer(respHTML));

				resp.sendError(401);

			} else {

				AuthMechanism mech = cfg.getAuthMech(redirectURI);
				if (mech == null) {
					throw new ServletException("Redirect URI '" + redirectURI
							+ "' does not map to an authentication mechanism");
				}

				req.setAttribute(ProxyConstants.AUTH_REDIR_URI, redirectURI);
				if (curStep != null) {
					curStep.setExecuted(true);
				}

				if (req.getMethod().equalsIgnoreCase("get")) {
					mech.doGet(req, resp, curStep);
				} else if (req.getMethod().equalsIgnoreCase("post")) {
					mech.doPost(req, resp, curStep);
				} else if (req.getMethod().equalsIgnoreCase("put") || req.getMethod().equalsIgnoreCase("patch")) {
					mech.doPut(req, resp, curStep);
				} else if (req.getMethod().equalsIgnoreCase("delete")) {
					mech.doDelete(req, resp, curStep);
				} else if (req.getMethod().equalsIgnoreCase("head")) {
					mech.doHead(req, resp, curStep);
				} else if (req.getMethod().equalsIgnoreCase("options")) {
					mech.doOptions(req, resp, curStep);

				}

			}

			return false;
		} else {

			boolean success = true;
			boolean opSuccess = false;
			boolean hasOptional = false;

			for (AuthStep as : auths) {
				if (as.isRequired()) {
					if (!as.isSuccess()) {
						success = false;
						break;
					}
				} else {
					hasOptional = true;
					if (as.isSuccess()) {
						opSuccess = true;
					}
				}

			}

			boolean allSuccess = success
					&& ((hasOptional && opSuccess) || (!hasOptional));

			if (allSuccess) {

				return finishSuccessfulLogin(req, resp, holder, act, reqHolder,
						actl, next);

			} else {

				throw new ServletException("Unknown state");
				/*
				 * Cookie sessionCookieName = new
				 * Cookie("autoIdmSessionCookieName","DNE");
				 * sessionCookieName.setDomain
				 * (ProxyTools.getInstance().getCookieDomain
				 * (holder.getApp().getCookieConfig(), req));
				 * sessionCookieName.setPath("/");
				 * sessionCookieName.setMaxAge(0);
				 * sessionCookieName.setSecure(false);
				 * //resp.addCookie(sessionCookieName);
				 * 
				 * Cookie appCookieName = new Cookie("autoIdmAppName","DNE");
				 * appCookieName
				 * .setDomain(ProxyTools.getInstance().getCookieDomain
				 * (holder.getApp().getCookieConfig(), req));
				 * appCookieName.setPath("/"); appCookieName.setMaxAge(0);
				 * appCookieName.setSecure(false);
				 * //resp.addCookie(appCookieName);
				 */

			}

		}
	}

	private void failAuthentication(HttpServletRequest req, HttpServletResponse resp, UrlHolder holder,
			AuthChainType act) throws ServletException, IOException,Exception {
		AccessLog.log(AccessEvent.AuFail, holder.getApp(),
				req, null, act.getName());

		req.setAttribute(AuthMgrSys.AU_RES, new Boolean(
				false));

		AuthMgrSys ams = new AuthMgrSys(null);
		try {
			ams.processAuthResp(req, resp, holder,
					new Boolean(false));
		} catch (InstantiationException
				| IllegalAccessException
				| ClassNotFoundException e) {
			throw new ServletException(
					"Could not initialize custom response",
					e);
		}
		
		if (act.getCompliance() != null && act.getCompliance().isEnabled()) {
			String dn = getFailedUserDN(req);
			
			
			if (dn != null) {
				ArrayList<String> attrsToLoad = new ArrayList<String>();
				attrsToLoad.add(act.getCompliance().getNumFailedAttribute());
				attrsToLoad.add(act.getCompliance().getUidAttributeName());
				
				
				LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(dn, 0, "(objectClass=*)", attrsToLoad);
				
				if (res.hasMore()) {
					LDAPEntry userObj = res.next();
					String uid = userObj.getAttribute(act.getCompliance().getUidAttributeName()).getStringValue();
					
					LDAPAttribute numFails = userObj.getAttribute(act.getCompliance().getNumFailedAttribute());
					
					int fails = 0;
					if (numFails != null) {
						fails = Integer.parseInt(numFails.getStringValue());
					}
					fails++;
					
					User updateAttrs = new User(uid);
					
					DateTime now = new DateTime(DateTimeZone.UTC);
					
					updateAttrs.getAttribs().put(act.getCompliance().getLastFailedAttribute(), new Attribute(act.getCompliance().getLastFailedAttribute(),Long.toString(now.getMillis())));
					updateAttrs.getAttribs().put(act.getCompliance().getNumFailedAttribute(), new Attribute(act.getCompliance().getNumFailedAttribute(),Integer.toString(fails)));
					updateAttrs.getAttribs().put(act.getCompliance().getUidAttributeName(), new Attribute(act.getCompliance().getUidAttributeName(),uid));
					
					
					
					HashMap<String,Object> wfReq = new HashMap<String,Object>();
					wfReq.put(ProvisioningParams.UNISON_EXEC_TYPE, ProvisioningParams.UNISON_EXEC_SYNC);
					
					
					//load attributes from the user object if it exists
					/*AuthInfo userData = ((AuthController) req.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
					
					if (GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getUserAttrbiutes() != null) {
						for (String attrName : GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getUserAttrbiutes()) {
							Attribute fromAuth = userData.getAttribs().get(attrName);
							if (fromAuth != null) {
								Attribute attrForWF = new Attribute(attrName);
								attrForWF.getValues().addAll(fromAuth.getValues());
								
								updateAttrs.getAttribs().put(attrName,attrForWF);
							}
						}
					}*/
					
					
					
					holder.getConfig().getProvisioningEngine().getWorkFlow(act.getCompliance().getUpdateAttributesWorkflow()).executeWorkflow(updateAttrs, wfReq);
				}
			}
			
		}
	}

	private String getFailedUserDN(HttpServletRequest req) {
		
		String dn = (String) req.getAttribute(ProxyConstants.AUTH_FAILED_USER_DN);
		
		AuthController actl = (AuthController) req.getSession().getAttribute(ProxyConstants.AUTH_CTL);
		
		if (dn != null) {
			return dn;
		} else if (actl != null) {
			return actl.getAuthInfo().getUserDN();
		} else {
			return null;
		}
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.auth.sys.AuthManager#finishSuccessfulLogin(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, com.tremolosecurity.config.util.UrlHolder, com.tremolosecurity.config.xml.AuthChainType, com.tremolosecurity.proxy.auth.RequestHolder, com.tremolosecurity.proxy.auth.AuthController, com.tremolosecurity.proxy.util.NextSys)
	 */
	@Override
	public boolean finishSuccessfulLogin(HttpServletRequest req,
			HttpServletResponse resp, UrlHolder holder, AuthChainType act,
			RequestHolder reqHolder, AuthController actl, NextSys next)
			throws IOException, ServletException {

		ConfigManager cfg = (ConfigManager) req
				.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		AuthInfo ai = actl.getAuthInfo();

		ai.setAuthComplete(true);

		StringBuffer msg = new StringBuffer();
		msg.append(act.getLevel()).append(" / ").append(act.getName());
		AccessLog.log(AccessEvent.AuSuccess, holder.getApp(), req, ai,
				msg.toString());

		StringBuffer redirURL;

		if (reqHolder == null) {
			Cookie sessionCookieName = new Cookie("autoIdmSessionCookieName",
					"DNE");
			String domain = ProxyTools.getInstance().getCookieDomain(
					holder.getApp().getCookieConfig(), req);
			if (domain != null) {
				sessionCookieName.setDomain(domain);
			}
			sessionCookieName.setPath("/");
			sessionCookieName.setMaxAge(0);
			sessionCookieName.setSecure(false);
		    //resp.addCookie(sessionCookieName);
			if ((holder.getApp() == null || holder.getApp().getCookieConfig() == null || holder.getApp().getCookieConfig() == null || holder.getApp().getCookieConfig().isCookiesEnabled() == null)  || holder.getApp().getCookieConfig().isCookiesEnabled()) {
				ProxyResponse.addCookieToResponse(holder, sessionCookieName, (HttpServletResponse)((ProxyResponse)resp).getResponse());
			}

			Cookie appCookieName = new Cookie("autoIdmAppName", "DNE");
			if (domain != null) {
				appCookieName.setDomain(domain);
			}
			appCookieName.setPath("/");
			appCookieName.setMaxAge(0);
			appCookieName.setSecure(false);
			//resp.addCookie(appCookieName);
			if ((holder.getApp() == null || holder.getApp().getCookieConfig() == null || holder.getApp().getCookieConfig() == null || holder.getApp().getCookieConfig().isCookiesEnabled() == null)  || holder.getApp().getCookieConfig().isCookiesEnabled()) {
				ProxyResponse.addCookieToResponse(holder, appCookieName, (HttpServletResponse)((ProxyResponse)resp).getResponse());
			}

			AuthMgrSys ams = new AuthMgrSys(null);
			try {
				ams.processAuthResp(req, resp, holder, new Boolean(true));
			} catch (InstantiationException | IllegalAccessException
					| ClassNotFoundException e) {
				throw new ServletException(
						"Could not initialize custom response", e);
			}

			return true;

		} else {
			switch (reqHolder.getMethod()) {
			case GET:
				redirURL = getGetRedirectURL(reqHolder);

				Cookie sessionCookieName = new Cookie(
						"autoIdmSessionCookieName", "DNE");
				String domain = ProxyTools.getInstance().getCookieDomain(
						holder.getApp().getCookieConfig(), req);
				if (domain != null) {
					sessionCookieName.setDomain(domain);
				}
				sessionCookieName.setPath("/");
				sessionCookieName.setMaxAge(0);
				sessionCookieName.setSecure(false);
				//resp.addCookie(sessionCookieName);
				if ((holder.getApp() == null || holder.getApp().getCookieConfig() == null || holder.getApp().getCookieConfig() == null || holder.getApp().getCookieConfig().isCookiesEnabled() == null)  || holder.getApp().getCookieConfig().isCookiesEnabled()) {
					ProxyResponse.addCookieToResponse(holder, sessionCookieName, (HttpServletResponse)((ProxyResponse)resp).getResponse());
				}

				Cookie appCookieName = new Cookie("autoIdmAppName", "DNE");
				if (domain != null) {
					appCookieName.setDomain(domain);
				}
				appCookieName.setPath("/");
				appCookieName.setMaxAge(0);
				appCookieName.setSecure(false);
				//resp.addCookie(appCookieName);
				if ((holder.getApp() == null || holder.getApp().getCookieConfig() == null || holder.getApp().getCookieConfig() == null || holder.getApp().getCookieConfig().isCookiesEnabled() == null)  || holder.getApp().getCookieConfig().isCookiesEnabled()) {
					ProxyResponse.addCookieToResponse(holder, appCookieName, (HttpServletResponse)((ProxyResponse)resp).getResponse());
				}

				break;

			case POST:
				redirURL = new StringBuffer(holder.getConfig()
						.getAuthFormsPath()).append("postPreservation.jsp");
				break;

			default:
				redirURL = new StringBuffer(reqHolder.getURL());
			}

			req.setAttribute(AuthMgrSys.AU_RES, new Boolean(true));

			AuthMgrSys ams = new AuthMgrSys(null);
			try {
				ams.processAuthResp(req, resp, holder, new Boolean(true));
			} catch (InstantiationException | IllegalAccessException
					| ClassNotFoundException e) {
				throw new ServletException(
						"Could not initialize custom response", e);
			}

			
			
			if (act.getCompliance() != null && act.getCompliance().isEnabled()) {
				Attribute uidAttribute = actl.getAuthInfo().getAttribs().get(act.getCompliance().getUidAttributeName());
				if (uidAttribute != null) {
					String uid = uidAttribute.getValues().get(0);
					User updateAttrs = new User(uid);
					
					updateAttrs.getAttribs().put(act.getCompliance().getLastSucceedAttribute(), new Attribute(act.getCompliance().getLastSucceedAttribute(),Long.toString(new DateTime(DateTimeZone.UTC).getMillis())));
					updateAttrs.getAttribs().put(act.getCompliance().getNumFailedAttribute(), new Attribute(act.getCompliance().getNumFailedAttribute(),"0"));
					updateAttrs.getAttribs().put(act.getCompliance().getUidAttributeName(), new Attribute(act.getCompliance().getUidAttributeName(),uid));
					
					
					
					if (GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getUserAttrbiutes() != null) {
						for (String attrName : GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getUserAttrbiutes()) {
							Attribute fromAuth = ai.getAttribs().get(attrName);
							if (fromAuth != null) {
								Attribute attrForWF = new Attribute(attrName);
								attrForWF.getValues().addAll(fromAuth.getValues());
								
								updateAttrs.getAttribs().put(attrName,attrForWF);
							}
						}
					}
					
					
					HashMap<String,Object> wfReq = new HashMap<String,Object>();
					wfReq.put(ProvisioningParams.UNISON_EXEC_TYPE, ProvisioningParams.UNISON_EXEC_SYNC);
					
					
					try {
						holder.getConfig().getProvisioningEngine().getWorkFlow(act.getCompliance().getUpdateAttributesWorkflow()).executeWorkflow(updateAttrs, wfReq);
					} catch (ProvisioningException e) {
						throw new ServletException("Could not update successful login attribute",e);
					}
				}
			}
			
			
			
			// if
			// (redirURL.toString().equalsIgnoreCase(req.getRequestURL().toString())
			// || ( actl.getAuthSteps().size() == 1 && !
			// req.getRequestURI().startsWith(cfg.getAuthPath()))) {
			if (!req.getRequestURI().startsWith(cfg.getAuthPath())) {

				next.nextSys(req, resp);

			} else {
				resp.sendRedirect(redirURL.toString());
			}
			// resp.setStatus(302);
			// resp.setHeader("Location", redirURL.toString());

			return false;
		}

	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.auth.sys.AuthManager#loadAmtParams(javax.servlet.http.HttpSession, com.tremolosecurity.config.xml.AuthMechType)
	 */
	@Override
	public void loadAmtParams(HttpSession session, AuthMechType amt) {
		Iterator<ParamType> it = amt.getParams().getParam().iterator();
		HashMap<String, Attribute> authParams = new HashMap<String, Attribute>();
		while (it.hasNext()) {
			ParamType param = it.next();
			Attribute attrib = authParams.get(param.getName());
			if (attrib == null) {
				attrib = new Attribute(param.getName());
				authParams.put(param.getName(), attrib);
			}
			attrib.getValues().add(param.getValue());
		}

		session.setAttribute(ProxyConstants.AUTH_MECH_PARAMS, authParams);
		session.setAttribute(ProxyConstants.AUTH_MECH_NAME, amt.getName());
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.proxy.auth.sys.AuthManager#getGetRedirectURL(com.tremolosecurity.proxy.auth.RequestHolder)
	 */
	@Override
	public StringBuffer getGetRedirectURL(RequestHolder reqHolder) {
		StringBuffer redirURL = new StringBuffer(reqHolder.getURL());

		if (reqHolder.isForceAuth() || redirURL.indexOf("?") > 0) {
			return redirURL;
		}

		boolean first = true;
		for (NVP p : reqHolder.getQueryStringParams()) {
			if (first) {
				first = false;
				redirURL.append('?');
			} else {
				redirURL.append('&');
			}
			
			try {
				redirURL.append(p.getName()).append('=')
				.append(URLEncoder.encode(p.getValue(),"UTF-8"));
			} catch (UnsupportedEncodingException e) {
				
			}
		}
		
		
		
		return redirURL;
	}
}

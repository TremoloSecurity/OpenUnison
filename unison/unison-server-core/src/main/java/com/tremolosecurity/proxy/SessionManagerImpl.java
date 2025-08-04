/*
Copyright 2015, 2018 Tremolo Security, Inc.

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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.GZIPOutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.Logger;

import org.joda.time.DateTime;

import com.google.gson.Gson;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.openunison.OpenUnisonConstants;
import com.tremolosecurity.proxy.auth.AnonAuth;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.logout.LogoutHandler;
import com.tremolosecurity.proxy.logout.LogoutUtil;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.proxy.util.ProxyTools;


public class SessionManagerImpl implements SessionManager {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(SessionManagerImpl.class);

	private static final String AUTOIDM_KEY_SESSION = "AUTOIDM_KEY_SESSION";

	public static final String TREMOLO_SESSION_LAST_ACCESSED = "TREMOLO_SESSION_LAST_ACCESSED";
	public static final String TREMOLO_EXTERNAL_SESSION = "TREMOLO_EXTERNAL_SESSION";
	private final SessionByUserChecker sessionByUSerChacker;

	SecureRandom random;

	private ConfigManager cfg;

	private AuthChainType anonChainType;

	private AnonAuth anonMech;

	ServletContext ctx;
	
	

	private ConcurrentHashMap<String, TremoloHttpSession> sessions;
	private ConcurrentHashMap<String, ConcurrentHashMap<String, TremoloHttpSession>> sessionsByUserDN;


	private SessionTimeoutChecker checker;

	
		
	

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.tremolosecurity.proxy.SessionManager#invalidateSession(com.
	 * tremolosecurity.proxy.TremoloHttpSession)
	 */
	@Override
	public void invalidateSession(TremoloHttpSession tsession) {

		String userdn = tsession.getUserDN();

		if (logger.isDebugEnabled()) {
			logger.debug("Invalidating Session : " + tsession.getId());
		}

		this.removeUserSession(userdn, tsession);

		shutdownSession(tsession);
		
		sessions.remove(tsession.getId());
	}

	@Override
	public void shutdownSession(TremoloHttpSession tsession) {
		//we need to run the logout handlers
		ArrayList<LogoutHandler> handlers = (ArrayList<LogoutHandler>) tsession.getAttribute(LogoutUtil.LOGOUT_HANDLERS);
		if (handlers != null) {
			for (LogoutHandler handler : handlers) {
				try {
					handler.handleLogout(null, null,false);
				} catch (ServletException e) {
					logger.warn("Could not run logout handler",e);
				}
			}
		}
	}

	@Override
	public void addUserSession(String userDN, TremoloHttpSession session) {
		synchronized (this.sessionsByUserDN) {
			ConcurrentHashMap<String,TremoloHttpSession> sessions = this.sessionsByUserDN.get(userDN);
			if (sessions == null) {
				sessions = new ConcurrentHashMap<String,TremoloHttpSession>();
				this.sessionsByUserDN.put(userDN, sessions);
			}
			sessions.put(session.getId(), session);
		}

		session.putValue(ProxyConstants.TREMOLO_SESSION_DN,userDN);

	}

	@Override
	public void removeUserSession(String dn, TremoloHttpSession session) {
		if (dn == null) {
			return;
		}
		synchronized (this.sessionsByUserDN) {
			ConcurrentHashMap<String, TremoloHttpSession> sessions = this.sessionsByUserDN.get(dn);
			if (sessions != null) {
				sessions.remove(session.getId());
				if (sessions.isEmpty()) {
					this.sessionsByUserDN.remove(dn);
				}
			}
			this.sessions.remove(session.getId());

		}


	}

	@Override
	public void moveSession(String currentDn, String newDn) {
		synchronized (this.sessionsByUserDN) {
			ConcurrentHashMap<String, TremoloHttpSession> sessions = this.sessionsByUserDN.remove(currentDn);
			if (sessions != null) {
				this.sessionsByUserDN.put(newDn, sessions);
			}
		}
	}

	@Override
	public void logoutAll(String userdn) {
		logger.info("Logging out user '" + userdn + "'");
		final ConcurrentHashMap<String, TremoloHttpSession> sessions;
		synchronized (this.sessionsByUserDN) {
			logger.info(this.sessionsByUserDN.keySet());
			sessions = this.sessionsByUserDN.get(userdn);
			if (sessions != null) {
				this.sessionsByUserDN.remove(userdn);
			}
		}

		if (sessions != null) {
			sessions.keySet().forEach(sessionid -> {
				TremoloHttpSession session = sessions.get(sessionid);
				session.invalidate();
				this.sessions.remove(sessionid);
			});
		}
	}

	@Override
	public void removeSessionFromCache(TremoloHttpSession tsession) {
		if (logger.isDebugEnabled()) {
			logger.debug("Removing Session : " + tsession.getId());
		}
		
		sessions.remove(tsession.getId());
	}



	public SessionManagerImpl(ConfigManager cfg, ServletContext ctx) {
		sessions = new ConcurrentHashMap<String, TremoloHttpSession>();
		sessionsByUserDN = new ConcurrentHashMap<String, ConcurrentHashMap<String, TremoloHttpSession>>();

		this.ctx = ctx;
		try {
			this.random = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			logger.error("Could not load secure random", e);
		}

		this.cfg = cfg;

		for (String key : this.cfg.getAuthChains().keySet()) {
			AuthChainType act = this.cfg.getAuthChains().get(key);
			if (act.getLevel() == 0) {
				this.anonChainType = act;
				String mechName = act.getAuthMech().get(0).getName();
				this.anonMech = (AnonAuth) cfg.getAuthMech(cfg.getAuthMechs()
						.get(mechName).getUri());
			}
		}

		if (this.anonMech == null) {
			this.anonChainType = new AuthChainType();
			this.anonChainType.setFinishOnRequiredSucess(true);
			this.anonChainType.setLevel(0);
			this.anonChainType.setName("anon");

			this.anonMech = new AnonAuth();

		}

		checker = new SessionTimeoutChecker(this.cfg,this);
		checker.start();

		this.sessionByUSerChacker = new SessionByUserChecker(this.cfg,this,this.sessionsByUserDN);
		this.sessionByUSerChacker.start();


		if (cfg.getCfg().getApplications().getOpenSessionCookieName() == null) {
			cfg.getCfg().getApplications()
					.setOpenSessionCookieName("TREMOLO_SESSION");
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.tremolosecurity.proxy.SessionManager#getSession(com.tremolosecurity
	 * .config.util.UrlHolder, jakarta.servlet.http.HttpServletRequest,
	 * jakarta.servlet.http.HttpServletResponse, jakarta.servlet.ServletContext)
	 */
	@Override
	public HttpSession getSession(UrlHolder holder, HttpServletRequest request,
			HttpServletResponse response, ServletContext ctx) throws Exception {

		// if we are not using a secure session, use generic session
		if (holder.getApp().getCookieConfig() == null) {
			return request.getSession();
		}

		String cookieName = holder.getApp().getCookieConfig()
				.getSessionCookieName();
		if (cookieName == null || cookieName.length() == 0) {
			return request.getSession();
		}

		HttpSession session = locateSession(holder, request, ctx, cookieName,
				response);
		if (session instanceof HttpSession) {
			((TremoloHttpSession) session).refresh(ctx, this);
		}

		return session;

	}

	private HttpSession locateSession(UrlHolder holder,
			HttpServletRequest request, ServletContext ctx, String cookieName,
			HttpServletResponse resp) throws Exception {
		Cookie sessionCookie = null;

		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (int i = 0; i < cookies.length; i++) {
				Cookie cookie = cookies[i];
				if (cookie.getName().equalsIgnoreCase(cookieName)) {
					sessionCookie = cookie;
					break;
				}
			}
		}

		ConfigManager cfg = (ConfigManager) ctx
				.getAttribute(ProxyConstants.TREMOLO_CONFIG);

		ApplicationType app;

		if (holder != null) {
			app = holder.getApp();
		} else {
			app = null;

			String appName = null;
			if (cookies != null) {
				for (int i = 0; i < cookies.length; i++) {
					if (cookies[i].getName().equals("autoIdmAppName")) {
						appName = URLDecoder.decode(cookies[i].getValue(),
								"UTF-8");
						break;
					}
				}
			}

			if (appName == null) {
				// TODO create open session
				if (cookies != null) {
					for (int i = 0; i < cookies.length; i++) {
						if (cookies[i].getName().equals(cfg.getCfg().getApplications().getOpenSessionCookieName())) {
							String sessionID = cookies[i].getValue();
							TremoloHttpSession tsession = this.sessions
									.get(sessionID);
							// TODO add timeouts
							if (tsession == null) {
								return this.createOpenSession(request, resp,
										ctx);
							} else {
								return tsession;
							}

						}
					}
				}

				return createOpenSession(request, resp, ctx);
			} else {
				app = cfg.getApp(appName);

				if (app == null) {
					throw new Exception("No application named '" + appName
							+ "' found");
				}

			}
		}

		SecretKey encKey = cfg
				.getSecretKey(app.getCookieConfig().getKeyAlias());

		// TremoloHttpSession tsession = (TremoloHttpSession)
		// request.getSession().getAttribute(app.getCookieConfig().getSessionCookieName());

		if (sessionCookie == null) {
			// if (tsession != null) tsession.invalidate();
			return createSession(app, request, resp, ctx, encKey);
		} else {

			HttpSession session = null;

			try {

				try {

					TremoloHttpSession tsession = findSessionFromCookie(sessionCookie, encKey,this);

					if (tsession == null) {
						return createSession(app, request, resp, ctx, encKey);
					}

					String fromSessionID = (String) tsession
							.getAttribute(OpenUnisonConstants.TREMOLO_SESSION_ID);

					if (app.getCookieConfig().getTimeout() > 0) {
						if (logger.isDebugEnabled()) {
							logger.debug("Application - '" + tsession.getAppName() + "' - Timeout greater then 0");
						}
						ExternalSessionExpires extSession = (ExternalSessionExpires) tsession.getAttribute(SessionManagerImpl.TREMOLO_EXTERNAL_SESSION);
						
						if (extSession != null) {
							if (logger.isDebugEnabled()) {
								logger.debug("Application - '" + tsession.getAppName() + "' - External session");
							}
							DateTime now = new DateTime();
							DateTime lastAccessed = (DateTime) tsession
									.getAttribute(SessionManagerImpl.TREMOLO_SESSION_LAST_ACCESSED);
							
							if (logger.isDebugEnabled()) {
								logger.debug("Application - '" + tsession.getAppName() + "' - now='" + now + "' ext expired='" + extSession.isExpired() + "'");
								logger.debug("Application - '" + tsession.getAppName() + "' - now='" + now + "' expires='" + lastAccessed + "' expired='" + (now.minusSeconds(app.getCookieConfig().getTimeout())
										.isAfter(lastAccessed)) + "'");
							}

							if (extSession.isExpired(app.getCookieConfig().getTimeout(),lastAccessed.getMillis())) {
								if (logger.isDebugEnabled()) {
									logger.debug("Application - '" + tsession.getAppName() + "' - Invalidating and creating");
								}
								//external session has expired, create a new one
								tsession.invalidate();
								return createSession(app, request, resp, ctx,
										encKey);
							} else {
								if (logger.isDebugEnabled()) {
									logger.debug("Application - '" + tsession.getAppName() + "' - Session OK");
								}
								tsession.setAttribute(
										SessionManagerImpl.TREMOLO_SESSION_LAST_ACCESSED,
										now);
								session = tsession;
							}
							
						} else {
							
							if (logger.isDebugEnabled()) {
								logger.debug("Application - '" + tsession.getAppName() + "' - Not external session");
							}
						
							DateTime lastAccessed = (DateTime) tsession
									.getAttribute(SessionManagerImpl.TREMOLO_SESSION_LAST_ACCESSED);
							DateTime now = new DateTime();
							
							if (logger.isDebugEnabled()) {
								logger.debug("Application - '" + tsession.getAppName() + "' - now='" + now + "' expires='" + lastAccessed + "' expired='" + (now.minusSeconds(app.getCookieConfig().getTimeout())
										.isAfter(lastAccessed)) + "'");
							}
							
							if (now.minusSeconds(app.getCookieConfig().getTimeout())
									.isAfter(lastAccessed)) {
								
								if (logger.isDebugEnabled()) {
									logger.debug("Application - '" + tsession.getAppName() + "' - Invalidating sesssion and recreating");
								}
								
								tsession.invalidate();
								return createSession(app, request, resp, ctx,
										encKey);
							} else {
								if (logger.isDebugEnabled()) {
									logger.debug("Application - '" + tsession.getAppName() + "' - Session OK");
								}
								
								tsession.setAttribute(
										SessionManagerImpl.TREMOLO_SESSION_LAST_ACCESSED,
										now);
								session = tsession;
							}
						}
					} else {
						session = tsession;
					}

				} catch (Exception e) {
					if (logger.isDebugEnabled()) {
						logger.debug("Exception loading session", e);
					}
					return createSession(app, request, resp, ctx, encKey);

				}

				// this.sessions.put(session.getSessionID(), key);
				// }

			} catch (Exception e) {
				logger.error("Error generating session", e);
			}
			if (session == null) {
				// session.invalidate();
				return createSession(app, request, resp, ctx, encKey);
			}

			// session.resetAccess();

			return session;

		}
	}



	public static TremoloHttpSession findSessionFromCookie(Cookie sessionCookie, SecretKey encKey,SessionManagerImpl sessionMgr)
			throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		String tokenHeader = new String(
				org.bouncycastle.util.encoders.Base64
						.decode(sessionCookie.getValue().getBytes(
								"UTF-8")));
		Gson gson = new Gson();
		Token token = gson.fromJson(tokenHeader, Token.class);
		byte[] iv = org.bouncycastle.util.encoders.Base64
				.decode(token.getIv());

		IvParameterSpec spec = new IvParameterSpec(iv);
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, encKey, spec);

		byte[] encBytes = org.bouncycastle.util.encoders.Base64
				.decode(token.getEncryptedRequest());
		String requestToken = new String(cipher.doFinal(encBytes));

		TremoloHttpSession tsession = sessionMgr.getSessions().get(requestToken);
		return tsession;
	}

	private HttpSession createSession(ApplicationType app,
			HttpServletRequest req, HttpServletResponse resp,
			ServletContext ctx, SecretKey encKey) throws Exception {

		byte[] idBytes = new byte[20];
		random.nextBytes(idBytes);

		StringBuffer b = new StringBuffer();
		b.append('f').append(Hex.encodeHexString(idBytes));
		String id = b.toString();

		// HttpSession session = req.getSession(true);
		TremoloHttpSession tsession = new TremoloHttpSession(id);
		tsession.setAppName(app.getName());
		tsession.refresh(this.ctx, this);
		tsession.setOpen(false);
		this.anonMech.createSession(tsession, this.anonChainType);

		AuthController actl = (AuthController) tsession
				.getAttribute(ProxyConstants.AUTH_CTL);

		AuthInfo auInfo = actl.getAuthInfo();
		auInfo.setAuthComplete(true);

		// session.setAttribute(app.getCookieConfig().getSessionCookieName(),
		// tsession);

		tsession.setAttribute(OpenUnisonConstants.TREMOLO_SESSION_ID, id);
		tsession.setMaxInactiveInterval(app.getCookieConfig().getTimeout());

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, encKey);

		byte[] encSessionKey = cipher.doFinal(id.getBytes("UTF-8"));
		String base64d = new String(
				org.bouncycastle.util.encoders.Base64.encode(encSessionKey));

		Token token = new Token();
		token.setEncryptedRequest(base64d);
		token.setIv(new String(org.bouncycastle.util.encoders.Base64
				.encode(cipher.getIV())));

		Gson gson = new Gson();

		String cookie = gson.toJson(token);

		byte[] btoken = cookie.getBytes("UTF-8");
		String encCookie = new String(
				org.bouncycastle.util.encoders.Base64.encode(btoken));

		Cookie sessionCookie;

		sessionCookie = new Cookie(
				app.getCookieConfig().getSessionCookieName(), encCookie);

		// logger.debug("session size : " +
		// org.apache.directory.shared.ldap.util.Base64.encode(encSession).length);
		String domain = ProxyTools.getInstance().getCookieDomain(
				app.getCookieConfig(), req);
		if (domain != null) {
			sessionCookie.setDomain(domain);
		}
		sessionCookie.setPath("/");
		sessionCookie.setSecure(false);
		sessionCookie.setMaxAge(-1);
		sessionCookie.setSecure(app.getCookieConfig().isSecure());
		sessionCookie.setHttpOnly(app.getCookieConfig().isHttpOnly() != null && app.getCookieConfig().isHttpOnly());
		//resp.addCookie(sessionCookie);
		ProxyResponse.addCookieToResponse(app, sessionCookie, resp);

		// delete the opensession if it exists
		if (cfg.getCfg().getApplications().getOpenSessionCookieName() != null && ! cfg.getCfg().getApplications().getOpenSessionCookieName().isEmpty()) {
		Cookie openSessionCookie = new Cookie(cfg.getCfg().getApplications()
				.getOpenSessionCookieName(), id);

		openSessionCookie.setPath("/");
		openSessionCookie.setSecure(cfg.getCfg().getApplications().isOpenSessionSecure());
		openSessionCookie.setHttpOnly(cfg.getCfg().getApplications().isOpenSessionHttpOnly());
		openSessionCookie.setMaxAge(0);
		resp.addCookie(openSessionCookie);
		}
		
		sessions.put(id, tsession);

		return tsession;
	}

	private HttpSession createOpenSession(HttpServletRequest req,
			HttpServletResponse resp, ServletContext ctx) throws Exception {

		byte[] idBytes = new byte[20];
		random.nextBytes(idBytes);
		StringBuffer b = new StringBuffer();
		b.append('f').append(Hex.encodeHexString(idBytes));
		String id = b.toString();

		// HttpSession session = req.getSession(true);
		TremoloHttpSession tsession = new TremoloHttpSession(id);
		tsession.setOpen(true);
		tsession.refresh(this.ctx, this);
		this.anonMech.createSession(tsession, this.anonChainType);

		AuthController actl = (AuthController) tsession
				.getAttribute(ProxyConstants.AUTH_CTL);

		AuthInfo auInfo = actl.getAuthInfo();
		auInfo.setAuthComplete(true);

		// session.setAttribute(app.getCookieConfig().getSessionCookieName(),
		// tsession);

		tsession.setAttribute(OpenUnisonConstants.TREMOLO_SESSION_ID, id);

		// TODO add global session timeout
		// tsession.setMaxInactiveInterval(app.getCookieConfig().getTimeout());

		// TODO add global open session name
		Cookie sessionCookie = new Cookie(cfg.getCfg().getApplications()
				.getOpenSessionCookieName(), id);

		sessionCookie.setPath("/");
		sessionCookie.setSecure(cfg.getCfg().getApplications().isOpenSessionSecure());
		sessionCookie.setHttpOnly(cfg.getCfg().getApplications().isOpenSessionHttpOnly());
		sessionCookie.setMaxAge(-1);
		// TODO add secure?
		// sessionCookie.setSecure(app.getCookieConfig().isSecure());
		resp.addCookie(sessionCookie);

		sessions.put(id, tsession);

		return tsession;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.tremolosecurity.proxy.SessionManager#getSession(java.lang.String,
	 * com.tremolosecurity.config.util.UrlHolder,
	 * jakarta.servlet.http.HttpServletRequest,
	 * jakarta.servlet.http.HttpServletResponse, jakarta.servlet.ServletContext)
	 */
	@Override
	public HttpSession getSession(String sessionCookieName, UrlHolder holder,
			HttpServletRequest request, HttpServletResponse response,
			ServletContext ctx) throws Exception {
		return this.locateSession(holder, request, ctx, sessionCookieName,
				response);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.tremolosecurity.proxy.SessionManager#writeSession(com.tremolosecurity
	 * .config.util.UrlHolder, com.tremolosecurity.proxy.TremoloHttpSession,
	 * jakarta.servlet.http.HttpServletRequest,
	 * jakarta.servlet.http.HttpServletResponse)
	 */
	@Override
	public void writeSession(UrlHolder holder, TremoloHttpSession session,
			HttpServletRequest request, HttpServletResponse response)
			throws IOException {
		/*
		 * Enumeration enumer = session.getAttributeNames(); while
		 * (enumer.hasMoreElements()) { String name = (String)
		 * enumer.nextElement(); String value =
		 * session.getAttribute(name).toString(); logger.debug(name + "='" +
		 * value + "'"); }
		 */

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		GZIPOutputStream gzip = new GZIPOutputStream(bos);
		ObjectOutputStream oos = new ObjectOutputStream(gzip);
		oos.writeObject(session);
		oos.flush();
		oos.close();

		byte[] encSession = new byte[0];

		try {
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(
					Cipher.ENCRYPT_MODE,
					holder.getConfig().getSecretKey(
							holder.getApp().getCookieConfig().getKeyAlias()));
			encSession = cipher.doFinal(bos.toByteArray());
		} catch (Exception e) {
			e.printStackTrace();
		}
		Cookie sessionCookie;
		sessionCookie = new Cookie(holder.getApp().getCookieConfig()
				.getSessionCookieName(), new String(
				Base64.encodeBase64(encSession)));

		// logger.debug("session size : " +
		// org.apache.directory.shared.ldap.util.Base64.encode(encSession).length);

		String domain = ProxyTools.getInstance().getCookieDomain(
				holder.getApp().getCookieConfig(), request);
		if (domain != null) {
			sessionCookie.setDomain(domain);
		}
		sessionCookie.setPath("/");
		sessionCookie.setSecure(false);
		sessionCookie.setMaxAge(-1);
		//response.addCookie(sessionCookie);
		
		if ((holder.getApp() == null || holder.getApp().getCookieConfig() == null || holder.getApp().getCookieConfig() == null || holder.getApp().getCookieConfig().isCookiesEnabled() == null)  || holder.getApp().getCookieConfig().isCookiesEnabled()) {
			ProxyResponse.addCookieToResponse(holder, sessionCookie, (HttpServletResponse) ((ProxyResponse) response).getResponse());
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.tremolosecurity.proxy.SessionManager#clearSession(com.tremolosecurity
	 * .config.util.UrlHolder, jakarta.servlet.http.HttpSession,
	 * jakarta.servlet.http.HttpServletRequest,
	 * jakarta.servlet.http.HttpServletResponse)
	 */
	@Override
	public void clearSession(UrlHolder holder, HttpSession sharedSession,
			HttpServletRequest request, HttpServletResponse response) {
		Cookie sessionCookie;
		sessionCookie = new Cookie(holder.getApp().getCookieConfig()
				.getSessionCookieName(), "LOGGED_OUT");
		String domain = ProxyTools.getInstance().getCookieDomain(
				holder.getApp().getCookieConfig(), request);
		if (domain != null) {
			sessionCookie.setDomain(domain);
		}
		sessionCookie.setPath("/");
		sessionCookie.setSecure(false);
		sessionCookie.setMaxAge(0);
		response.addCookie(sessionCookie);
		sharedSession.invalidate();

	}

	@Override
	public void resetSessionChecker(ConfigManager cfg) {
		this.cfg = cfg;
		SessionTimeoutChecker checker = new SessionTimeoutChecker(this.cfg,this);
		checker.start();
	}



	@Override
	public ConcurrentHashMap<String, TremoloHttpSession> getSessions() {
		return this.sessions;
	}



	@Override
	public void stopSessionChecker() {
		this.checker.stopChecker();
		
	}

}

class SessionByUserChecker extends Thread {
	private final ConcurrentHashMap<String, ConcurrentHashMap<String, TremoloHttpSession>> sessionsByUser;
	boolean stillRun;
	SessionManager sessionMgr;
	ConfigManager cfg;

	public SessionByUserChecker(ConfigManager cfg,SessionManager sessionManager,ConcurrentHashMap<String, ConcurrentHashMap<String, TremoloHttpSession>> sessionsByUser) {
		this.sessionMgr = sessionManager;
		this.cfg = cfg;
		this.stillRun = true;
		this.sessionsByUser = sessionsByUser;
		Runtime.getRuntime().addShutdownHook(new Thread() {

			@Override
			public void run() {
				stillRun = false;
			}
		});
	}


	public void stopChecker() {
		this.stillRun = false;
		this.interrupt();
	}

	@Override
	public void run() {
		while (stillRun) {
			try {

				for (String userDN : this.sessionsByUser.keySet()) {
					ConcurrentHashMap<String, TremoloHttpSession> sessions = this.sessionsByUser.get(userDN);
					synchronized (this.sessionsByUser) {
						if (sessions.isEmpty()) {
							this.sessionsByUser.remove(userDN);
						} else {
							List<String> sessionsToRemove = new ArrayList<String>();
							for (String sessionID : sessions.keySet()) {
								TremoloHttpSession session = sessions.get(sessionID);
								if (! sessions.containsKey(session.getId())) {
									sessionsToRemove.add(sessionID);
								}
							}

							sessionsToRemove.forEach(sessionID -> {sessions.remove(sessionID);});
							if (sessions.isEmpty()) {
								this.sessionsByUser.remove(userDN);
							}
						}
					}
				}

				try {
					Thread.sleep(60000);
				} catch (InterruptedException e) {

				}
			} catch (Throwable t) {
				SessionManagerImpl.logger.warn(
						"Exception while processing expired sessions", t);

				try {
					Thread.sleep(60000);
				} catch (InterruptedException e) {

				}
			}
		}
	}
}

class SessionTimeoutChecker extends Thread {

	boolean stillRun;
	SessionManager sessionMgr;
	ConfigManager cfg;

	public SessionTimeoutChecker(ConfigManager cfg,SessionManager sessionManager) {
		this.sessionMgr = sessionManager;
		this.cfg = cfg;
		this.stillRun = true;
		Runtime.getRuntime().addShutdownHook(new Thread() {

			@Override
			public void run() {
				stillRun = false;
			}
		});
	}

	
	public void stopChecker() {
		this.stillRun = false;
		this.interrupt();
	}
	
	@Override
	public void run() {
		while (stillRun) {

			try {

				ArrayList<String> toremove = new ArrayList<String>();

				
				Set<String> keys = new HashSet<String>();
				
				synchronized (this.sessionMgr.getSessions()) {
					keys.addAll(this.sessionMgr.getSessions().keySet());
				}
				
				for (String key : keys) {
					TremoloHttpSession session = this.sessionMgr.getSessions().get(key);
					
					if (session == null) {
						continue;
					}
					
					
					
					ApplicationType app = cfg.getApp(session.getAppName());

					if (SessionManagerImpl.logger.isDebugEnabled()) {
						SessionManagerImpl.logger.debug(String.format("Application %s", app.getName()));
					}
					
					if (session.isOpen()) {

						SessionManagerImpl.logger.debug("Session open");

						if (cfg.getCfg().getApplications()
								.getOpenSessionTimeout() > 0) {
							SessionManagerImpl.logger.debug("session timeout is more then 0");
							
							ExternalSessionExpires extSession = (ExternalSessionExpires) session.getAttribute(SessionManagerImpl.TREMOLO_EXTERNAL_SESSION);
							
							if (extSession != null) {
								SessionManagerImpl.logger.debug("has an external session");
								if (extSession.isExpired()) {
									session.invalidate();
									toremove.add(key);
								}
							} else {
								DateTime lastAccessed = (DateTime) session
										.getAttribute(SessionManagerImpl.TREMOLO_SESSION_LAST_ACCESSED);

								if (lastAccessed == null) {
									lastAccessed = new DateTime(session.getCreationTime());
								}

								DateTime now = new DateTime();
								if (now.minusSeconds(
										cfg.getCfg().getApplications()
												.getOpenSessionTimeout()).isAfter(
										lastAccessed)) {
									session.invalidate();
									toremove.add(key);
								}
							}
							
							
							
						}
					} else {
						if (app == null) {
							StringBuffer b = new StringBuffer();
							b.append("Session ").append(session.getId())
									.append(" application ")
									.append(session.getAppName())
									.append(" does not exist, invalidating");
							SessionManagerImpl.logger.warn(b.toString());
							toremove.add(key);
							session.invalidate();
						} else {
							if (app.getCookieConfig().getTimeout() > 0) {
								
								ExternalSessionExpires extSession = (ExternalSessionExpires) session.getAttribute(SessionManagerImpl.TREMOLO_EXTERNAL_SESSION);
								
								if (extSession != null) {
									DateTime lastAccessed = (DateTime) session
											.getAttribute(SessionManagerImpl.TREMOLO_SESSION_LAST_ACCESSED);
									DateTime now = new DateTime();

									if (lastAccessed != null) {
										if (extSession.isExpired(app.getCookieConfig().getTimeout(),lastAccessed.getMillis())) {
											session.invalidate();
											toremove.add(key);
										}
									} else {
										if (extSession.isExpired()) {
											session.invalidate();
											toremove.add(key);

										}
									}


								} else {
									DateTime lastAccessed = (DateTime) session
											.getAttribute(SessionManagerImpl.TREMOLO_SESSION_LAST_ACCESSED);

									if (lastAccessed == null) {
										lastAccessed = new DateTime(session.getCreationTime());
									}

									DateTime now = new DateTime();
									if (now.minusSeconds(
											app.getCookieConfig().getTimeout())
											.isAfter(lastAccessed)) {
										session.invalidate();
										toremove.add(key);
									}
								}
								
							}
						}
					}

				}

				synchronized (this.sessionMgr.getSessions()) {
					StringBuffer b = new StringBuffer();
					b.append("Clearing ").append(toremove.size()).append(" sessions");
					SessionManagerImpl.logger.warn(b.toString());
					for (String key : toremove) {
						this.sessionMgr.getSessions().remove(key);
					}
				}

				try {
					Thread.sleep(60000);
				} catch (InterruptedException e) {

				}
			} catch (Throwable t) {
				SessionManagerImpl.logger.warn(
						"Exception while processing expired sessions", t);
				
				try {
					Thread.sleep(60000);
				} catch (InterruptedException e) {

				}
			}
		}

	}

}

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
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.GZIPOutputStream;

import javax.crypto.Cipher;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.Logger;

import org.joda.time.DateTime;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.ApplicationType;
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



	private ConfigManager cfg;




	
	

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




		this.cfg = cfg;



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
		if (sessionCookie.getDomain() != null && sessionCookie.getDomain().startsWith(".")) {
			sessionCookie.setDomain(sessionCookie.getDomain().substring(1));
		}
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

	@Override
	public TremoloHttpSession getSessionById(String sessionId) {
		return this.sessions.get(sessionId);
	}

	@Override
	public void putSession(String sessionId, TremoloHttpSession session) {
		this.sessions.put(sessionId, session);
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

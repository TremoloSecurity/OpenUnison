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


package com.tremolosecurity.proxy.auth;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.Queue;

import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import com.tremolosecurity.proxy.TremoloHttpSession;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.logging.log4j.Logger;
import org.hibernate.query.Query;
import org.hibernate.SessionFactory;
import org.hibernate.boot.MetadataSources;
import org.hibernate.boot.cfgxml.spi.LoadedConfig;
import org.hibernate.boot.jaxb.cfg.spi.JaxbCfgHibernateConfiguration;
import org.hibernate.boot.jaxb.cfg.spi.JaxbCfgMappingReferenceType;
import org.hibernate.boot.jaxb.cfg.spi.JaxbCfgHibernateConfiguration.JaxbCfgSessionFactory;
import org.hibernate.boot.registry.StandardServiceRegistry;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.Configuration;
import org.joda.time.DateTime;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.provisioning.util.GenPasswd;
import com.tremolosecurity.proxy.auth.passwordreset.PasswordResetRequest;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.auth.util.AuthUtil;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.StopableThread;



public class PasswordReset implements AuthMechanism {
	
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(PasswordReset.class.getName());
	
	ConfigManager cfgMgr;
	
	private SessionFactory sessionFactory;
	
	int minValidKey;
	String passwordResetURL;
	
	String smtpServer;
	int smtpPort;
	String smtpUser;
	String smtpPassword;
	String smtpSubject;
	String smtpMsg;
	String smtpFrom;
	String socksHost;
	int socksPort;
	boolean useSocks;
	String smtpLocalhost;



	private boolean smtpTLS;
	
	boolean enabled;
	
	Queue<SmtpMessage> msgQ;

	String lookupAttributeName;


	
	private void initializeHibernate(String driver, String user,String password,String url,String dialect,int maxCons,int maxIdleCons,String validationQuery,String mappingFile,String createSchema) {
		StandardServiceRegistryBuilder builder = new StandardServiceRegistryBuilder();
		
		
		Configuration config = new Configuration();
		config.setProperty("hibernate.connection.driver_class", driver);
		config.setProperty("hibernate.connection.password", password);
		config.setProperty("hibernate.connection.url", url);
		config.setProperty("hibernate.connection.username", user);
		config.setProperty("hibernate.dialect", dialect);
		
		if (createSchema == null || createSchema.equalsIgnoreCase("true")) {
			config.setProperty("hibernate.hbm2ddl.auto", "update");
		}
		
		config.setProperty("show_sql", "true");
		config.setProperty("hibernate.current_session_context_class", "thread");
		
		config.setProperty("hibernate.c3p0.max_size", Integer.toString(maxCons));
		config.setProperty("hibernate.c3p0.maxIdleTimeExcessConnections", Integer.toString(maxIdleCons));
		
		if (validationQuery != null && ! validationQuery.isEmpty()) {
			config.setProperty("hibernate.c3p0.testConnectionOnCheckout", "true");
		}
		
		
		
		config.setProperty("hibernate.c3p0.autoCommitOnClose", "true");
		
		

		
		//config.setProperty("hibernate.c3p0.debugUnreturnedConnectionStackTraces", "true");
		//config.setProperty("hibernate.c3p0.unreturnedConnectionTimeout", "30");
		
		
		
		if (validationQuery == null) {
			validationQuery = "SELECT 1";
		}
		config.setProperty("hibernate.c3p0.preferredTestQuery", validationQuery);
		
		LoadedConfig lc = null;

		
		if (mappingFile == null || mappingFile.trim().isEmpty()) {
		
			JaxbCfgHibernateConfiguration jaxbCfg = new JaxbCfgHibernateConfiguration();
			jaxbCfg.setSessionFactory(new JaxbCfgSessionFactory());
			
			JaxbCfgMappingReferenceType mrt = new JaxbCfgMappingReferenceType();
			mrt.setClazz(PasswordResetRequest.class.getName());
			jaxbCfg.getSessionFactory().getMapping().add(mrt);
			
			lc = LoadedConfig.consume(jaxbCfg);
		} else {
			lc = LoadedConfig.baseline(); 
		}
		
		
		StandardServiceRegistry registry = builder.configure(lc).applySettings(config.getProperties()).build();
		try {
			sessionFactory = null; 
			
			if (mappingFile == null || mappingFile.trim().isEmpty()) {
				sessionFactory = new MetadataSources( registry ).buildMetadata().buildSessionFactory();
			} else {
				sessionFactory = new MetadataSources( registry ).addResource(mappingFile).buildMetadata().buildSessionFactory();
			}
			
			
			
			this.cfgMgr.addThread(new StopableThread() {

				@Override
				public void run() {
					// TODO Auto-generated method stub
					
				}

				@Override
				public void stop() {
					logger.info("Stopping hibernate");
					sessionFactory.close();
					
				}
				
			});
		}
		catch (Exception e) {
			e.printStackTrace();
			// The registry would be destroyed by the SessionFactory, but we had trouble building the SessionFactory
			// so destroy it manually.
			StandardServiceRegistryBuilder.destroy( registry );
		}
	}
	
	
	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		
		if (! this.enabled) {
			throw new ServletException("Operation Not Supported");
		}
		
		
		
		
		HttpSession session = ((HttpServletRequest) request).getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		if (holder == null) {
			String finalURL = this.getFinalURL(request, response);
			try {
				holder = cfgMgr.findURL(finalURL);
				request.setAttribute(ProxyConstants.AUTOIDM_CFG, holder);
				
			} catch (Exception e) {
				throw new ServletException("Could not run authentication",e);
			}
		}
		
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		if (request.getParameter("email") != null) {
			
			AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
			String splashRedirect = authParams.get("splashRedirect").getValues().get(0);
			String noUserSplash = authParams.get("noUserSplash").getValues().get(0);

			generateResetKey(request, response, splashRedirect,noUserSplash,as,act,this.lookupAttributeName);
			return;
		} else if (request.getParameter("key") == null) {
			String emailCollectionRedir = authParams.get("emailCollectionRedir").getValues().get(0);
			response.sendRedirect(emailCollectionRedir);
			return;
		} else {
			String key = request.getParameter("key");
			org.hibernate.Session con = null;
			try {
				con = this.sessionFactory.openSession();
			
			
			String urlChain = holder.getUrl().getAuthChain();
			
			AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
			
			
			if (as == null || ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthSteps().size() == 0) {
				//like saml2 idp initiated, this is a special use case
				
				ArrayList<AuthStep> auths = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthSteps();
				
				
				int id = 0;
				for (AuthMechType amt : act.getAuthMech()) {
					AuthStep asx = new AuthStep();
					asx.setId(id);
					asx.setExecuted(false);
					asx.setRequired(amt.getRequired().equals("required"));
					asx.setSuccess(false);
					auths.add(asx);
					id++;
				}
				
				as = auths.get(0);
				
			}
			
			
			
			AuthMechType amt = act.getAuthMech().get(as.getId());
			
			
				finishLogin(request, response, session, act, as.getId(), amt,
						minValidKey, key, con,reqHolder,as);
			} catch (SQLException e) {
				throw new ServletException("Could not complete login",e);
			} finally {
				
					if (con != null) {
						con.close();
					}
				
				
			}
		}
			
		
		

	}

	private void finishLogin(HttpServletRequest request,
			HttpServletResponse response, HttpSession session,
			AuthChainType act, int step, AuthMechType amt, int minValidKey,
			String key, org.hibernate.Session con,RequestHolder reqHolder,AuthStep as) throws SQLException, ServletException,
			IOException {
		
		if (! this.enabled) {
			throw new ServletException("Operation Not Supported");
		}

		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);

		int maxChecks = 0;

		if (authParams.containsKey("maxChecks")) {
			maxChecks = Integer.parseInt(authParams.get("maxChecks").getValues().get(0));
		} else {
			maxChecks = 1;
		}

		DateTime now = new DateTime().minusMinutes(minValidKey);
		
		
		Query query = con.createQuery("FROM PasswordResetRequest r WHERE r.resetKey = :resetkey AND r.ts > :ts AND r.numRequests < :numRequests");
		query.setParameter("resetkey", key);
		query.setParameter("ts", new Timestamp(now.getMillis()));
		query.setParameter("numRequests", maxChecks);
		
		List<PasswordResetRequest> resetRequests = query.list();
		
		
		
		
		if (resetRequests == null || resetRequests.isEmpty()) {
			
			
		
			as.setSuccess(false);
			
		} else {
			PasswordResetRequest req = resetRequests.get(0);
			String email = req.getEmail();
			
			
			
			
			try {
				LDAPSearchResults res = this.cfgMgr.getMyVD().search(AuthUtil.getChainRoot(cfgMgr,act), 2, equal(this.lookupAttributeName,email).toString(), new ArrayList<String>());
				
				if (res.hasMore()) {
					
					LDAPEntry entry = res.next();
					while (res.hasMore()) res.next();
					
					Iterator<LDAPAttribute> it = entry.getAttributeSet().iterator();
					
					AuthInfo authInfo = new AuthInfo(entry.getDN(),(String) session.getAttribute(ProxyConstants.AUTH_MECH_NAME),act.getName(),act.getLevel(),(TremoloHttpSession) session);
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
					
					as.setSuccess(false);
				}
				
			} catch (LDAPException e) {
				logger.error("Could not authenticate user",e);
				
				as.setSuccess(false);
			}
			
			con.beginTransaction();
			req.setNumRequests(req.getNumRequests() + 1);
			if (req.getNumRequests() < maxChecks) {
				con.save(req);
			} else {
				con.delete(req);
			}
			con.getTransaction().commit();
			
			
		}
		
		String redirectToURL = null;
		
		if (as.isSuccess()) {
			reqHolder.setURL(this.getFinalURL(request, response));
		} else {
			request.getParameter("target");
			if (redirectToURL != null && ! redirectToURL.isEmpty()) {
				reqHolder.setURL(redirectToURL);
			}
		}
		
		
		
		
		this.cfgMgr.getAuthManager().nextAuth(request, response,session,false);
	}

	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		
		
		HttpSession session = ((HttpServletRequest) request).getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
		
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);

		
		
		
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());

		
		
		
		AuthMechType amt = act.getAuthMech().get(as.getId());

		String splashRedirect = authParams.get("splashRedirect").getValues().get(0);
		
		String noUserSplash = authParams.get("noUserSplash").getValues().get(0);


		
		if (request.getParameter("email") != null) {
		
			generateResetKey(request, response, splashRedirect,noUserSplash,as,act, this.lookupAttributeName);
		
			return;
		} else if (request.getParameter("key") != null) {
		
			String key = request.getParameter("key");
		
			org.hibernate.Session con = null;
			try {
				con = this.sessionFactory.openSession();
		
			
			
			
				
		
				finishLogin(request, response, session, act, as.getId(), amt,
						minValidKey, key, con,reqHolder,as);
		
			} catch (SQLException e) {
		
				throw new ServletException("Could not complete login",e);
			} finally {
				
					if (con != null) {
						con.close();
					}
				
				
			}
			
		}
		
		

	}

	private void generateResetKey(HttpServletRequest request,
								  HttpServletResponse response, String splashRedirect, String noUserSplash, AuthStep as, AuthChainType act, String lookupAttribute)
			throws ServletException, IOException {
		org.hibernate.Session con = null;
		try {
			con = this.sessionFactory.openSession();
		
		
		String lookupAttributeValue = request.getParameter("email");
		
		
		ArrayList<String> attrs = new ArrayList<String>();
		attrs.add("mail");
		
		
		String emailAddress = null;
		
			
			LDAPSearchResults res = this.cfgMgr.getMyVD().search(AuthUtil.getChainRoot(cfgMgr,act), 2, equal(lookupAttribute,lookupAttributeValue).toString(), attrs);
			
			if (! res.hasMore()) {
				response.sendRedirect(noUserSplash);
				
				return;
			} else {

				LDAPEntry entry = res.next();
				if (entry.getAttribute("mail") != null) {
					emailAddress = entry.getAttribute("mail").getStringValue();
				}
				while (res.hasMore()) res.next();
			}
			
			if (emailAddress == null) {
				response.sendRedirect(noUserSplash);

				return;
			}
			
			sendPasswordReset(con,lookupAttributeValue, emailAddress);
			
			response.sendRedirect(splashRedirect);
			return;
			
		} catch (Exception e) {
			throw new ServletException("Could not set password key",e);
		} finally {
			if (con != null) {
				
					con.close();
				
			}
		}
	}

	
	public void sendPasswordReset(String uid,String emailAddress) throws Exception {
		org.hibernate.Session con = null;
		try {
			con = this.sessionFactory.openSession();
			this.sendPasswordReset(con, uid,emailAddress);
		
		} finally {
			if (con != null) {
				con.close();
			}
		}
	}
	
	private void sendPasswordReset(org.hibernate.Session con, String uid,String emailAddress)
			throws SQLException, Exception {
		GenPasswd gp = new GenPasswd(30);
		String key = gp.getPassword();
		DateTime now = new DateTime();
		
		
		PasswordResetRequest req = new PasswordResetRequest();
		req.setEmail(uid);
		req.setResetKey(key);
		req.setTs(new Timestamp(now.getMillis()));
		
		con.beginTransaction();
		con.save(req);
		con.getTransaction().commit();
		
		this.sendEmail(emailAddress, key);
	}

	private void sendEmail(String email,String key) throws Exception {
		String msgTxt = this.smtpMsg.replaceAll("[$][{]key[}]", URLEncoder.encode(key,"UTF-8"));
		
		SmtpMessage msg = new SmtpMessage();
		msg.to = email;
		msg.from = this.smtpFrom;
		msg.subject = this.smtpSubject;
		msg.msg = msgTxt;
		
		synchronized (msgQ) {
			msgQ.add(msg);
		}
		
		
		
		
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
		
		this.enabled = Boolean.parseBoolean(init.get("enabled").getValues().get(0));
		
		if (this.enabled) {
			
			this.msgQ = new ArrayDeque<SmtpMessage>();
			
			StopableThread st = new SendMessageThread(this);
			Thread t = new Thread(st);
			t.start();
			this.cfgMgr.addThread(st);
		
			String driver = init.get("driver").getValues().get(0);
			logger.info("Driver : '" + driver + "'");
			
			String url = init.get("url").getValues().get(0);;
			logger.info("URL : " + url);
			String user = init.get("user").getValues().get(0);;
			logger.info("User : " + user);
			String pwd = init.get("password").getValues().get(0);;
			logger.info("Password : **********");
			
			
			int maxCons = Integer.parseInt(init.get("maxCons").getValues().get(0));
			logger.info("Max Cons : " + maxCons);
			int maxIdleCons = Integer.parseInt(init.get("maxIdleCons").getValues().get(0));
			logger.info("maxIdleCons : " + maxIdleCons);
			
			String dialect = init.get("dialect").getValues().get(0);
			logger.info("Hibernate Dialect : '" + dialect + "'");
			
			String validationQuery = init.get("validationQuery").getValues().get(0);
			logger.info("Validation Query : '" + validationQuery + "'");
	        
			String hibernateConfig = init.get("hibernateConfig") != null ? init.get("hibernateConfig").getValues().get(0) : null;
			logger.info("HIbernate mapping file : '" + hibernateConfig + "'");
			
			String hibernateCreateSchema = init.get("hibernateCreateSchema") != null ? init.get("hibernateCreateSchema").getValues().get(0) : null;
			logger.info("Can create schema : '" + hibernateCreateSchema + "'");
			
			
	        this.initializeHibernate(driver, user, pwd, url, dialect, maxCons, maxIdleCons, validationQuery,hibernateConfig,hibernateCreateSchema);
	        
	        this.passwordResetURL = init.get("passwordResetURI").getValues().get(0);
	        this.minValidKey = Integer.parseInt(init.get("minValidKey").getValues().get(0));
	        
	        StopableThread tokenClean = new TokenCleanup(this.sessionFactory,this.minValidKey);
			t = new Thread(tokenClean);
			
			this.cfgMgr.addThread(tokenClean);
			t.start();
	
			this.smtpServer = init.get("smtpHost").getValues().get(0);
			logger.info("SMTP Server : '" + this.smtpServer + "'");
			this.smtpPort = Integer.parseInt(init.get("smtpPort").getValues().get(0));
			logger.info("SMTP Port : '" + this.smtpPort + "'");
			this.smtpUser = init.get("smtpUser").getValues().get(0);
			logger.info("SMTP User : '" + this.smtpUser + "'");
			this.smtpPassword = init.get("smtpPassword").getValues().get(0);
			logger.info("SMTP Password : '************'");
			this.smtpSubject = init.get("smtpSubject").getValues().get(0);
			logger.info("SMTP Subject : '" + this.smtpSubject + "'");
			this.smtpMsg = init.get("smtpMsg").getValues().get(0);
			
			this.smtpFrom = init.get("smtpFrom").getValues().get(0);
			logger.info("SMTP From : '" + this.smtpFrom + "'");
			this.smtpTLS = Boolean.parseBoolean(init.get("smtpTLS").getValues().get(0));
			logger.info("SMTP TLS : '" + this.smtpTLS + "'");
			if (init.get("smtpSocksHost") != null && init.get("smtpSocksHost").getValues().size() > 0 && ! init.get("smtpSocksHost").getValues().get(0).isEmpty()) {
				logger.info("SMTP SOCKS : 'true'");
				this.useSocks = true;
				this.socksHost = init.get("smtpSocksHost").getValues().get(0);
				logger.info("SMTP SOCKS Host : '" + this.socksHost + "'");
				this.socksPort = Integer.parseInt(init.get("smtpSocksPort").getValues().get(0));
				logger.info("SMTP SOCKS Port : '" + this.socksPort + "'");
			} else {
				logger.info("SMTP SOCKS : 'false'");
				this.useSocks = false;
			}
			
			if (init.get("smtpLocalhost") != null && init.get("smtpLocalhost").getValues().size() > 0) {
				this.smtpLocalhost = init.get("smtpLocalhost").getValues().get(0);
				logger.info("SMTP Localhost : '" + this.smtpLocalhost + "'");
			} else {
				this.smtpLocalhost = null;	
			}

			if (init.get("uidAttributeName") != null) {
				this.lookupAttributeName = init.get("uidAttributeName").getValues().get(0);
			} else {
				this.lookupAttributeName = "mail";
			}
		
		}
		
	}

	@Override
	public String getFinalURL(HttpServletRequest request,
			HttpServletResponse response) {
		URL url;
		try {
			url = new URL(request.getRequestURL().toString());
		} catch (MalformedURLException e) {
			logger.error("Could not parse url",e);
			return "";
		}
		StringBuffer nurl = new StringBuffer();
		nurl.append(url.getProtocol()).append("://").append(url.getHost());
		
		if (url.getPort() > 0) {
			nurl.append(":").append(url.getPort());
		}
		
		nurl.append(this.passwordResetURL);
		
		return nurl.toString();
	}

	public String getSmtpServer() {
		return smtpServer;
	}

	public int getSmtpPort() {
		return smtpPort;
	}

	public String getSmtpUser() {
		return smtpUser;
	}

	public String getSmtpPassword() {
		return smtpPassword;
	}

	public String getSmtpSubject() {
		return smtpSubject;
	}

	public String getSmtpFrom() {
		return smtpFrom;
	}

	public String getSocksHost() {
		return socksHost;
	}

	public int getSocksPort() {
		return socksPort;
	}

	public boolean isUseSocks() {
		return useSocks;
	}

	public String getSmtpLocalhost() {
		return smtpLocalhost;
	}

	public boolean isSmtpTLS() {
		return smtpTLS;
	}
	
	public Queue<SmtpMessage> getMsgQ() {
		return this.msgQ;
	}

	public String getLookupAttributeName() {
		return lookupAttributeName;
	}

	public void clearUserRequests(String id) {
		org.hibernate.Session con = null;
			try {
				con = this.sessionFactory.openSession();
				
				con.beginTransaction();
				Query delq = con.createQuery("DELETE FROM PasswordResetRequest r WHERE r.email = :email");
				delq.setParameter("email", id);
				delq.executeUpdate();
				con.getTransaction().commit();
				
			
			} finally {
				if (con != null) {
					
						con.close();
					
				}
			}
	}
}

class TokenCleanup implements StopableThread {
	boolean running = true;
	int minutes;
	private SessionFactory sessionFactory;
	
	
	public TokenCleanup(SessionFactory sessionFactory,int minutes) {
		this.sessionFactory = sessionFactory;
		this.minutes = minutes;
	}
	
	@Override
	public void run() {
		while (this.running) {
			PasswordReset.logger.info("Clearing Expired Tokens");
			
			org.hibernate.Session con = null;
			try {
				con = this.sessionFactory.openSession();
				DateTime expires = new DateTime().minusMinutes(this.minutes);
				con.beginTransaction();
				Query delq = con.createQuery("DELETE FROM PasswordResetRequest r WHERE r.ts <= :ts");
				delq.setParameter("ts", new Timestamp(expires.getMillis()));
				delq.executeUpdate();
				con.getTransaction().commit();
				
			
			} finally {
				if (con != null) {
					
						con.close();
					
				}
			}
			
			
			try {
				//TODO
				//I hate threads
				synchronized (this) {
					this.wait(30000);
				}
				
			} catch (InterruptedException e) {
				this.running = false;
			}
		}
		
	}

	@Override
	public void stop() {
		this.running = false;
		
	}
	
}

class SmtpAuthenticator extends Authenticator {
	String username;
	String password;
	
	public SmtpAuthenticator(String username,String password) {
		this.username = username;
		this.password = password;
	}
	
	@Override
	protected PasswordAuthentication getPasswordAuthentication() {
		
		return new PasswordAuthentication(username,password);
	}
	
	
}


class SmtpMessage {
	String subject;
	String to;
	String from;
	String msg;
	
}

class SendMessageThread implements StopableThread {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(SendMessageThread.class.getName());
	
	
	
	boolean running = true;

	



	private PasswordReset reset;
	
	public SendMessageThread(PasswordReset reset) {
		this.reset = reset;
	}
	
	@Override
	public void run() {
		while (running) {
			
			
			
			
			
			boolean goToSleep = false;
			
			SmtpMessage msg = null;
			synchronized (reset.getMsgQ()) {
				
				msg = reset.getMsgQ().poll();
				goToSleep = (msg == null);
			}
			
			if (goToSleep) {
				
				try {
					Thread.sleep(30000);
				} catch (InterruptedException e) {
					logger.warn("Error sleeping",e);
				}
			} else {
				
				
					
					try {
						
						sendEmail(msg);
						
					} catch (Throwable t) {
						logger.warn("Error sending email",t);
					}
				
				
				
			}
		}
		
	}
	
	private void sendEmail(SmtpMessage msg) throws MessagingException {
Properties props = new Properties();
		boolean doAuth = false;
		props.setProperty("mail.smtp.host", this.reset.getSmtpServer());
		props.setProperty("mail.smtp.port", Integer.toString(reset.getSmtpPort()));
	//props.setProperty("mail.smtp.user", reset.getSmtpUser());
		//props.setProperty("mail.smtp.auth", "true");
		props.setProperty("mail.transport.protocol", "smtp");
		props.setProperty("mail.smtp.starttls.enable", Boolean.toString(reset.isSmtpTLS()));
		//props.setProperty("mail.debug", "true");
		//props.setProperty("mail.socket.debug", "true");
		

		if (reset.getSmtpUser() != null && ! reset.getSmtpUser().isEmpty()) {
			logger.debug("SMTP user found '" + reset.getSmtpUser() + "', enabling authentication");
			props.setProperty("mail.smtp.user", reset.getSmtpUser());
			props.setProperty("mail.smtp.auth", "true");
			doAuth = true;
		} else {
			logger.debug("No SMTP user, disabling authentication");
			doAuth = false;
			props.setProperty("mail.smtp.auth", "false");
		}

		if (logger.isDebugEnabled()) {
			props.setProperty("mail.debug", "true");
			props.setProperty("mail.socket.debug", "true");
		}

		if (reset.getSmtpLocalhost() != null && ! reset.getSmtpLocalhost().isEmpty()) {
			props.setProperty("mail.smtp.localhost", reset.getSmtpLocalhost());
		}
		
		
		if (reset.isUseSocks()) {
			
			
			props.setProperty("mail.smtp.socks.host", reset.getSocksHost());
			
			props.setProperty("mail.smtp.socks.port", Integer.toString(reset.getSocksPort()));
			props.setProperty("mail.smtps.socks.host", reset.getSocksHost());
			
			props.setProperty("mail.smtps.socks.port", Integer.toString(reset.getSocksPort()));
		}
		
		Session session = null;
		if (doAuth) {
			logger.debug("Creating authenticated session");
			session = Session.getInstance(props, 
					new Authenticator(){
				protected PasswordAuthentication getPasswordAuthentication() {
				   return new PasswordAuthentication(reset.getSmtpUser(), reset.getSmtpPassword());
				}});
		} else {
			logger.debug("Creating unauthenticated session");
			session = Session.getInstance(props);
		}
		
		
		
		if (logger.isDebugEnabled()) {
			session.setDebugOut(System.out);
			session.setDebug(true);
		}
		
		
		//session.setDebug(true);
		//Transport tr = session.getTransport("smtp");
		//tr.connect();
		
		//tr.connect(this.smtpHost,this.smtpPort, this.smtpUser, this.smtpPassword);

		Message msgToSend = new MimeMessage(session);
		msgToSend.setFrom(new InternetAddress(msg.from));
		msgToSend.addRecipient( Message.RecipientType.TO, new InternetAddress(msg.to));
		msgToSend.setSubject(msg.subject);
		msgToSend.setText(msg.msg);
		
		msgToSend.saveChanges();
		Transport.send(msgToSend);
		//tr.sendMessage(msg, msg.getAllRecipients());
		//tr.close();
	}

	@Override
	public void stop() {
		this.running = false;
		
	}


	
}
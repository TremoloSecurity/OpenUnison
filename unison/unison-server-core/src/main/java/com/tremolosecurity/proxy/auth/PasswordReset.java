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
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
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
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.sql.DataSource;

import org.apache.commons.dbcp.cpdsadapter.DriverAdapterCPDS;
import org.apache.commons.dbcp.datasources.SharedPoolDataSource;
import org.apache.log4j.Logger;
import org.joda.time.DateTime;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.provisioning.core.ProvisioningEngineImpl;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningTargetImpl;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.util.GenPasswd;
import com.tremolosecurity.proxy.ProxyRequest;
import com.tremolosecurity.proxy.ProxyUtil;
import com.tremolosecurity.proxy.auth.RequestHolder.HTTPMethod;
import com.tremolosecurity.proxy.auth.ssl.CRLManager;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.auth.util.AuthUtil;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.StopableThread;



public class PasswordReset implements AuthMechanism {
	
	
	static Logger logger = Logger.getLogger(PasswordReset.class.getName());
	
	ConfigManager cfgMgr;
	
	DataSource ds;
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
			generateResetKey(request, response, splashRedirect,noUserSplash,as,act);
			return;
		} else if (request.getParameter("key") == null) {
			String emailCollectionRedir = authParams.get("emailCollectionRedir").getValues().get(0);
			response.sendRedirect(emailCollectionRedir);
			return;
		} else {
			String key = request.getParameter("key");
			Connection con = null;
			try {
				con = ds.getConnection();
			} catch (SQLException e) {
				throw new ServletException("Could not generate connection",e);
			}
			
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
			
			try {
				finishLogin(request, response, session, act, as.getId(), amt,
						minValidKey, key, con,reqHolder,as);
			} catch (SQLException e) {
				throw new ServletException("Could not complete login",e);
			} finally {
				try {
					if (con != null) {
						con.close();
					}
				} catch (SQLException e) {
					//do nothing
				}
				
			}
		}
			
		
		

	}

	private void finishLogin(HttpServletRequest request,
			HttpServletResponse response, HttpSession session,
			AuthChainType act, int step, AuthMechType amt, int minValidKey,
			String key, Connection con,RequestHolder reqHolder,AuthStep as) throws SQLException, ServletException,
			IOException {
		
		if (! this.enabled) {
			throw new ServletException("Operation Not Supported");
		}
		
		
		
		DateTime now = new DateTime().minusMinutes(minValidKey);
		
		
		PreparedStatement ps = con.prepareStatement("SELECT email FROM ResetRequests WHERE resetkey=? AND ts>?");
		ps.setString(1, key);
		
		ps.setTimestamp(2, new Timestamp(now.getMillis()));
		ResultSet rs = ps.executeQuery();
		
		if (! rs.next()) {
			
			rs.close();
			ps.close();
		
			as.setSuccess(false);
			
		} else {
			
			String email = rs.getString("email");
			
			
			
			
			try {
				LDAPSearchResults res = this.cfgMgr.getMyVD().search(AuthUtil.getChainRoot(cfgMgr,act), 2, equal("mail",email).toString(), new ArrayList<String>());
				
				if (res.hasMore()) {
					
					LDAPEntry entry = res.next();
					
					
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
					
					as.setSuccess(false);
				}
				
			} catch (LDAPException e) {
				logger.error("Could not authenticate user",e);
				
				as.setSuccess(false);
			}
			
			rs.close();
			ps.close();
			
			ps = con.prepareStatement("DELETE FROM ResetRequests WHERE resetkey=?");
			ps.setString(1, key);
			ps.executeUpdate();
			ps.close();
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
		
			generateResetKey(request, response, splashRedirect,noUserSplash,as,act);
		
			return;
		} else if (request.getParameter("key") != null) {
		
			String key = request.getParameter("key");
		
			Connection con = null;
		
			try {
				con = ds.getConnection();
		
			} catch (SQLException e) {
		
				throw new ServletException("Could not generate connection",e);
			}
			
			try {
				
		
				finishLogin(request, response, session, act, as.getId(), amt,
						minValidKey, key, con,reqHolder,as);
		
			} catch (SQLException e) {
		
				throw new ServletException("Could not complete login",e);
			} finally {
				try {
					if (con != null) {
						con.close();
					}
				} catch (SQLException e) {
					//do nothing
				}
				
			}
			
		}
		
		

	}

	private void generateResetKey(HttpServletRequest request,
			HttpServletResponse response, String splashRedirect, String noUserSplash,AuthStep as, AuthChainType act)
			throws ServletException, IOException {
		Connection con = null;
		try {
			con = ds.getConnection();
		} catch (SQLException e) {
			throw new ServletException("Could not generate connection",e);
		}
		
		
		String emailAddress = request.getParameter("email");
		
		
		ArrayList<String> attrs = new ArrayList<String>();
		attrs.add("1.1");
		
		
		
		try {
			
			LDAPSearchResults res = this.cfgMgr.getMyVD().search(AuthUtil.getChainRoot(cfgMgr,act), 2, equal("mail",emailAddress).toString(), attrs);
			
			if (! res.hasMore()) {
				response.sendRedirect(noUserSplash);
				
				return;
			} else {
				res.next();
				while (res.hasMore()) res.next();
			}
			
			
			
			sendPasswordReset(con, emailAddress);
			
			response.sendRedirect(splashRedirect);
			return;
			
		} catch (Exception e) {
			throw new ServletException("Could not set password key",e);
		} finally {
			if (con != null) {
				try {
					con.close();
				} catch (SQLException e) {
					//DO NOTHING
				}
			}
		}
	}

	
	public void sendPasswordReset(String emailAddress) throws Exception {
		Connection con = null;
		try {
			con = ds.getConnection();
			this.sendPasswordReset(con, emailAddress);
		} catch (SQLException e) {
			throw new ServletException("Could not generate connection",e);
		} finally {
			if (con != null) {
				con.close();
			}
		}
	}
	
	private void sendPasswordReset(Connection con, String emailAddress)
			throws SQLException, Exception {
		GenPasswd gp = new GenPasswd(30);
		String key = gp.getPassword();
		DateTime now = new DateTime();
		
		PreparedStatement ps = con.prepareStatement("INSERT INTO ResetRequests (email,resetkey,ts) VALUES (?,?,?)");
		ps.setString(1, emailAddress);
		ps.setString(2, key);
		ps.setTimestamp(3, new Timestamp(now.getMillis()));
		ps.executeUpdate();
		ps.close();
		
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
			
			DriverAdapterCPDS pool = new DriverAdapterCPDS();
			
			try {
				pool.setDriver(driver);
			} catch (ClassNotFoundException e) {
				logger.error("Could not load JDBC Driver",e);
				return;
			}
			pool.setUrl(url);
			pool.setUser(user);
			pool.setPassword(pwd);
			pool.setMaxActive(maxCons);
			pool.setMaxIdle(maxIdleCons);
			
			SharedPoolDataSource tds = new SharedPoolDataSource();
	        tds.setConnectionPoolDataSource(pool);
	        tds.setMaxActive(maxCons);
	        tds.setMaxWait(50);
	        
	        this.ds = tds;
	        
	        this.passwordResetURL = init.get("passwordResetURI").getValues().get(0);
	        this.minValidKey = Integer.parseInt(init.get("minValidKey").getValues().get(0));
	        
	        StopableThread tokenClean = new TokenCleanup(this.ds,this.minValidKey);
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
	
	

	
}

class TokenCleanup implements StopableThread {
	boolean running = true;
	int minutes;
	DataSource ds;
	
	public TokenCleanup(DataSource ds,int minutes) {
		this.ds = ds;
		this.minutes = minutes;
	}
	
	@Override
	public void run() {
		while (this.running) {
			PasswordReset.logger.info("Clearing Expired Tokens");
			
			Connection con = null;
			try {
				con = ds.getConnection();
				DateTime expires = new DateTime().minusMinutes(this.minutes);
				
				PreparedStatement ps = con.prepareStatement("DELETE FROM ResetRequests WHERE ts <= ?");
				ps.setTimestamp(1, new Timestamp(expires.getMillis()));
				ps.executeUpdate();
				ps.close();
				
			} catch (SQLException e) {
				PasswordReset.logger.error("Could not clear expired tokens",e);
			} finally {
				if (con != null) {
					try {
						con.close();
					} catch (SQLException e) {
						//do nothing
					}
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
	static Logger logger = Logger.getLogger(SendMessageThread.class.getName());
	
	
	
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
		
		props.setProperty("mail.smtp.host", this.reset.getSmtpServer());
		props.setProperty("mail.smtp.port", Integer.toString(reset.getSmtpPort()));
		props.setProperty("mail.smtp.user", reset.getSmtpUser());
		props.setProperty("mail.smtp.auth", "true");
		props.setProperty("mail.transport.protocol", "smtp");
		props.setProperty("mail.smtp.starttls.enable", Boolean.toString(reset.isSmtpTLS()));
		//props.setProperty("mail.debug", "true");
		//props.setProperty("mail.socket.debug", "true");
		
		if (reset.getSmtpLocalhost() != null && ! reset.getSmtpLocalhost().isEmpty()) {
			props.setProperty("mail.smtp.localhost", reset.getSmtpLocalhost());
		}
		
		
		if (reset.isUseSocks()) {
			
			
			props.setProperty("mail.smtp.socks.host", reset.getSocksHost());
			
			props.setProperty("mail.smtp.socks.port", Integer.toString(reset.getSocksPort()));
			props.setProperty("mail.smtps.socks.host", reset.getSocksHost());
			
			props.setProperty("mail.smtps.socks.port", Integer.toString(reset.getSocksPort()));
		}
		
		
		
		
		//Session session = Session.getInstance(props, new SmtpAuthenticator(this.smtpUser,this.smtpPassword));
		Session session = Session.getDefaultInstance(props, 
                new Authenticator(){
            protected PasswordAuthentication getPasswordAuthentication() {
               return new PasswordAuthentication(reset.getSmtpUser(), reset.getSmtpPassword());
            }});
		//Session session = Session.getInstance(props, null);
		session.setDebugOut(System.out);
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
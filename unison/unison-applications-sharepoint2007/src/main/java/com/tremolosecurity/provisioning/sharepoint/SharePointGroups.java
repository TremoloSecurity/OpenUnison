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


package com.tremolosecurity.provisioning.sharepoint;



import java.io.File;
import java.net.Authenticator;
import java.net.MalformedURLException;
import java.net.PasswordAuthentication;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.MessageContext;

import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;

import com.novell.ldap.util.Base64;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.sharepoint.ws.GetUserLoginFromEmailResponse;
import com.tremolosecurity.provisioning.sharepoint.ws.UserGroup;
import com.tremolosecurity.provisioning.sharepoint.ws.UserGroupSoap;
import com.tremolosecurity.provisioning.sharepoint.ws.UsersList;
import com.tremolosecurity.provisioning.sharepoint.ws.GetGroupCollectionFromUserResponse.GetGroupCollectionFromUserResult;
import com.tremolosecurity.provisioning.sharepoint.ws.GetGroupCollectionFromUserType.Groups.Group;
import com.tremolosecurity.saml.Attribute;




public class SharePointGroups implements UserStoreProvider {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(SharePointGroups.class.getName());

	
	private enum AuthType {
		UnisonLastMile,
		NTLM
	};
	
	ConfigManager cfg;
	
	String webServicesURL;
	String keyAlias;
	String administratorUPN;
	
	String headerName;
	int skew;

	AuthType authType;
	
	
	File wsdl;

	private URL defaultServiceURL;
	
	String name;

	private String upnAttribute = "userPrincipalName";
	
	private String touchURL;

	private String administratorPassword;
	
	public final static QName SERVICE = new QName("http://schemas.microsoft.com/sharepoint/soap/directory/", "UserGroup");
	
	private Map<String,URL> uris;
	boolean multiSite;
	
	@Override
	public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr,
			String name) throws ProvisioningException {
		this.name = name;
		this.cfg = cfgMgr;
		
		Attribute attr = cfg.get("webServicesURL");
		if (attr == null) {
			throw new ProvisioningException("No web services url");
		}
		this.webServicesURL = attr.getValues().get(0);
		logger.info("Web Services URL : '" + this.webServicesURL + "'");
		
		try {
			this.defaultServiceURL = new URL(this.webServicesURL);
		} catch (MalformedURLException e1) {
			throw new ProvisioningException("Can not parse web services url",e1);
		}
		
		attr = cfg.get("authMode");
		if (attr != null) {
			if (attr.getValues().get(0).equalsIgnoreCase("ntlm")) {
				authType = AuthType.NTLM;
			} else {
				authType = AuthType.UnisonLastMile;
			}
		} else {
			authType = AuthType.UnisonLastMile;
		}
		
		if (authType == AuthType.UnisonLastMile) {
			configureLastMile(cfg);
		} else if (authType == AuthType.NTLM){
			configureNTLM(cfg);
		}
		
		
		if (cfgMgr.getConfigXmlPath().startsWith("WEB-INF")) {
			String wsdlPath = cfgMgr.getContext().getRealPath("WEB-INF/wsdl/usergroup.asmx?wsdl");
			this.wsdl = new File(wsdlPath);
			
			if (! wsdl.exists()) {
				throw new ProvisioningException("WSDL does not exist : '" + wsdlPath + "'");
			}
		} else {
			String wsdlPath = cfgMgr.getConfigXmlPath();
			wsdlPath = wsdlPath.substring(0,wsdlPath.lastIndexOf('/')) + "/wsdl/usergroup.asmx.wsdl";
			this.wsdl = new File(wsdlPath);
			
			if (! wsdl.exists()) {
				throw new ProvisioningException("WSDL does not exist : '" + wsdlPath + "'");
			}
		}
		
		try {
			URL touchurl = new URL(this.webServicesURL);
			StringBuffer nurl = new StringBuffer();
			
			nurl.append(touchurl.getProtocol()).append("://").append(touchurl.getHost());
			
			if ((touchurl.getPort() != -1) && ( (touchurl.getProtocol().equalsIgnoreCase("https") && touchurl.getPort() != 443) || (touchurl.getProtocol().equalsIgnoreCase("http") && touchurl.getPort() != 80)) ) {
				nurl.append(':').append(touchurl.getPort());
			} 
			
			nurl.append("/Pages/Default.aspx");
			this.touchURL = nurl.toString();
		} catch (MalformedURLException e) {
			throw new ProvisioningException("Could not parse wsdl url",e);
		}
		
		if (cfg.get("multiSite") != null) {
			if (cfg.get("multiSite").getValues().get(0).equalsIgnoreCase("true")) {
				this.multiSite = true;
			} else {
				this.multiSite = false;
			}
		} else {
			this.multiSite = false;
		}
		
		if (this.multiSite) {
			this.uris = new HashMap<String,URL>();
			if (cfg.get("siteURI") == null) {
				throw new ProvisioningException("siteURI not set");
			}
			for (String uri : cfg.get("siteURI").getValues()) {
				URL touchurl = null;
				try {
					touchurl = new URL(this.webServicesURL);
				} catch (MalformedURLException e) {
					throw new ProvisioningException("Could not parse URL",e);
				}
				
				StringBuffer nurl = new StringBuffer();
				
				nurl.append(touchurl.getProtocol()).append("://").append(touchurl.getHost());
				
				if ((touchurl.getPort() != -1) && ( (touchurl.getProtocol().equalsIgnoreCase("https") && touchurl.getPort() != 443) || (touchurl.getProtocol().equalsIgnoreCase("http") && touchurl.getPort() != 80)) ) {
					nurl.append(':').append(touchurl.getPort());
				}
				
				String wsuri = "";
				if (uri.endsWith("/")) {
					wsuri = uri.substring(0,uri.lastIndexOf('/'));
				} else {
					wsuri = uri;
				}
				
				nurl.append(wsuri).append("/_vti_bin/usergroup.asmx");
				logger.info("Adding site map for '" + uri + "' to '" + nurl + "'");
				try {
					this.uris.put(uri, new URL(nurl.toString()));
				} catch (MalformedURLException e) {
					throw new ProvisioningException("Could not parse web services url",e);
				}
			}
		}
		
		

	}

	private void configureNTLM(Map<String, Attribute> cfg) throws ProvisioningException {
		Attribute attr = cfg.get("adminUPN");
		if (attr == null) {
			throw new ProvisioningException("No administrator upn");
		}
		this.administratorUPN = attr.getValues().get(0);
		logger.info("Administrator UPN : '" + this.administratorUPN + "'");
		
		attr = cfg.get("adminPassword");
		if (attr == null) {
			throw new ProvisioningException("No administrator password");
		}
		
		this.administratorPassword = cfg.get("adminPassword").getValues().get(0);
		
	}

	private void configureLastMile(Map<String, Attribute> cfg)
			throws ProvisioningException {
		Attribute attr;
		attr = cfg.get("keyAlias");
		if (attr == null) {
			throw new ProvisioningException("No key alias");
		}
		this.keyAlias = attr.getValues().get(0);
		logger.info("Key Alias : '" + this.keyAlias + "'");
		
		attr = cfg.get("adminUPN");
		if (attr == null) {
			throw new ProvisioningException("No administrator upn");
		}
		this.administratorUPN = attr.getValues().get(0);
		logger.info("Administrator UPN : '" + this.administratorUPN + "'");
		
		
		
		attr = cfg.get("headerName");
		if (attr == null) {
			throw new ProvisioningException("No header name");
		}
		this.headerName = attr.getValues().get(0);
		logger.info("Header Name : '" + this.headerName + "'");
		
		attr = cfg.get("skew");
		if (attr == null) {
			throw new ProvisioningException("No skew");
		}
		this.skew = Integer.parseInt(attr.getValues().get(0));
		logger.info("Skew : '" + this.skew + "'");
	}
	
	@Override
	public void createUser(User user, Set<String> attributes,
			Map<String, Object> request) throws ProvisioningException {
		throw new ProvisioningException("Operation not supported");

	}

	@Override
	public void setUserPassword(User user, Map<String, Object> request)
			throws ProvisioningException {
		throw new ProvisioningException("Operation not supported");

	}

	@Override
	public void syncUser(User user, boolean addOnly,
			Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		User fromsp = null;
		
		/**/
		
		try {
			fromsp = this.findUser(user.getUserID(), attributes, request);
		} catch (Exception e) {
			if (logger.isDebugEnabled()) {
				logger.debug("Could not find user : '" + user.getUserID() + "', attempting touch to force load");
			}
			
			if (user.getAttribs().get(this.upnAttribute ) == null) {
				throw new ProvisioningException(this.upnAttribute + " does not exist on user " + user.getUserID());
			}
			
			try {
				if (logger.isDebugEnabled()) {
					logger.debug("Touching Sharepoint");
				}
				this.touch(user.getAttribs().get(this.upnAttribute).getValues().get(0));
				if (logger.isDebugEnabled()) {
					logger.debug("Touching Sharepoint Complete");
				}
			} catch (Exception e1) {
				logger.error("Error touching Sharepoint",e1);
				throw new ProvisioningException("Error touching SharePoint",e1);
			}
			
			try {
				if (logger.isDebugEnabled()) {
					logger.debug("Loading user");
				}
				fromsp = this.findUser(user.getUserID(), attributes, request);
				if (logger.isDebugEnabled()) {
					logger.debug("User loaded");
				}
			} catch (Exception e2) {
				logger.error("Could not load user",e2);
				throw new ProvisioningException("Could not load user",e2);
			}
			
		}
		
		if (fromsp == null) {
			this.createUser(user, attributes, request);
			return;
		}
		
		
		
		
		
		Set<String> newGroups = new HashSet<String>();
		Set<String> spGroups = new HashSet<String>();
		newGroups.addAll(user.getGroups());
		spGroups.addAll(fromsp.getGroups());
		
		ArrayList<String> toRemove = new ArrayList<String>();
		
		for (String name : user.getGroups()) {
			if (! spGroups.contains(name)) {
				try {
					if (this.multiSite) {
						String uri = name.substring(0,name.indexOf('^'));
						String groupName = name.substring(name.indexOf('^') + 1);
						
						URL serviceURL = this.uris.get(uri);
						if (serviceURL == null) {
							logger.warn("Site URI '" + uri + "' not configured");
							
						} else {
							try {
								this.getConnection(serviceURL).addUserToGroup(groupName, fromsp.getAttribs().get("DisplayName").getValues().get(0), fromsp.getAttribs().get("Login").getValues().get(0), user.getUserID(), "");
							} catch (Throwable t) {
								logger.warn("Error adding '" + user.getUserID() + "' to the group '" + name + "'",t);
							}
						}
					} else {
						this.getConnection().addUserToGroup(name, fromsp.getAttribs().get("DisplayName").getValues().get(0), fromsp.getAttribs().get("Login").getValues().get(0), user.getUserID(), "");
					}
					
					
					this.cfg.getProvisioningEngine().logAction(this.name,false, ActionType.Add, approvalID, workflow, "group", name);
				} catch (Exception e) {
					throw new ProvisioningException("Error adding '" + user.getUserID() + "' to the group '" + name + "'",e);
				}
				
			}
		}
		
		if (! addOnly) {
			for (String name : fromsp.getGroups()) {
				if (! newGroups.contains(name)) {
					try {
						
						if (multiSite) {
							String uri = name.substring(0,name.indexOf('^'));
							String groupName = name.substring(name.indexOf('^') + 1);
							
							URL serviceURL = this.uris.get(uri);
							if (serviceURL == null) {
								throw new ProvisioningException("Site URI '" + uri + "' not configured");
							}
							
							this.getConnection(serviceURL).removeUserFromGroup(groupName, fromsp.getAttribs().get("Login").getValues().get(0));
						} else {
							this.getConnection().removeUserFromGroup(name, fromsp.getAttribs().get("Login").getValues().get(0));
						}
						
						
						this.cfg.getProvisioningEngine().logAction(this.name,false, ActionType.Delete, approvalID, workflow, "group", name);
					} catch (Exception e) {
						throw new ProvisioningException("Error removing '" + user.getUserID() + "' from the group '" + name + "'",e);
					}
					
				}
			}
		}
		
		
		

	}

	@Override
	public void deleteUser(User user, Map<String, Object> request)
			throws ProvisioningException {
		throw new ProvisioningException("Operation not supported");

	}

	@Override
	public User findUser(String userID, Set<String> attributes,
			Map<String, Object> request) throws ProvisioningException {
		
		UsersList email = new UsersList();
		UsersList.Users users = new UsersList.Users();
		com.tremolosecurity.provisioning.sharepoint.ws.User user = new com.tremolosecurity.provisioning.sharepoint.ws.User();
		user.setEmail(userID);
		users.setUser(user);
		email.setUsers(users);
		GetUserLoginFromEmailResponse.GetUserLoginFromEmailResult res = null;
		
		
		
		try {
			if (this.multiSite) {
				//it doesn't matter which one we search to get user attributes
				res = this.getConnection(this.uris.get(uris.keySet().iterator().next())).getUserLoginFromEmail(email);
			} else {
				res = this.getConnection().getUserLoginFromEmail(email);
			}
			
		} catch (Exception e) {
			throw new ProvisioningException("Error retrieving sharepoint user : '" + userID + "'",e);
		}
		
		if (res.getGetUserLoginFromEmail().getUser() == null) { 
			return null;
		}
		
		User fromsp = new User(userID);
		
		
		fromsp.getAttribs().put("DisplayName", new Attribute("DisplayName",res.getGetUserLoginFromEmail().getUser().getDisplayName()));
		fromsp.getAttribs().put("Email", new Attribute("Email",res.getGetUserLoginFromEmail().getUser().getEmail()));
		fromsp.getAttribs().put("Login", new Attribute("Login",res.getGetUserLoginFromEmail().getUser().getLogin()));
		fromsp.getAttribs().put("SiteUser", new Attribute("SiteUser",res.getGetUserLoginFromEmail().getUser().getSiteUser()));
		
		
		addUserGroups(userID, fromsp);
		
		return fromsp;
		
		
	}

	private void addUserGroups(String userID, User fromsp)
			throws ProvisioningException {
		
		if (! this.multiSite) {
			GetGroupCollectionFromUserResult gres = null;
			try {
				gres = this.getConnection().getGroupCollectionFromUser(fromsp.getAttribs().get("Login").getValues().get(0));
				
				for (Group g :  gres.getGetGroupCollectionFromUser().getGroups().getGroup()) {
					fromsp.getGroups().add(g.getName());
				}
			} catch (Exception e) {
				
				if (logger.isDebugEnabled()) {
					logger.debug("Error retrieving groups for '" + userID + "'");
				}
				
				
			}
			
			
		} else {
			for (String uri : this.uris.keySet()) {
				URL url = this.uris.get(uri);
				
				GetGroupCollectionFromUserResult gres = null;
				try {
					gres = this.getConnection(url).getGroupCollectionFromUser(fromsp.getAttribs().get("Login").getValues().get(0));
					StringBuffer b = new StringBuffer();
					
					for (Group g :  gres.getGetGroupCollectionFromUser().getGroups().getGroup()) {
						b.setLength(0);
						b.append(uri).append('^').append(g.getName());
						fromsp.getGroups().add(b.toString());
					}
				} catch (Exception e) {
					
					
					
					if (logger.isDebugEnabled()) {
						logger.debug("Error retrieving groups for '" + userID + "'");
					}
				}
				
				
			}
		}
	}



	private UserGroupSoap getConnection(URL url) throws Exception {
		UserGroup ss = new UserGroup(wsdl.toURI().toURL(),SERVICE);
		UserGroupSoap port = ss.getUserGroupSoap12();
		
		BindingProvider provider = (BindingProvider) port;
		
		if (authType == AuthType.UnisonLastMile) {
			DateTime now = new DateTime();
			DateTime future = now.plusMillis(this.skew);
			now = now.minusMillis(skew);
			com.tremolosecurity.lastmile.LastMile lastmile = new com.tremolosecurity.lastmile.LastMile(url.getPath(),now,future,0,"chainName");
			lastmile.getAttributes().add(new Attribute("userPrincipalName",this.administratorUPN));
			
			SecretKey sk = this.cfg.getSecretKey(this.keyAlias);
			Map<String, List<String>> headers = (Map<String, List<String>>) provider.getRequestContext().get(MessageContext.HTTP_REQUEST_HEADERS);
			if (headers == null) {
				headers = new HashMap<String, List<String>>();
			}
			
			headers.put(this.headerName, Collections.singletonList(lastmile.generateLastMileToken(sk)));
		
			provider.getRequestContext().put(MessageContext.HTTP_REQUEST_HEADERS, headers);
		} else if (authType == AuthType.NTLM) {
			NtlmAuthenticator authenticator = new NtlmAuthenticator(this.administratorUPN, this.administratorPassword);
			Authenticator.setDefault(authenticator);
			
		}
		
		
		
		provider.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, url.toString());
		
		return port;
	}

	private UserGroupSoap getConnection() throws Exception {
		return this.getConnection(this.defaultServiceURL);
		
		
	}
	
	private void touch(String upn) throws Exception {
		
		if (this.authType == AuthType.UnisonLastMile) {
			DateTime now = new DateTime();
			DateTime future = now.plusMillis(this.skew);
			now = now.minusMillis(skew);
			com.tremolosecurity.lastmile.LastMile lastmile = new com.tremolosecurity.lastmile.LastMile("/Pages/Default.aspx",now,future,0,"chainName");
			lastmile.getAttributes().add(new Attribute("userPrincipalName",upn));
			
			SecretKey sk = this.cfg.getSecretKey(this.keyAlias);
			
			
			
			DefaultHttpClient http = new DefaultHttpClient();
			HttpGet get = new HttpGet(this.touchURL);
			get.addHeader(this.headerName, lastmile.generateLastMileToken(sk));
			http.execute(get);
		} else {
			
		}
		
	}

	@Override
	public void shutdown() throws ProvisioningException {
		// TODO Auto-generated method stub
		
	}
	
	

}

class NtlmAuthenticator extends Authenticator {

	  private final String username;
	  private final char[] password;

	  public NtlmAuthenticator(final String username, final String password) {
	    super();
	    this.username = new String(username);
	    this.password = password.toCharArray(); 
	  }

	  @Override
	  public PasswordAuthentication getPasswordAuthentication() {
	    return (new PasswordAuthentication (username, password));
	  }
}

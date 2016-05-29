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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.PrivilegedActionException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import net.sourceforge.spnego.SpnegoAuthenticator;
import net.sourceforge.spnego.SpnegoFilterConfig;
import net.sourceforge.spnego.SpnegoHttpServletResponse;
import net.sourceforge.spnego.SpnegoPrincipal;
import net.sourceforge.spnego.SpnegoHttpFilter.Constants;

import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.ietf.jgss.GSSException;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.auth.util.AuthUtil;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;



public class IWAAuth implements AuthMechanism {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(IWAAuth.class.getName());
	HashMap<String,SpnegoAuthenticator> domains;
	
	HashMap<String,String> spnegoCfg;

	//private SpnegoAuthenticator authenticator;

	private ConfigManager cfgMgr;

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		
		String header = request.getHeader("Authorization");
		
		
		HttpSession session = ((HttpServletRequest) request).getSession();
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		
		
		if (header == null) {
			sendFail(request,response,as);
			return;
		}
		
		

		SpnegoPrincipal principal = null;
		for (String realm : this.domains.keySet()) {
			SpnegoAuthenticator authenticator = this.domains.get(realm);
			final SpnegoHttpServletResponse spnegoResponse = new SpnegoHttpServletResponse(
	                (HttpServletResponse) response);

	        // client/caller principal
	        
	        try {
	        	
	        	
	        	
	            principal = authenticator.authenticate(request, spnegoResponse);
	            break;
	        } catch (GSSException gsse) {
	        	logger.error("Could not authenticate IWA user",gsse);
	        } catch (Throwable t) {
	        	logger.error("Could not authenticate IWA user",t);
	        }
		}
		
		if (principal == null) {
			sendFail(request,response,as);
			return;
		}
		
        
        
        
MyVDConnection myvd = cfgMgr.getMyVD();
		
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		
		
		
		
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());// holder.getConfig().getAuthChains().get(urlChain);
		
		
		
		
	
		AuthMechType amt = act.getAuthMech().get(as.getId());
		
		try {
			
			StringBuffer b = new StringBuffer();
			b.append("(userPrincipalName=").append(principal.toString()).append(")");
			
			LDAPSearchResults res = myvd.search(AuthUtil.getChainRoot(cfgMgr,act), 2, equal("userPrincipalName",principal.toString()).toString(), new ArrayList<String>());
			
			if (res.hasMore()) {
				logger.info("Loading user attributes");
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
				request.getSession().removeAttribute("TREMOLO_IWA_CHECKED");
				
			} else {
				logger.info("user not found, failing");
				as.setSuccess(false);
			}
			
		} catch (LDAPException e) {
			logger.error("Could not authenticate user",e);
			as.setSuccess(false);
			sendFail(request,response,as);
			return;
			
			/*if (amt.getRequired().equals("required")) {
				session.setAttribute(AuthSys.AUTH_RES, false);
			}*/
		}
		
		
		holder.getConfig().getAuthManager().nextAuth(request, response,session,true);

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
		if (init.get("domain") != null) {
			String krb5Conf = "[libdefaults]\n";
				  krb5Conf += "     default_tkt_enctypes = aes128-cts rc4-hmac des3-cbc-sha1 des-cbc-md5 des-cbc-crc\n";
				  krb5Conf += "     default_tgs_enctypes = aes128-cts rc4-hmac des3-cbc-sha1 des-cbc-md5 des-cbc-crc\n";
				  krb5Conf += "     permitted_enctypes   = aes128-cts rc4-hmac des3-cbc-sha1 des-cbc-md5 des-cbc-crc\n";
				  
				  if (init.get("domain").getValues().size() == 1) {
					  krb5Conf += "     default_realm   = " + init.get("domain").getValues().get(0) + "\n";
				  } else {
					  if (init.get("defaultDomain") == null) {
						  krb5Conf += "     default_realm   = " + init.get("domain").getValues().get(0) + "\n";
					  } else {
						  krb5Conf += "     default_realm   = " + init.get("defaultDomain").getValues().get(0) + "\n";
					  }
				  }
				  
				  krb5Conf += "\n";          
				  krb5Conf += "[realms]\n";
				  
				  
			  
				  for (String domain : init.get("domain").getValues()) {
					  String domainKDC = init.get(domain + ".kdc").getValues().get(0);
					  
					  krb5Conf += "     " + domain + " = {\n";
					  krb5Conf += "          kdc = " + domainKDC + "\n";
					  krb5Conf += "          default_domain = " + domain + "\n";
					  krb5Conf += "     }\n\n";
				  }
				  
				  krb5Conf += "[domain_realm]\n";
				  for (String domain : init.get("domain").getValues()) {
					  krb5Conf += "     ." + domain + " = " + domain + "\n";
				  }
			  
			  
			  
			  String pathToKrb5 = ctx.getRealPath("/WEB-INF/krb5.conf");
			  
			  logger.info("Path to krb5.conf : '" + pathToKrb5 + "'");
			  
			  String pathToLogin = "file://" + ctx.getRealPath("/WEB-INF/login.conf");
			  
			  logger.info("Path to login.conf : '" +  pathToLogin + "'");
			  
			  
			  
			  try {
				PrintWriter out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(pathToKrb5)));
				out.println(krb5Conf);
				out.flush();
				out.close();
			} catch (FileNotFoundException e) {
				logger.error("Could not create krb5.conf",e);
			}
			
			this.domains = new HashMap<String,SpnegoAuthenticator>();
			
			for (String domain : init.get("domain").getValues()) {
			
				HashMap<String,String >spnegoCfg = new HashMap<String,String>();
				spnegoCfg.put("spnego.allow.basic", "false");
				spnegoCfg.put("spnego.allow.localhost","false");
				spnegoCfg.put("spnego.allow.unsecure.basic", "false");
				spnegoCfg.put("spnego.login.client.module", "spnego-client");
				spnegoCfg.put("spnego.krb5.conf", pathToKrb5);
				spnegoCfg.put("spnego.login.conf", pathToLogin);
				spnegoCfg.put("spnego.login.server.module", "spnego-server");
				spnegoCfg.put("spnego.prompt.ntlm", "false");
				spnegoCfg.put("spnego.logger.level", "1");
				spnegoCfg.put("spnego.allow.delegation", "false");
				
				//String domain = init.get("domain").getValues().get(0);
				String userName = init.get(domain + ".userName").getValues().get(0);
				String password = init.get(domain + ".password").getValues().get(0);
				
				
				
				spnegoCfg.put("spnego.preauth.username", userName);
				spnegoCfg.put("spnego.preauth.password", password);
				
				
		            try {
						SpnegoAuthenticator authenticator = new SpnegoAuthenticator(spnegoCfg);
						this.domains.put(domain.toLowerCase(), authenticator);
					} catch (LoginException e) {
						logger.error("Could not initiate KDC connection",e);
					} catch (FileNotFoundException e) {
						logger.error("Could not initiate KDC connection",e);
					} catch (GSSException e) {
						logger.error("Could not initiate KDC connection",e);
					} catch (PrivilegedActionException e) {
						logger.error("Could not initiate KDC connection",e);
					} catch (URISyntaxException e) {
						logger.error("Could not initiate KDC connection",e);
					}
			}
				
				this.cfgMgr = (ConfigManager) ctx.getAttribute(ProxyConstants.TREMOLO_CONFIG);
		}

	}

	private void sendFail(HttpServletRequest request,HttpServletResponse response,AuthStep as)
	throws IOException, ServletException {
		
		
		Boolean checked = (Boolean) request.getSession().getAttribute("TREMOLO_IWA_CHECKED");
		
		if (checked == null || ! checked.booleanValue()) {
			as.setExecuted(false);
			checked = new Boolean(true);
			request.getSession().setAttribute("TREMOLO_IWA_CHECKED",checked);
		}
		
		
		as.setSuccess(false);
		StringBuffer realm = new StringBuffer();
		
		response.addHeader("WWW-Authenticate", "Negotiate");
		
		response.sendError(401);
		
		
		
		
		this.cfgMgr.getAuthManager().nextAuth(request, response,request.getSession(),true);
		
	}
	
	@Override
	public String getFinalURL(HttpServletRequest request,
			HttpServletResponse response) {
		
		return null;
	}

}

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


package com.tremolosecurity.lastmile.undertow;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.KeyStore;
import java.security.Principal;
import java.security.Security;

import javax.crypto.SecretKey;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.jboss.logging.Logger;

import com.tremolosecurity.lastmile.custom.CustomLastMile;
import com.tremolosecurity.lastmile.jboss71.valve.UnisonValve;
import com.tremolosecurity.saml.Attribute;

import io.undertow.security.idm.Account;
import io.undertow.security.impl.SecurityContextImpl;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.ResponseCodeHandler;
import io.undertow.servlet.handlers.ServletRequestContext;
import io.undertow.util.HttpString;

public class UnisonLastmileHandler implements HttpHandler {

	private volatile HttpHandler defaultHandler = ResponseCodeHandler.HANDLE_403;
	
	protected static Logger log = Logger.getLogger(UnisonLastmileHandler.class.getName());

	String headerName;

	String userAttribute;
	String roleAttribute;
	boolean createHeaders;
	Boolean initialized = false;
	String encryptionKeyName;

	boolean debug;

	SecretKey encryptionKey;

	String ignoreURI;

	String pathToKeyStore;
	String keyPass;

	CustomLastMile postValidate;

	String postValidateClassName;
	
	HttpHandler next;
	
	
	
	public UnisonLastmileHandler(HttpHandler next) {
		this.next = next;
		
		
	}
	
	
	@Override
	public void handleRequest(HttpServerExchange exchange) throws Exception {
		if (!this.initialized.booleanValue()) {
			initialize();
			
		}
		
		
		

		String xml = exchange.getRequestHeaders().getFirst(this.headerName);

		if (xml == null) {
			log.warn("No Header");
			defaultHandler.handleRequest(exchange);
			return;
		}

		if (log.isDebugEnabled()) {
			log.debug("Header value : '" + xml + "'");
		}

		com.tremolosecurity.lastmile.LastMile lastmile = new com.tremolosecurity.lastmile.LastMile();
		try {

			lastmile.loadLastMielToken(xml, encryptionKey);
		} catch (Exception e) {
			log.error("Could not validate LastMile header",e);
			defaultHandler.handleRequest(exchange);
			return;
		}

		try {
			if (!lastmile.isValid(exchange.getRequestURI())) {
				log.warn("Request not valid");
				defaultHandler.handleRequest(exchange);
				return;
			}
		} catch (Exception e) {
			throw new IOException("Could not validate request", e);
		}

		Attribute userID = null;
		Attribute userRoles = null;

		for (Attribute attr : lastmile.getAttributes()) {
			if (log.isDebugEnabled()) {
				log.debug("Attribute : " + attr);
			}

			if (this.createHeaders) {
				exchange.getRequestHeaders().addAll(new HttpString(headerName), attr.getValues());
			}

			if (attr.getName().equalsIgnoreCase(this.userAttribute)) {
				if (log.isDebugEnabled()) {
					log.debug("User Attribute " + this.userAttribute + " found");
				}
				userID = attr;
			} else if (attr.getName().equalsIgnoreCase(this.roleAttribute)) {
				if (log.isDebugEnabled()) {
					log.debug("Role Attribute " + this.roleAttribute + " found");
				}
				userRoles = attr;
			}
		}

		if (userID == null) {
			log.error("User identifier not found");
			defaultHandler.handleRequest(exchange);
			return;
		}

		UnisonAccount remoteAccount = new UnisonAccount(userID.getValues().get(0), userRoles);
		
		if (exchange.getSecurityContext() == null) {
			exchange.setSecurityContext(new SecurityContextImpl(exchange,new UnisonIdentityManager(remoteAccount)));
		} 
		
		if (exchange.getSecurityContext().getAuthenticationMechanisms().size() == 0 ) {
			exchange.getSecurityContext().addAuthenticationMechanism(new UnisonAuthenticationMechanism(remoteAccount));
			
		}
		
		
		
		
		Account currentAccount = exchange.getSecurityContext().getAuthenticatedAccount();
		if (currentAccount == null || ! currentAccount.getPrincipal().getName().equalsIgnoreCase(userID.getValues().get(0))) {
			exchange.getSecurityContext().setAuthenticationRequired();
			exchange.getSecurityContext().authenticationComplete(remoteAccount, "FORM", false);
		}
		
		
		/*ServletRequestContext context =	exchange.getAttachment(ATTACHMENT_KEY);
		
		request.setAttribute("UNISON_USER", userID.getValues().get(0));
		request.setAttribute("UINSON_ROLES", userRoles);
		
		request.setAttribute("tremolosecurity.loginlevel",
				lastmile.getLoginLevel());
		request.setAttribute("tremolosecurity.authchain",
				lastmile.getAuthChain());
		
		if (this.postValidate != null) {
			try {
				this.postValidate.postValidate(request, response, lastmile);
			} catch (Exception e) {
				throw new IOException(
						"Error during last mile post validation", e);
			}
		}*/
		
		
		
		
		this.next.handleRequest(exchange);

	}
	
	private synchronized void initialize() throws IOException {
		synchronized (this.initialized) {
			
			if (!this.initialized.booleanValue()) {
				log.info("Initializing");
				Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

				log.info("Logger initialized");

				log.info("Header Name - '" + this.headerName + "'");

				log.info("User Attribute - '" + this.userAttribute + "'");

				log.info("Keystore Path - '" + pathToKeyStore + "'");
				
				log.info("Post Validation Class Name - '" + this.postValidateClassName + "'");
				
				log.info("Create Headers - '" + this.createHeaders + "'");
				

				/*
				 * if (! pathToKeyStore.startsWith("/")) { pathToKeyStore =
				 * cfg.getServletContext().getRealPath("/") + "/" +
				 * pathToKeyStore; }
				 */

				log.info("Encryption Alias - '" + this.encryptionKeyName + "'");

				log.info("Config loaded");

				KeyStore ks;
				try {

					String fullPath = pathToKeyStore;
					log.info("Full Path to KeyStore : '" + fullPath);

					File f = new File(fullPath);
					if (!f.exists()) {
						throw new ServletException(
								"Could not load tremolo keystore : '"
										+ fullPath + "'");
					}

					ks = KeyStore.getInstance("JCEKS");
					ks.load(new FileInputStream(pathToKeyStore),
							keyPass.toCharArray());
					// ks.load(ctx.getResourceAsStream("/" + pathToKeyStore),
					// keyPass.toCharArray());

					this.encryptionKey = (SecretKey) ks.getKey(
							this.encryptionKeyName, keyPass.toCharArray());

					if (this.encryptionKey == null) {
						throw new ServletException(
								"Encryption Key does not exist");
					}

				} catch (Exception e) {

					log.error("Could not decrypt", e);
				}

				log.info("Keystore loaded");

				log.info("Loading post validate class");

				if (this.postValidateClassName != null && ! this.postValidateClassName.isEmpty()) {
					log.info("Post Validation Class : '"
							+ this.postValidateClassName + "'");
					try {
						this.postValidate = (CustomLastMile) Class.forName(
								this.postValidateClassName).newInstance();
					} catch (InstantiationException | IllegalAccessException
							| ClassNotFoundException e) {
						log.error("Could not initialize", e);
						throw new IOException("Could not initialize '"
								+ this.postValidateClassName + "'", e);
					}
					log.info("Post validation class loaded");
				} else {
					log.info("No post validation");
				}

				this.initialized = true;
			}
		}

	}

	public String getHeaderName() {
		return headerName;
	}

	public void setHeaderName(String headerName) {
		this.headerName = headerName;
	}

	public String getUserAttribute() {
		return userAttribute;
	}

	public void setUserAttribute(String userAttribute) {
		this.userAttribute = userAttribute;
	}

	public String getRoleAttribute() {
		return roleAttribute;
	}

	public void setRoleAttribute(String roleAttribute) {
		this.roleAttribute = roleAttribute;
	}

	public boolean isCreateHeaders() {
		return createHeaders;
	}

	public void setCreateHeaders(boolean createHeaders) {
		this.createHeaders = createHeaders;
	}

	public String getEncryptionKeyName() {
		return encryptionKeyName;
	}

	public void setEncryptionKeyName(String encryptionKeyName) {
		this.encryptionKeyName = encryptionKeyName;
	}

	public boolean isDebug() {
		return debug;
	}

	public void setDebug(boolean debug) {
		this.debug = debug;
	}

	public String getIgnoreURI() {
		return ignoreURI;
	}

	public void setIgnoreURI(String ignoreURI) {
		this.ignoreURI = ignoreURI;
	}

	public String getPathToKeyStore() {
		return pathToKeyStore;
	}

	public void setPathToKeyStore(String pathToKeyStore) {
		this.pathToKeyStore = pathToKeyStore;
	}

	public String getKeyPass() {
		return keyPass;
	}

	public void setKeyPass(String keyPass) {
		this.keyPass = keyPass;
	}

	public CustomLastMile getPostValidate() {
		return postValidate;
	}

	public void setPostValidate(CustomLastMile postValidate) {
		this.postValidate = postValidate;
	}

	public String getPostValidateClassName() {
		return postValidateClassName;
	}

	public void setPostValidateClassName(String postValidateClassName) {
		this.postValidateClassName = postValidateClassName;
	}

	
	
}

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


package com.tremolosecurity.lastmile.jboss71.valve;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;

import javax.crypto.SecretKey;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.connector.Request;
import org.apache.catalina.deploy.LoginConfig;
import org.jboss.as.web.security.ExtendedFormAuthenticator;
import org.jboss.logging.Logger;
import org.apache.catalina.Realm;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.catalina.realm.GenericPrincipal;

import com.tremolosecurity.filter.AutoIDMPrincipal;
import com.tremolosecurity.lastmile.custom.CustomLastMile;
import com.tremolosecurity.saml.Attribute;

public class UnisonValve extends ExtendedFormAuthenticator {

	protected static org.apache.logging.log4j.Logger log = org.apache.logging.log4j.LogManager.getLogger(UnisonValve.class.getName());

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

	ServletContext ctx;

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

	public String getEncryptionKeyName() {
		return encryptionKeyName;
	}

	public void setEncryptionKeyName(String encryptionKeyName) {
		this.encryptionKeyName = encryptionKeyName;
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

	private synchronized void initialize(ServletContext ctx) throws IOException {
		synchronized (this.initialized) {
			this.ctx = ctx;
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

	public boolean isCreateHeaders() {
		return createHeaders;
	}

	public void setCreateHeaders(boolean createHeaders) {
		this.createHeaders = createHeaders;
	}

	public String getPostValidateClassName() {
		return postValidateClassName;
	}

	public void setPostValidateClassName(String postValidateClassName) {
		this.postValidateClassName = postValidateClassName;
	}

	@Override
	public boolean authenticate(Request request, HttpServletResponse response,
			LoginConfig loginConfig) throws IOException {

		if (!this.initialized.booleanValue()) {
			initialize(request.getContext().getServletContext());
		}

		Session session = request.getSessionInternal(true);

		String xml = request.getHeader(this.headerName);

		if (xml == null) {
			log.warn("No Header");
			((HttpServletResponse) response)
					.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			return false;
		}

		if (log.isDebugEnabled()) {
			log.debug("Header value : '" + xml + "'");
		}

		com.tremolosecurity.lastmile.LastMile lastmile = new com.tremolosecurity.lastmile.LastMile();
		try {

			lastmile.loadLastMielToken(xml, encryptionKey);
		} catch (Exception e) {
			e.printStackTrace();
			((HttpServletResponse) response)
					.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			return false;
		}

		try {
			if (!lastmile.isValid(request.getRequestURI())) {
				log.warn("Request not valid");
				((HttpServletResponse) response)
						.sendError(HttpServletResponse.SC_UNAUTHORIZED);
				return false;
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
				for (String val : attr.getValues()) {
	
					request.getCoyoteRequest().getMimeHeaders()
							.setValue(attr.getName()).setString(val);
				}
			}
			
			request.setAttribute(attr.getName(), attr);

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
			return false;
		}

		request.setAttribute("UNISON_USER", userID.getValues().get(0));
		request.setAttribute("UINSON_ROLES", userRoles);
		
		request.setAttribute("tremolosecurity.loginlevel",
				lastmile.getLoginLevel());
		request.setAttribute("tremolosecurity.authchain",
				lastmile.getAuthChain());
		
		Principal principal = request.getUserPrincipal();
		if (principal != null) {
			if (log.isDebugEnabled()) {
				log.debug("Already authenticated '" + principal.getName() + "'");
			}

			if (this.postValidate != null) {
				try {
					this.postValidate.postValidate(request, response, lastmile);
				} catch (Exception e) {
					throw new IOException(
							"Error during last mile post validation", e);
				}
			}

			return true;
		} else {

			

			
			if (log.isDebugEnabled()) {
				log.debug("Authenticating '" + userID.getValues().get(0) + "'");
			}

			Principal authenticatedPrincipal = context.getRealm().authenticate(
					userID.getValues().get(0), "");

			if (log.isDebugEnabled()) {
				log.debug("Authenticated '" + authenticatedPrincipal.getName() + "'");
			}

			

			session.setNote(Constants.SESS_USERNAME_NOTE, userID.getValues()
					.get(0));
			session.setNote(Constants.SESS_PASSWORD_NOTE, "");
			request.setUserPrincipal(authenticatedPrincipal);

			register(request, response, authenticatedPrincipal,
					HttpServletRequest.FORM_AUTH,
					authenticatedPrincipal.getName(), "");

			if (this.postValidate != null) {
				try {
					this.postValidate.postValidate(request, response, lastmile);
				} catch (Exception e) {
					throw new IOException(
							"Error during last mile post validation", e);
				}
			}

			return true;

		}

	}

}

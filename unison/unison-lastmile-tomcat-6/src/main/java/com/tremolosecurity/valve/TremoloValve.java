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


package com.tremolosecurity.valve;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;
import java.util.Vector;

import javax.crypto.SecretKey;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.logging.log4j.Logger;


import com.tremolosecurity.filter.AutoIDMPrincipal;
import com.tremolosecurity.lastmile.LastMile;
import com.tremolosecurity.lastmile.custom.CustomLastMile;
import com.tremolosecurity.saml.Attribute;


public class TremoloValve extends ValveBase {

//static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AutoIDMFilter.class);
	
	String headerName;
	
	String userAttribute;
	String roleAttribute;
	boolean createHeaders;
	Boolean initialized = false;
	String encryptionKeyName;
	
	boolean debug;
	

	SecretKey encryptionKey;
	SecretKey sigKey;
	String ignoreURI;
	
	String pathToKeyStore;
	String keyPass;
	
	CustomLastMile postValidate;
	
	String postValidateClassName;
	
	

	ServletContext ctx;
	
	public boolean isDebug() {
		return debug;
	}

	public void setDebug(boolean debug) {
		this.debug = debug;
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

	public boolean isCreateHeaders() {
		return createHeaders;
	}

	public void setCreateHeaders(boolean createHeaders) {
		this.createHeaders = createHeaders;
	}

	public String getIgnoreURI() {
		return ignoreURI;
	}

	public void setIgnoreURI(String ignoreURI) {
		this.ignoreURI = ignoreURI;
	}
	
	public String getPostValidateClassName() {
		return postValidateClassName;
	}

	public void setPostValidateClassName(String postValidateClassName) {
		this.postValidateClassName = postValidateClassName;
	}

	@Override
	public void invoke(Request request, Response response) throws IOException,
			ServletException {
		
		
		
		if (! this.initialized.booleanValue()) {
			initialize(request.getContext().getServletContext());
		}
		
		if (this.ignoreURI == null || this.ignoreURI.isEmpty() || ! request.getRequestURI().startsWith(this.ignoreURI)) {
			
			String xml = request.getHeader(this.headerName);
			
			if (xml == null) {
				System.out.println("No Header");
				((HttpServletResponse) response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
				return;
			}
			
			
			
			if (debug) {
				System.out.println("Header value : '" + xml + "'");
			}
			
			
			com.tremolosecurity.lastmile.LastMile lastmile = new com.tremolosecurity.lastmile.LastMile();
			try {
				
				lastmile.loadLastMielToken(xml, encryptionKey);
			} catch (Exception e) {
				e.printStackTrace();
				((HttpServletResponse) response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
				return;
			}
			
			try {
				if (! lastmile.isValid(request.getRequestURI())) {
					System.out.println("Request not valid");
					((HttpServletResponse) response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
					return;
				}
			} catch (Exception e) {
				throw new ServletException("Could not validate request",e);
			}
			
			
			
			HashMap<String,Attribute> attrs = new HashMap<String,Attribute>();
			
				Iterator<Attribute> attribs = lastmile.getAttributes().iterator();
				while (attribs.hasNext()) {
					Attribute attrib = attribs.next();
					if (this.createHeaders) {
						for (String val : attrib.getValues()) {
							
							request.getCoyoteRequest().getMimeHeaders().setValue(attrib.getName()).setString(val);
						}
					}
						
					attrs.put(attrib.getName(), attrib);
						
					
					/*
					if (attrib.getName().equals(roleAttribute)) {
						
						
						this.roles.addAll(attrib.getValues());
					}*/
						
					if (attrib.getName().equalsIgnoreCase(userAttribute)) {
						request.setUserPrincipal(new AutoIDMPrincipal(attrib.getValues().get(0),attrs));
					}
				}
			
			
			
			request.setAttribute("tremolosecurity.loginlevel", lastmile.getLoginLevel());
			request.setAttribute("tremolosecurity.authchain", lastmile.getAuthChain());
			
			if (this.postValidate != null) {
				try {
					this.postValidate.postValidate(request, response, lastmile);
				} catch (Exception e) {
					throw new ServletException("Error during last mile post validation",e);
				}
			}
			
		} 
		
		
		
		this.getNext().invoke(request, response);
		

	}

	private synchronized void initialize(ServletContext ctx) throws ServletException {
		synchronized (this.initialized) {
			this.ctx = ctx;
			if (! this.initialized.booleanValue()) {
				System.out.println("TREMOLO : Starting");
				Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
				
				
				System.out.println("TREMOLO : logger initialized");
				
								
				
				
				System.out.println("Header Name - '" + this.headerName + "'");
				
				
				
				System.out.println("Role Attribute - '" + this.roleAttribute + "'");
				
				
				
				System.out.println("Create Headers - '" + this.createHeaders + "'");
				
				
				
				System.out.println("User Attribute - '" + this.userAttribute + "'");
				
				
				
				System.out.println("Keystore Path - '" + pathToKeyStore + "'");
				
				/*if (! pathToKeyStore.startsWith("/")) {
					pathToKeyStore = cfg.getServletContext().getRealPath("/") + "/" + pathToKeyStore;
				}*/
				
				
				
				
				System.out.println("Encryption Alias - '" + this.encryptionKeyName + "'");
				
				
				
				System.out.println("Post Validation Class - '" + this.postValidateClassName + "'");
				
				
				
				System.out.println("Ignore URI - '" + this.ignoreURI + "'");
				
				System.out.println("TREMOLO : config loaded");
				
				KeyStore ks;
				try {
					
					String fullPath =  null;
					
					if (pathToKeyStore.startsWith("WEB-INF")) {
						fullPath = ctx.getRealPath("/" + pathToKeyStore);
					} else {
						fullPath = pathToKeyStore;
					}
					
					System.out.println("Full Path to KeyStore : '" + fullPath + "'");
					
					File f = new File(fullPath);
					if (! f.exists()) {
						throw new ServletException("Could not load tremolo keystore : '" + fullPath + "'");
					}
					
					ks = KeyStore.getInstance("PKCS12");
					try {
						ks.load(new FileInputStream(f), keyPass.toCharArray());
					} catch (Throwable t) {
						ks = KeyStore.getInstance("JCEKS");
						ks.load(new FileInputStream(f), keyPass.toCharArray());
					}
					this.encryptionKey = (SecretKey) ks.getKey(this.encryptionKeyName, keyPass.toCharArray());
					
					if (this.encryptionKey == null) {
						throw new ServletException("Encryption Key does not exist");
					}
					
					if (this.postValidateClassName != null) {
						this.postValidate = (CustomLastMile) Class.forName(this.postValidateClassName).newInstance();
					}
					
					/*
					this.sigKey = (SecretKey) ks.getKey(sigKeyAlias, password.toCharArray());
					
					if (this.sigKey == null) {
						throw new ServletException("Signature Key does not exist");
					}*/
					
				} catch (KeyStoreException e) {
					
					e.printStackTrace();
				} catch (NoSuchAlgorithmException e) {
					
					e.printStackTrace();
				} catch (CertificateException e) {
					
					e.printStackTrace();
				} catch (FileNotFoundException e) {
					
					e.printStackTrace();
				} catch (IOException e) {
					
					e.printStackTrace();
				} catch (UnrecoverableKeyException e) {
					
					e.printStackTrace();
				} catch (InstantiationException e) {
					
					e.printStackTrace();
				} catch (IllegalAccessException e) {
					
					e.printStackTrace();
				} catch (ClassNotFoundException e) {
					
					e.printStackTrace();
				}
				
				System.out.println("TREMOLO : keystore loaded");
				
				this.initialized = true;
			}
		}
		
	}

}

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


package com.tremolosecurity.lastmile.servlet3x.filter;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.StringTokenizer;

import javax.crypto.SecretKey;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.tremolosecurity.lastmile.custom.CustomLastMile;

public class UnisonLastMileFilter implements Filter {
	
	String headerName;
	String userAttribute;
	String roleAttribute;
	boolean createHeaders;
	SecretKey encryptionKey;
	boolean isDebug;
	
	CustomLastMile postValidate;

	String ignoreURI;
	
	ServletContext ctx;
	
	boolean verifyOnly;
	private HashSet<String> welcomeFileList;
	

	@Override
	public void destroy() {
		// TODO Auto-generated method stub

	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {
		
		
HttpServletRequest httpRequest = (HttpServletRequest) request;
		
		
		

		
		
		if (this.ignoreURI == null || this.ignoreURI.isEmpty()  || ! httpRequest.getRequestURI().startsWith(this.ignoreURI)) {
			
			String xml = httpRequest.getHeader(this.headerName);
			
			if (isDebug) {
				ctx.log("TREMOLO : Header - " + xml);
				
				Enumeration enumer = httpRequest.getHeaderNames();
				while (enumer.hasMoreElements()) {
					String headerName = (String) enumer.nextElement();
					Enumeration vals = httpRequest.getHeaders(headerName);
					while (vals.hasMoreElements()) {
						String val = (String) vals.nextElement();
						ctx.log("TREMOLO : Header '" + headerName + "'='" + val + "'");
					}
				}
			}
			
			/*if (logger.isDebugEnabled()) {
				ctx.log("Header value : '" + xml + "'");
			}*/
			
			
			com.tremolosecurity.lastmile.LastMile lastmile = new com.tremolosecurity.lastmile.LastMile();
			
			try {
				
				lastmile.loadLastMielToken(xml, encryptionKey);
			} catch (Exception e) {
				ctx.log("Could not load XML",e);
				((HttpServletResponse) response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
				return;
			}
			
			try {
				if (! lastmile.isValid(httpRequest.getRequestURI())) {
					
					String file = httpRequest.getRequestURI().substring(httpRequest.getRequestURI().lastIndexOf('/') + 1);
					
					if (this.welcomeFileList.contains(file)) {
						if (! lastmile.isValid(httpRequest.getRequestURI().substring(0,httpRequest.getRequestURI().lastIndexOf('/') +1))) {
							ctx.log("Request not valid");
							((HttpServletResponse) response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
							return;
						}
					} else {
						
						ctx.log("Request not valid");
						((HttpServletResponse) response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
						return;
						
					}
					
					
				}
			} catch (Exception e) {
				throw new ServletException("Could not validate request",e);
			}
			
			request.setAttribute("tremolosecurity.loginlevel", lastmile.getLoginLevel());
			request.setAttribute("tremolosecurity.authchain", lastmile.getAuthChain());
			
			UnisonLastMileRequest idmRequest = new UnisonLastMileRequest(httpRequest,lastmile,this.userAttribute,this.roleAttribute,this.createHeaders);
			
			
			
			
			if (this.postValidate != null) {
				try {
					this.postValidate.postValidate(httpRequest, (HttpServletResponse) response, lastmile);
				} catch (Exception e) {
					throw new ServletException("Could not run post validate",e);
				}
			}
			
			if (this.verifyOnly) {
				if (idmRequest.getUserPrincipal() != null && ! idmRequest.getUserPrincipal().getName().equals(httpRequest.getUserPrincipal().getName())) {
					throw new ServletException("User context incorrect");
				}
				
				chain.doFilter(httpRequest, response);
			} else {
				chain.doFilter(idmRequest, response);
			}
			
			
		} else {
			chain.doFilter(request, response);
		}
		
		

	}

	@Override
	public void init(FilterConfig cfg) throws ServletException {
		this.ctx = cfg.getServletContext();
		
		
		
		ctx.log("TREMOLO : Starting");
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		/*Properties loggingProps = new Properties();
		try {
			
			
			
			loggingProps.load(cfg.getServletContext().getResourceAsStream("/WEB-INF/log4j.properties"));
			PropertyConfigurator.configure(loggingProps);
		} catch (IOException e1) {
			throw new ServletException(e1);
		}*/
		
		ctx.log("TREMOLO : logger initialized");
		

		String isDebug = cfg.getInitParameter("debug");
		this.isDebug = isDebug != null && isDebug.equalsIgnoreCase("true");
		ctx.log("TREMOLO : Debug - " + this.isDebug);
		
		ctx.log("TREMOLO : bootstrap complete");
		
		this.headerName = cfg.getInitParameter("headerName");
		
		ctx.log("Header Name - '" + this.headerName + "'");
		
		this.roleAttribute = cfg.getInitParameter("roleAttribute");
		
		ctx.log("Role Attribute - '" + this.roleAttribute + "'");
		
		this.createHeaders = cfg.getInitParameter("createHeaders") != null && cfg.getInitParameter("createHeaders").equalsIgnoreCase("yes");
		
		ctx.log("Create Headers - '" + this.createHeaders + "'");
		
		this.userAttribute = cfg.getInitParameter("userAttribute");
		
		ctx.log("User Attribute - '" + this.userAttribute + "'");
		
		String pathToKeyStore = cfg.getInitParameter("keyStore");
		
		ctx.log("Keystore Path - '" + pathToKeyStore + "'");
		
		/*if (! pathToKeyStore.startsWith("/")) {
			pathToKeyStore = cfg.getServletContext().getRealPath("/") + "/" + pathToKeyStore;
		}*/
		
		String password = cfg.getInitParameter("keyPass");
		String encKeyAlias = cfg.getInitParameter("encKeyAlias");
		
		ctx.log("Encryption Alias - '" + encKeyAlias + "'");
		
		String sigKeyAlias = cfg.getInitParameter("sigKeyAlias");
		
		ctx.log("Sig Alias - '" + sigKeyAlias + "'");
		
		this.ignoreURI = cfg.getInitParameter("ignoreURI");
		
		ctx.log("Ignore URI - '" + this.ignoreURI + "'");
		
		String postValidateClassName = cfg.getInitParameter("postValidateClassName");
		if (postValidateClassName != null && ! postValidateClassName.isEmpty()) {
			try {
				this.postValidate = (CustomLastMile) Class.forName(postValidateClassName).newInstance();
			} catch (InstantiationException e) {
				throw new ServletException("Could not load custom last mile",e);
			} catch (IllegalAccessException e) {
				throw new ServletException("Could not load custom last mile",e);
			} catch (ClassNotFoundException e) {
				throw new ServletException("Could not load custom last mile",e);
			}
		}
		
		String verifyOnly = cfg.getInitParameter("verifyOnly");
		if (verifyOnly != null) {
			this.verifyOnly = verifyOnly.equalsIgnoreCase("true");
		} else {
			this.verifyOnly = false;
		}
		
		ctx.log("TREMOLO : config loaded");
		
		KeyStore ks;
		try {
			
			String fullPath;
			
			if (pathToKeyStore.startsWith("WEB-INF")) {
				fullPath = cfg.getServletContext().getRealPath("/" + pathToKeyStore);
			} else {
				fullPath = pathToKeyStore;
			}
			
			ctx.log("Full Path to KeyStore : '" + fullPath + "'");
			
			File f = new File(fullPath);
			if (! f.exists()) {
				throw new ServletException("Could not load tremolo keystore : '" + fullPath + "'");
			}
			
			ks = KeyStore.getInstance("PKCS12");
			try {
				ks.load(new FileInputStream(new File(fullPath)), password.toCharArray());
			} catch (Throwable t) {
				ks = KeyStore.getInstance("JCEKS");
				ks.load(new FileInputStream(new File(fullPath)), password.toCharArray());
			}
			
			this.encryptionKey = (SecretKey) ks.getKey(encKeyAlias, password.toCharArray());
			
			if (this.encryptionKey == null) {
				throw new ServletException("Encryption Key does not exist");
			}
			
			
			
			
		} catch (KeyStoreException e) {
			
			ctx.log("Could not load keystore",e);
		} catch (NoSuchAlgorithmException e) {
			
			ctx.log("Could not load keystore",e);
		} catch (CertificateException e) {
			
			ctx.log("Could not load keystore",e);
		} catch (FileNotFoundException e) {
			
			ctx.log("Could not load keystore",e);
		} catch (IOException e) {
			
			ctx.log("Could not load keystore",e);
		} catch (UnrecoverableKeyException e) {
			
			ctx.log("Could not load keystore",e);
		}
		
		ctx.log("TREMOLO : keystore loaded");
		
		String welcomeFiles = cfg.getInitParameter("welcomeFiles");
		if (welcomeFiles == null) {
			welcomeFiles = "";
		}
		
		this.welcomeFileList = new HashSet<String>();
		StringTokenizer toker = new StringTokenizer(welcomeFiles,",",false);
		while (toker.hasMoreTokens()) {
			this.welcomeFileList.add(toker.nextToken());
		}
		
		if (this.postValidate != null) {
			this.postValidate.afterInit(cfg);
		}

	}

}

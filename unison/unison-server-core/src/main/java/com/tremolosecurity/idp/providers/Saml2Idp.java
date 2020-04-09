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


package com.tremolosecurity.idp.providers;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.security.cert.X509Certificate;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.Logger;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.impl.AuthnRequestUnmarshaller;
import org.stringtemplate.v4.ST;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.idp.server.IDP;
import com.tremolosecurity.idp.server.IdentityProvider;
//import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.proxy.ProxyRequest;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AuthSys;
import com.tremolosecurity.proxy.auth.AzSys;
import com.tremolosecurity.proxy.auth.RequestHolder;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterChainImpl;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterRequestImpl;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.filter.HttpFilterResponseImpl;
import com.tremolosecurity.proxy.filter.PostProcess;
import com.tremolosecurity.proxy.util.NextSys;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.saml.Saml2Assertion;



public class Saml2Idp implements IdentityProvider {

	public static String DEFAULT_SAML2_POST_TEMPLATE = "<html>\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />\n<title>Completing Federation</title>\n</head>\n<body onload=\"document.forms[0].submit()\">\n<form method=\"post\" action=\"$postaction$\">\n<input name=\"SAMLResponse\" value=\"$postdata$\" type=\"hidden\"/>\n<input name=\"RelayState\" value=\"$relaystate$\" type=\"hidden\"/>\n</form>\n<center>\n<img src=\"/auth/forms/images/ts_logo.png\" /><br />\n<h2>Completing Federation...</h2>\n</center>\n</body>\n</html>";

	private static HashMap<String, String> xmlDigSigAlgs;

	private static HashMap<String, String> javaDigSigAlgs;

	static {
		xmlDigSigAlgs = new HashMap<String,String>();
		xmlDigSigAlgs.put("http://www.w3.org/2000/09/xmldsig#rsa-sha1","RSA-SHA1");
		xmlDigSigAlgs.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256","RSA-SHA256");
		xmlDigSigAlgs.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384","RSA-SHA384");
		xmlDigSigAlgs.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "RSA-SHA512" );
		
		javaDigSigAlgs = new HashMap<String,String>();
		javaDigSigAlgs.put("http://www.w3.org/2000/09/xmldsig#rsa-sha1", "SHA1withRSA");
		javaDigSigAlgs.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "SHA256withRSA");
		javaDigSigAlgs.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "SHA384withRSA");
		javaDigSigAlgs.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "SHA512withRSA");
		
	}
	
	public static final String SAML2_AUTHN_REQ_URL = "SAML2_AUTHN_REQ_URL";

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(Saml2Idp.class.getName());
	
	private static final String TRANSACTION_DATA = "TREMOLO_SAML2_IDP_TRANSACTION_DATA";
	String idpName;
	String idpSigKeyName;
	boolean requireSignedAuthn;
	
	
	private HashMap<String, Saml2Trust> trusts;

	MapIdentity mapper;

	private String saml2PostTemplate;
	
	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {
		if (logger.isDebugEnabled()) {
			logger.debug("SAMLRequest: " + request.getParameter("SAMLRequest"));
		}
		
		String action = (String) request.getAttribute(IDP.ACTION_NAME);
		
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		
		if (action.equalsIgnoreCase("httpRedirect")) {
			processGetAuthnReq(request, response, factory);
		} else if (action.equalsIgnoreCase("completeFed")) {
			completeFederation(request, response);
		} else if (action.equalsIgnoreCase("idpInit")) {
			
			String issuer = request.getParameter("sp");
			
			Saml2Trust trust = this.trusts.get(issuer);
			
			if (trust.params.get("defaultNameId") == null) {
				throw new ServletException("No default name id");
			}
			String nameID = trust.params.get("defaultNameId").getValues().get(0);
			String authnCtx = trust.params.get("defaultAuthCtx").getValues().get(0);
			
			if (trust.params.get("defaultAuthCtx") == null) {
				throw new ServletException("No default auth ctx");
			}
			
			String binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
			String url = trust.params.get("httpPostRespURL").getValues().get(0);
			
			if (trust.params.get("httpPostRespURL") == null) {
				throw new ServletException("No post back url");
			}
			
			String relayState = request.getParameter("RelayState");
			
			if (logger.isDebugEnabled()) {
				logger.debug("Issuer : '" + issuer + "'");
				logger.debug("Binding : '" + binding + "'");
				logger.debug("URL : '" + url + "'");
				
				logger.debug("NameID Format : '" + nameID + "'");
				logger.debug("Authn Class Ctx : '" + authnCtx + "'");
			}
			
			
			try {
				doFederation(request, response, issuer, nameID, authnCtx, url,relayState,trust);
			} catch (Exception e) {
				throw new ServletException("Could not do idp initiated federation",e);
			}
		}
		

	}

	private void completeFederation(HttpServletRequest request,
			HttpServletResponse response) throws IOException, ServletException,
			MalformedURLException {
		final SamlTransaction transaction = (SamlTransaction) request.getSession().getAttribute(Saml2Idp.TRANSACTION_DATA);
		
		final AuthInfo authInfo = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
		
		if (! authInfo.isAuthComplete()) {
			logger.warn("Attempted completetd federation before autthentication is completeed, clearing authentication and redirecting to the original URL");
			
			UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
			request.getSession().removeAttribute(ProxyConstants.AUTH_CTL);
			holder.getConfig().createAnonUser(request.getSession());
			
			this.postErrorResponse(transaction, request, response, authInfo, holder);
			
			return;
		}
		
		request.setAttribute(AzSys.FORCE, "true");
		NextSys completeFed = new NextSys() {

			@Override
			public void nextSys(final HttpServletRequest request,
					final HttpServletResponse response) throws IOException,
					ServletException {
				//System.out.println("Authorized!!!!");
				
				
				final AuthInfo authInfo = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
				UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
				
				HttpFilterRequest filterReq = new HttpFilterRequestImpl(request, null);
				HttpFilterResponse filterResp = new HttpFilterResponseImpl(response);

				PostProcess postProc = new PostProcess() {

					@Override
					public void postProcess(HttpFilterRequest req,
							HttpFilterResponse resp, UrlHolder holder,HttpFilterChain chain)
							throws Exception {
						postResponse(transaction, request, response, authInfo,
								holder);
						
					}

					@Override
					public boolean addHeader(String name) {
						
						return false;
					}
					
				};
				
				HttpFilterChain chain = new HttpFilterChainImpl(holder,postProc);
				try {
					chain.nextFilter(filterReq, filterResp, chain);
				} catch (Exception e) {
					
					throw new ServletException(e);
				}
				
				
				
				
			}
			
		};
		
		AzSys az = new AzSys();
		az.doAz(request, response, completeFed);
	}

	private void processGetAuthnReq(HttpServletRequest request,
			HttpServletResponse response, DocumentBuilderFactory factory)
			throws ServletException {
		try {
			ProxyRequest pr = (ProxyRequest) request;
			StringBuffer url = new StringBuffer();
			url.append(request.getRequestURL()).append('?').append(request.getQueryString());
			request.getSession().setAttribute(SAML2_AUTHN_REQ_URL, url);
			
			String saml = this.inflate(request.getParameter("SAMLRequest"));
			if (logger.isDebugEnabled()) {
				logger.debug(saml);
			}
			
			
			
			String relayState = request.getParameter("RelayState");
			
			
			procAuthnReq(request, response, factory, saml, relayState);
			
			
			
			
		} catch (NullPointerException e) {
			throw new ServletException("AuthnRequest is missing elements",e);
		} catch (Exception e) {
			logger.error("Could not parse http-relay request",e);
			throw new ServletException("Could not parse http-relay request",e);
		}
	}

	private void processPostAuthnReq(HttpServletRequest request,
			HttpServletResponse response, DocumentBuilderFactory factory)
			throws ServletException {
		try {
			String saml = new String(Base64.decodeBase64(request.getParameter("SAMLRequest")));
			if (logger.isDebugEnabled()) {
				logger.debug(saml);
			}
			
			Enumeration enumer = request.getParameterNames();
			while (enumer.hasMoreElements()) {
				String name = (String) enumer.nextElement();
				if (logger.isDebugEnabled()) {
					logger.debug(name + "=" + request.getParameter(name));
				}
			}
			
			String relayState = request.getParameter("RelayState");
			
			
			procAuthnReq(request, response, factory, saml, relayState);
			
			
			
			
		} catch (NullPointerException e) {
			throw new ServletException("AuthnRequest is missing elements",e);
		} catch (Exception e) {
			throw new ServletException("Could not parse http-relay request",e);
		}
	}
	
	private void procAuthnReq(HttpServletRequest request,
			HttpServletResponse response, DocumentBuilderFactory factory,
			String saml, String relayState)
			throws ParserConfigurationException, SAXException, IOException,
			UnmarshallingException, Exception, UnsupportedEncodingException,
			NoSuchAlgorithmException, InvalidKeyException, SignatureException,
			ServletException {
		AuthnRequestUnmarshaller marshaller = new AuthnRequestUnmarshaller();
		DocumentBuilder builder = factory.newDocumentBuilder();

		Element root = builder
				.parse(new InputSource(new StringReader(saml)))
				.getDocumentElement();
		
		AuthnRequest authn = (AuthnRequest) marshaller.unmarshall(root);
		
		String issuer = authn.getIssuer().getValue();
		
		
		
		String authnCtx = null;
		
		if (authn.getRequestedAuthnContext() == null || authn.getRequestedAuthnContext().getAuthnContextClassRefs().size() == 0 || authn.getRequestedAuthnContext().getAuthnContextClassRefs().get(0).getAuthnContextClassRef() == null) {
			//no authnCtx information, use default
			authnCtx = null;
		} else {
			authnCtx = authn.getRequestedAuthnContext().getAuthnContextClassRefs().get(0).getAuthnContextClassRef();
		}
		
		
		String nameID = null;
		
		if (authn.getNameIDPolicy() == null) {
			nameID = null;
		} else {
			nameID = authn.getNameIDPolicy().getFormat();
		}
		
		
		
		String binding = authn.getProtocolBinding();
		String url = authn.getAssertionConsumerServiceURL();
		
		if (logger.isDebugEnabled()) {
			logger.debug("Issuer : '" + issuer + "'");
			logger.debug("Binding : '" + binding + "'");
			logger.debug("URL : '" + url + "'");
			
			logger.debug("NameID Format : '" + nameID + "'");
			logger.debug("Authn Class Ctx : '" + authnCtx + "'");
		}
		
		Saml2Trust trust = this.trusts.get(issuer);
		
		if (trust == null) {
			StringBuffer b = new StringBuffer();
			b.append("Could not find a trust for issuer '").append(issuer).append("'");
			throw new Exception(b.toString());
		}
		
		String authnSig = request.getParameter("Signature");
		if (authnSig != null) {
			String sigAlg = request.getParameter("SigAlg");
			StringBuffer query = new StringBuffer();
			query.append("SAMLRequest=").append(URLEncoder.encode(request.getParameter("SAMLRequest"),"UTF-8"));
			if (relayState != null) {
				query.append("&RelayState=").append(URLEncoder.encode(relayState,"UTF-8"));
			}
			query.append("&SigAlg=").append(URLEncoder.encode(sigAlg,"UTF-8"));
			
			String validationCert = trust.spSigCert;
			UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
			java.security.cert.X509Certificate cert = holder.getConfig().getCertificate(validationCert);
			
			if (! Saml2Idp.xmlDigSigAlgs.containsKey(sigAlg)  ) {
				throw new Exception("Invalid signature algorithm : " + sigAlg);
			}
			
			if (! authn.getDestination().equals(request.getRequestURL().toString())) {
				throw new Exception("Invalid destination");
			}
			
			Signature sigv = Signature.getInstance(Saml2Idp.javaDigSigAlgs.get(sigAlg));
			
			
			
			sigv.initVerify(cert.getPublicKey());
			sigv.update(query.toString().getBytes("UTF-8"));
			
			if (! sigv.verify(Base64.decodeBase64(authnSig.getBytes("UTF-8")))) {
				throw new Exception("Signature verification failed");
			}
			
		} else if (this.requireSignedAuthn) {
			throw new Exception("No signature on the authentication request");
		}
		
		doFederation(request, response, issuer, nameID, authnCtx, url,relayState,trust);
	}

	private void doFederation(HttpServletRequest request,
			HttpServletResponse response, String issuer, String nameID,
			String authnCtx, String url, String relayState,Saml2Trust trust) throws Exception, ServletException,
			IOException {
		
		
		if (authnCtx == null) {
			authnCtx = trust.params.get("defaultAuthCtx").getValues().get(0);
		}
		
		if (nameID == null) {
			nameID = trust.params.get("defaultNameId").getValues().get(0);
		}
		
		
		
		String authChain = trust.authChainMap.get(authnCtx);
		
		if (authChain == null) {
			StringBuffer b = new StringBuffer();
			b.append("IdP does not have an authenticaiton chain configured with '").append(authnCtx).append("'");
			throw new Exception(b.toString());
		}
		
		String nameIDAttr = trust.nameIDMap.get(nameID);
		
		if (logger.isDebugEnabled()) {
			logger.debug("Auth Chain : '" + authChain + "'");
			logger.debug("NameID Attr : '" + nameIDAttr + "'");
		}
		
		HttpSession session = request.getSession();
		
		AuthInfo authData = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		AuthChainType act = holder.getConfig().getAuthChains().get(authChain);
		
		if (url == null) {
			url = trust.params.get("httpPostRespURL").getValues().get(0);
		}
		
		SamlTransaction transaction = new SamlTransaction();
		transaction.issuer = issuer;
		transaction.nameIDAttr = nameIDAttr;
		transaction.nameIDFormat = nameID;
		transaction.postToURL = url;
		transaction.authnCtxName = authnCtx;
		transaction.relayState = relayState;
		
		session.setAttribute(Saml2Idp.TRANSACTION_DATA, transaction);
		
		
		
		
		
		if (authData == null || ! authData.isAuthComplete() && ! (authData.getAuthLevel() < act.getLevel()) ) {
			nextAuth(request,response,session,false,act);
		} else {
			if (authData.getAuthLevel() < act.getLevel()) {
				//step up authentication, clear existing auth data
				/*AuthController controller = ((AuthController) session.getAttribute(AuthSys.AUTH_CTL));
				controller.setHolder(null);
				for (AuthStep as : controller.getAuthSteps()) {
					as.setExecuted(false);
					as.setSuccess(false);
				}*/
				
				session.removeAttribute(ProxyConstants.AUTH_CTL);
				holder.getConfig().createAnonUser(session);
				
				nextAuth(request,response,session,false,act);
			} else {
				//chain.doFilter(req, resp);
				//next.nextSys((HttpServletRequest) req, (HttpServletResponse) resp);
				StringBuffer b = genFinalURL(request);
				response.sendRedirect(b.toString());
				
			}
		}
	}

	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {
		
		
		
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		
		processPostAuthnReq(request, response, factory);
	}

	@Override
	public void doPut(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {
		// TODO Auto-generated method stub

	}

	@Override
	public void doHead(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {
		// TODO Auto-generated method stub

	}

	@Override
	public void doOptions(HttpServletRequest request,
			HttpServletResponse response) throws IOException, ServletException {
		// TODO Auto-generated method stub

	}

	@Override
	public void doDelete(HttpServletRequest request,
			HttpServletResponse response) throws IOException, ServletException {
		// TODO Auto-generated method stub

	}

	


	private String inflate(String saml) throws Exception {
		byte[] compressedData = Base64.decodeBase64(saml);
		ByteArrayInputStream bin = new ByteArrayInputStream(compressedData);
		
		InflaterInputStream decompressor  = new InflaterInputStream(bin,new Inflater(true));
		//decompressor.setInput(compressedData);
		
		// Create an expandable byte array to hold the decompressed data
		ByteArrayOutputStream bos = new ByteArrayOutputStream(compressedData.length);
		
		// Decompress the data
		byte[] buf = new byte[1024];
		int len;
		while ((len = decompressor.read(buf)) > 0) {
		    
		        
		        bos.write(buf, 0, len);
		    
		}
		try {
		    bos.close();
		} catch (IOException e) {
		}

		// Get the decompressed data
		byte[] decompressedData = bos.toByteArray();
		
		String decoded = new String(decompressedData);
		
		return decoded;
	}

	@Override
	public void init(String idpName,ServletContext ctx, HashMap<String, Attribute> init,
			HashMap<String, HashMap<String, Attribute>> trustCfg,MapIdentity mapper) {
		
		this.idpName = idpName;
		this.idpSigKeyName = init.get("sigKey").getValues().get(0);
		this.requireSignedAuthn = init.get("requireSignedAuthn") != null && Boolean.parseBoolean(init.get("requireSignedAuthn").getValues().get(0));
		this.saml2PostTemplate = init.get("postTemplate") != null ? init.get("postTemplate").getValues().get(0) : Saml2Idp.DEFAULT_SAML2_POST_TEMPLATE;
		try {
			InitializationService.initialize();
		} catch (InitializationException e) {
			logger.warn("Could not initialize opensaml",e);
		}
		
		this.trusts = new HashMap<String,Saml2Trust>();
		
		
		
		for (String name : trustCfg.keySet()) {
			
			HashMap<String,Attribute> trust = trustCfg.get(name);
			Saml2Trust samlTrust = new Saml2Trust();
			
			this.trusts.put(name, samlTrust);
			
			samlTrust.params = trust;
			samlTrust.name = name;
			
			
			samlTrust.encAssertion = trust.get("encAssertion") != null && Boolean.parseBoolean(trust.get("encAssertion").getValues().get(0));
			samlTrust.signAssertion = trust.get("signAssertion") != null && Boolean.parseBoolean(trust.get("signAssertion").getValues().get(0));
			samlTrust.signResponse = trust.get("signResponse") != null && Boolean.parseBoolean(trust.get("signResponse").getValues().get(0));
			
			samlTrust.spEncCert = trust.get("spEncKey").getValues().get(0);
			samlTrust.spSigCert = trust.get("spSigKey").getValues().get(0);
			
			samlTrust.authChainMap = new HashMap<String,String>();
			samlTrust.nameIDMap = new HashMap<String,String>();
			
			Attribute attr = trust.get("nameIdMap");
			
			for (String val : attr.getValues()) {
				String nameidFormat = val.substring(0,val.indexOf('='));
				String attrName = val.substring(val.indexOf('=') + 1);
				
				samlTrust.nameIDMap.put(nameidFormat, attrName);
			}
			
			attr = trust.get("authCtxMap");
			
			for (String val : attr.getValues()) {
				String ctxType = val.substring(0,val.indexOf('='));
				String authchain = val.substring(val.indexOf('=') + 1);
				
				samlTrust.authChainMap.put(ctxType, authchain);
			}
		}
		
		this.mapper = mapper;
		
	}
	
	private boolean nextAuth(HttpServletRequest req,HttpServletResponse resp,HttpSession session,boolean jsRedirect,AuthChainType act) throws ServletException, IOException {
		//HttpSession session = req.getSession(true);
		
		RequestHolder reqHolder;
		
		UrlHolder holder = (UrlHolder) req.getAttribute(ProxyConstants.AUTOIDM_CFG);
		String urlChain = holder.getUrl().getAuthChain();
		
		
		StringBuffer b = genFinalURL(req);
		
		
		return holder.getConfig().getAuthManager().execAuth(req, resp, session, jsRedirect, holder, act,b.toString());
	}

	private StringBuffer genFinalURL(HttpServletRequest req) {
		if (logger.isDebugEnabled()) {
			logger.debug("url : '" + req.getRequestURL() + "'");
		}
		
		ConfigManager cfg = (ConfigManager) req.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		
		String url = req.getRequestURL().substring(0,req.getRequestURL().indexOf("/",8));
		StringBuffer b = new StringBuffer(url);
		b.append(cfg.getAuthIdPPath()).append(this.idpName).append("/completeFed");
		
		if (logger.isDebugEnabled()) {
			logger.debug("final url : '" + b + "'");
		}
		return b;
	}

	private void postResponse(final SamlTransaction transaction,
			HttpServletRequest request, HttpServletResponse response,
			AuthInfo authInfo, UrlHolder holder) throws MalformedURLException,
			ServletException, UnsupportedEncodingException, IOException {
		
		User mapped = null;
		try {
			
			if (authInfo.getAttribs().get(transaction.nameIDAttr) == null) {
				StringBuffer b = new StringBuffer();
				b.append("No attribute mapping for '").append(transaction.nameIDAttr).append("'");
				throw new ServletException(b.toString());
			}
			
			User orig = new User(authInfo.getAttribs().get(transaction.nameIDAttr).getValues().get(0));
			orig.getAttribs().putAll(authInfo.getAttribs());
			mapped = this.mapper.mapUser(orig);
		} catch (Exception e) {
			throw new ServletException("Could not map user",e);
		}
		
		
		
		String subject = authInfo.getAttribs().get(transaction.nameIDAttr).getValues().get(0);
		
		Saml2Trust trust = trusts.get(transaction.issuer);
		
		if (transaction.authnCtxName == null) {
			transaction.authnCtxName = trust.params.get("defaultAuthCtx").getValues().get(0);
		}
		
		PrivateKey pk = holder.getConfig().getPrivateKey(this.idpSigKeyName);
		java.security.cert.X509Certificate cert = holder.getConfig().getCertificate(this.idpSigKeyName);
		java.security.cert.X509Certificate spEncCert = holder.getConfig().getCertificate(trust.spEncCert);
		
		StringBuffer issuer = new StringBuffer();
		URL url = new URL(request.getRequestURL().toString());
		
		if (request.isSecure()) {
			issuer.append("https://");
		} else {
			issuer.append("http://");
		}
		
		issuer.append(url.getHost());
		
		if (url.getPort() != -1) {
			issuer.append(':').append(url.getPort());
		}
		
		
		ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		//issuer.append(holder.getUrl().getUri());
		issuer.append(cfg.getAuthIdPPath()).append(this.idpName);
		
		Saml2Assertion resp = new Saml2Assertion(subject,pk,cert,spEncCert,issuer.toString(),transaction.postToURL,transaction.issuer,trust.signAssertion,trust.signResponse,trust.encAssertion,transaction.nameIDFormat,transaction.authnCtxName);
		
		for (String attrName : mapped.getAttribs().keySet()) {
			resp.getAttribs().add(mapped.getAttribs().get(attrName));
		}
		
		//resp.getAttribs().add(new Attribute("groups","admin"));
		
		String respXML = "";
		
		try {
			respXML = resp.generateSaml2Response();
		} catch (Exception e) {
			throw new ServletException("Could not generate SAMLResponse",e);
		}
		
		if (logger.isDebugEnabled()) {
			logger.debug(respXML);
		}
		
		String base64 = Base64.encodeBase64String(respXML.getBytes("UTF-8"));
		
		request.setAttribute("postdata", base64);
		request.setAttribute("postaction", transaction.postToURL);
		
		if (transaction.relayState != null) {
			request.setAttribute("relaystate", transaction.relayState);
		} else {
			request.setAttribute("relaystate", "");
		}
		

		


		
		ST st = new ST(this.saml2PostTemplate,'$','$');
		st.add("relaystate", (String) request.getAttribute("relaystate"));
		st.add("postdata",base64);
		st.add("postaction",transaction.postToURL);
		response.setContentType("text/html");
		response.getWriter().write(st.render());
		
		
		
		
	}
	
	
	private void postErrorResponse(final SamlTransaction transaction,
			HttpServletRequest request, HttpServletResponse response,
			AuthInfo authInfo, UrlHolder holder) throws MalformedURLException,
			ServletException, UnsupportedEncodingException, IOException {
		
		
		
		
		
		
		
		Saml2Trust trust = trusts.get(transaction.issuer);
		
		
		
		PrivateKey pk = holder.getConfig().getPrivateKey(this.idpSigKeyName);
		java.security.cert.X509Certificate cert = holder.getConfig().getCertificate(this.idpSigKeyName);
		java.security.cert.X509Certificate spEncCert = holder.getConfig().getCertificate(trust.spEncCert);
		
		StringBuffer issuer = new StringBuffer();
		URL url = new URL(request.getRequestURL().toString());
		
		if (request.isSecure()) {
			issuer.append("https://");
		} else {
			issuer.append("http://");
		}
		
		issuer.append(url.getHost());
		
		if (url.getPort() != -1) {
			issuer.append(':').append(url.getPort());
		}
		
		
		ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		//issuer.append(holder.getUrl().getUri());
		issuer.append(cfg.getAuthIdPPath()).append(this.idpName);
		
		Saml2Assertion resp = new Saml2Assertion(null,pk,cert,spEncCert,issuer.toString(),transaction.postToURL,transaction.issuer,trust.signAssertion,trust.signResponse,trust.encAssertion,transaction.nameIDFormat,transaction.authnCtxName);
		
		
		
		//resp.getAttribs().add(new Attribute("groups","admin"));
		
		String respXML = "";
		
		try {
			respXML = resp.generateSaml2Response();
		} catch (Exception e) {
			throw new ServletException("Could not generate SAMLResponse",e);
		}
		
		if (logger.isDebugEnabled()) {
			logger.debug(respXML);
		}
		
		String base64 = Base64.encodeBase64String(respXML.getBytes("UTF-8"));
		
		request.setAttribute("postdata", base64);
		request.setAttribute("postaction", transaction.postToURL);
		
		if (transaction.relayState != null) {
			request.setAttribute("relaystate", transaction.relayState);
		} else {
			request.setAttribute("relaystate", "");
		}
		

		


		
		ST st = new ST(this.saml2PostTemplate,'$','$');
		st.add("relaystate", (String) request.getAttribute("relaystate"));
		st.add("postdata",base64);
		st.add("postaction",transaction.postToURL);
		response.setContentType("text/html");
		response.getWriter().write(st.render());
		
		
		
		
	}
}

class Saml2Trust {
	public String spSigCert;
	
	String name;
	HashMap<String,Attribute> params;
	HashMap<String,String> nameIDMap;
	HashMap<String,String> authChainMap;
	String spEncCert;
	boolean signAssertion;
	boolean signResponse;
	boolean encAssertion;
}

class SamlTransaction implements Serializable {

	public String relayState;

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	String postToURL;
	String nameIDFormat;
	String nameIDAttr;
	String authnCtxName;
	String issuer;
	
	
}

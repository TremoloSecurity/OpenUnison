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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.StringTokenizer;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.security.cert.X509Certificate;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.Logger;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnRequestMarshaller;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutRequestUnmarshaller;
import org.opensaml.saml.saml2.core.impl.LogoutResponseUnmarshaller;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.saml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.proxy.TremoloHttpSession;
import com.tremolosecurity.proxy.auth.saml2.Saml2SingleLogout;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.auth.util.AuthUtil;
import com.tremolosecurity.proxy.logout.LogoutUtil;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.proxy.util.OpenSAMLUtils;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.proxy.util.ProxyTools;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;




public class SAML2Auth implements AuthMechanism {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(SAML2Auth.class);

	ConfigManager cfgMgr;

	private SecureRandom random;
	
	

	String defaultRelayState;


	private HashMap<String, String> defaultRelayStates;
	
	public static HashMap<String,String> xmlDigSigAlgs;
	public static HashMap<String,String> javaDigSigAlgs;
	
	static {
		xmlDigSigAlgs = new HashMap<String,String>();
		xmlDigSigAlgs.put("RSA-SHA1", "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
		xmlDigSigAlgs.put("RSA-SHA256", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
		xmlDigSigAlgs.put("RSA-SHA384", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384");
		xmlDigSigAlgs.put("RSA-SHA512", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
		
		javaDigSigAlgs = new HashMap<String,String>();
		javaDigSigAlgs.put("RSA-SHA1", "SHA1withRSA");
		javaDigSigAlgs.put("RSA-SHA256", "SHA256withRSA");
		javaDigSigAlgs.put("RSA-SHA384", "SHA384withRSA");
		javaDigSigAlgs.put("RSA-SHA512", "SHA512withRSA");
		
	}
	

	
	@Override
	public void doGet(HttpServletRequest req, HttpServletResponse resp,AuthStep as)
			throws ServletException, IOException {
		HttpSession session = req.getSession(true);

		if (req.getParameter("SAMLResponse") != null) {
			String[] resps = req.getParameterValues("SAMLResponse");

			if (logger.isDebugEnabled()) {
				for (int i = 0; i < resps.length; i++) {
					logger.debug(resps[i]);
				}
			}
			
			String b64resp = resps[0];
			
			
		} else {
			RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
			
			HashMap<String, Attribute> authParams = (HashMap<String, Attribute>) session
					.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
			
			Attribute jumpPage = authParams.get("jumpPage");
			if (jumpPage != null && jumpPage.getValues().size() == 1 && ! jumpPage.getValues().get(0).isEmpty()) {
				
				if (logger.isDebugEnabled()) {
					Enumeration enumer = req.getHeaderNames();
					while (enumer.hasMoreElements()) {
						String name = (String) enumer.nextElement();
						logger.debug("Header '" + name + "'='" + req.getHeader(name) + "'");
					}
				}
				
				//String referer = req.getHeader("Referer");
				
				
				String isJump = req.getParameter("isJump");
				if (isJump != null && isJump.equalsIgnoreCase("true")) {
					logger.debug("initializing SSO");
					this.initializeSSO(req, resp, session,false,null);
				} else {
					

					this.initializeSSO(req, resp, session,true,jumpPage.getValues().get(0));

				}
			} else {
				this.initializeSSO(req, resp, session,false,null);
			}
		}
			
	}

	public void initializeSSO(HttpServletRequest req, HttpServletResponse resp,
			HttpSession session,boolean isJump,String jumpPage) throws MalformedURLException, ServletException {
		{
			RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
			
			HashMap<String, Attribute> authParams = (HashMap<String, Attribute>) session
					.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
			
			
			boolean isMultiIdp = authParams.get("isMultiIdP") != null && authParams.get("isMultiIdP").getValues().get(0).equalsIgnoreCase("true");
			
			String postAuthnReqTo = "";
			String redirAuthnReqTo = "";
			String assertionConsumerServiceURL = "";
			boolean signAuthnReq = false;
			
			String uri = (String) req.getAttribute(ProxyConstants.AUTH_REDIR_URI);
			if (uri == null) {
				uri = req.getRequestURI();
			}
			
			if (isMultiIdp) {
				
				URL url = new URL(req.getRequestURL().toString());
				String hostName = url.getHost();
				String dn = authParams.get("idpDir").getValues().get(0);
				
				try {
					StringBuffer b = new StringBuffer();
					
					LDAPSearchResults res = cfgMgr.getMyVD().search(dn, 2, equal("hostname",hostName).toString(), new ArrayList<String>());
					if (! res.hasMore()) {
						throw new ServletException("No IdP found");
					}
					
					LDAPEntry entry = res.next();
					postAuthnReqTo = entry.getAttribute("idpURL").getStringValue();
					
					redirAuthnReqTo = entry.getAttribute("idpRedirURL").getStringValue();
					
					assertionConsumerServiceURL = ProxyTools.getInstance().getFqdnUrl(uri,req);
					signAuthnReq = entry.getAttribute("signAuthnReq").getStringValue().equalsIgnoreCase("1");
					
					
				} catch (LDAPException e) {
					throw new ServletException("Could not load IdP data",e);
				}
				
				
			} else {
				postAuthnReqTo = authParams.get("idpURL").getValues().get(0);// "http://idp.partner.domain.com:8080/opensso/SSOPOST/metaAlias/testSaml2Idp";
				
					redirAuthnReqTo = authParams.get("idpRedirURL").getValues().get(0);
				
				assertionConsumerServiceURL = ProxyTools.getInstance().getFqdnUrl(uri,req);// "http://sp.localdomain.com:8080/SampleSP/echo";
				
				if (authParams.get("forceToSSL") != null && authParams.get("forceToSSL").getValues().get(0).equalsIgnoreCase("true")) {
					if (! assertionConsumerServiceURL.startsWith("https")) {
						assertionConsumerServiceURL = assertionConsumerServiceURL.replace("http://", "https://");
					}
				}
				
				signAuthnReq = authParams.get("signAuthnReq") != null && authParams.get("signAuthnReq").getValues().get(0).equalsIgnoreCase("true");
			}

			ConfigManager cfg = (ConfigManager) req.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
			
			
			
			AuthnRequestBuilder authnBuilder = new AuthnRequestBuilder();
			AuthnRequest authn = authnBuilder.buildObject();
			authn.setAssertionConsumerServiceURL(assertionConsumerServiceURL);
			authn.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
			//authn.setDestination(postAuthnReqTo);
			authn.setDestination(redirAuthnReqTo);
			DateTime dt = new DateTime();
		
			String authMechanism = authParams.get("authCtxRef").getValues().get(0);
			

			byte[] idBytes = new byte[20];
			random.nextBytes(idBytes);
			
			
			/*StringBuffer id = new StringBuffer();
			for (byte b : idBytes) {
				id.append(Hex.encode(idBytes));
			}*/
			
			StringBuffer b = new StringBuffer();
			b.append('f').append(Hex.encodeHexString(idBytes));
			
			String id = b.toString();
			
			
			authn.setIssueInstant(dt);
			//authn.setID(Long.toString(random.nextLong()));
			authn.setID(id.toString());
			session.setAttribute("AUTOIDM_SAML2_REQUEST", authn.getID());
			IssuerBuilder ib = new IssuerBuilder();
			Issuer issuer = ib.buildObject();
			issuer.setValue(assertionConsumerServiceURL);

			authn.setIssuer(issuer);
			//authn.setAssertionConsumerServiceIndex(0);
			//authn.setAttributeConsumingServiceIndex(0);
			
			NameIDPolicyBuilder nidbpb = new NameIDPolicyBuilder();
			NameIDPolicy nidp = nidbpb.buildObject();
			//nidp.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified");
			nidp.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
			nidp.setAllowCreate(true);
			nidp.setSPNameQualifier(assertionConsumerServiceURL);
			//authn.setNameIDPolicy(nidp);
			
			authn.setIsPassive(false);
			//authn.setProviderName("tremolosecurity.com");
			
			
			if (! authMechanism.isEmpty() && ! authMechanism.equalsIgnoreCase("none")) {
				AuthnContextClassRefBuilder accrb = new AuthnContextClassRefBuilder();
				AuthnContextClassRef accr = accrb.buildObject();
				 
				accr.setAuthnContextClassRef(authMechanism);
				
				//accr.setAuthnContextClassRef("urn:federation:authentication:windows");
				//accr.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
				
				RequestedAuthnContextBuilder racb = new RequestedAuthnContextBuilder();
				RequestedAuthnContext rac = racb.buildObject();
				rac.getAuthnContextClassRefs().add(accr);
				rac.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
				authn.setRequestedAuthnContext(rac);
			}
			
			authn.setForceAuthn(false);
			
			

			try {
				// Get the Subject marshaller
				Marshaller marshaller = new AuthnRequestMarshaller();

				// Marshall the Subject
				//Element assertionElement = marshaller.marshall(authn);

				String xml = OpenSAMLUtils.xml2str(authn);
				xml = xml.substring(xml.indexOf("?>") + 2);
				
				

				if (logger.isDebugEnabled()) {
					logger.debug("=======AuthnRequest============");
					logger.debug(xml);
					logger.debug("=======AuthnRequest============");
				}

				
				
				byte[] bxml = xml.getBytes("UTF-8");

				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				
				DeflaterOutputStream compressor  = new DeflaterOutputStream(baos,new Deflater(Deflater.BEST_COMPRESSION,true));
				
				compressor.write(bxml);
				compressor.flush();
				compressor.close();
				
				
				
				String b64 = new String( Base64.encodeBase64(baos.toByteArray()));
				StringBuffer redirURL = new StringBuffer();
				StringBuffer query = new StringBuffer();
				
				idBytes = new byte[20];
				random.nextBytes(idBytes);
				
				
				query.append("SAMLRequest=").append(URLEncoder.encode(b64,"UTF-8")).append("&RelayState=").append(URLEncoder.encode(Hex.encodeHexString(idBytes),"UTF-8"));
				
				
				if (signAuthnReq) {
					
					String sigAlg = authParams.get("sigAlg") != null ? authParams.get("sigAlg").getValues().get(0) : "RSA-SHA1";
					
					String xmlSigAlg = SAML2Auth.xmlDigSigAlgs.get(sigAlg);
					String javaSigAlg = SAML2Auth.javaDigSigAlgs.get(sigAlg);
					
					//sb.append("SAMLRequest=").append(xml).append("&SigAlg=").append(URLEncoder.encode("http://www.w3.org/2000/09/xmldsig#rsa-sha1", "UTF-8"));
					query.append("&SigAlg=").append(URLEncoder.encode(xmlSigAlg,"UTF-8"));
					
					
					java.security.Signature signer = java.security.Signature.getInstance(javaSigAlg);
					
					if (authParams.get("spSigKey") == null) {
						throw new ServletException("No signature certificate specified");
					}
					String spSigKey = authParams.get("spSigKey").getValues().get(0);
					
					signer.initSign(cfgMgr.getPrivateKey(spSigKey));
					signer.update(query.toString().getBytes("UTF-8"));
					String base64Sig = new String(Base64.encodeBase64(signer.sign()));
					query.append("&Signature=").append(URLEncoder.encode(base64Sig,"UTF-8"));
				}
				
				redirURL.append(redirAuthnReqTo).append("?").append(query.toString());
				
				
				
			
				
				
				if (isJump) {
					if (logger.isDebugEnabled()) {
						logger.debug("Redirecting to Jump Page");
						logger.debug("SAML2_JUMPPAGE='" + req.getAttribute("TREMOLO_AUTH_REDIR_URI"));
					}
					
					session.setAttribute("SAML2_JUMPPAGE", redirURL.toString());
					resp.sendRedirect(jumpPage);
				} else {
					resp.sendRedirect(redirURL.toString());
				}
				
				
				/*String b64 = new String(
						org.apache.directory.shared.ldap.util.Base64
								.encode(bxml));

				req.setAttribute("postaction", postAuthnReqTo);
				req.setAttribute("postdata", b64);
				req.getRequestDispatcher("/auth/fed/postauthnreq.jsp").forward(
						req, resp);*/

			} catch (Exception e) {
				throw new ServletException(
						"Error generating new authn request", e);
			}
		}
	}

	@Override
	public void doPost(HttpServletRequest req, HttpServletResponse resp,AuthStep as)
			throws ServletException, IOException {

		
		
		MyVDConnection myvd = cfgMgr.getMyVD();
		// HttpSession session = (HttpSession)
		// req.getAttribute(ConfigFilter.AUTOIDM_SESSION);//((HttpServletRequest)
		// req).getSession();
		// //SharedSession.getSharedSession().getSession(req.getSession().getId());
		HttpSession session = ((HttpServletRequest) req).getSession(); // SharedSession.getSharedSession().getSession(req.getSession().getId());
		UrlHolder holder = (UrlHolder) req.getAttribute(ProxyConstants.AUTOIDM_CFG);
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(urlChain);
		
		AuthInfo userData = ((AuthController) req.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
		
		if (userData.isAuthComplete() && userData.getAuthLevel() > 0) {
			//Session is already set, just redirect to relay state
			String relayState = this.getFinalURL(req, resp);
			if (relayState == null) {
				throw new ServletException("No RelayState or default RelayState");
			}
			
			resp.sendRedirect(relayState);
			return;
		}
		
		if (as == null) {
			//this is a special case - idp initiated means there's no context
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
		
		
		HashMap<String, Attribute> authParams = (HashMap<String, Attribute>) session
				.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);

		String defaultOC = authParams.get("defaultOC").getValues().get(0);
		
		String spEncKey = null;
		if (authParams.get("spEncKey") != null) {
			spEncKey = authParams.get("spEncKey").getValues().get(0);
		} 
		 
		
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		

		
		

		AuthMechType amt = act.getAuthMech().get(as.getId());

		String sigCertName = authParams.get("idpSigKeyName").getValues().get(0);
		java.security.cert.X509Certificate sigCert = null;
		
		boolean isMultiIdp = authParams.get("isMultiIdP") != null && authParams.get("isMultiIdP").getValues().get(0).equalsIgnoreCase("true");
		
		

		String ldapAttrib = authParams.get("ldapAttribute").getValues().get(0);
		String dnLabel = authParams.get("dnOU").getValues().get(0);

		String samlResp = req.getParameter("SAMLResponse");
		String xml = null;
		
		xml = new String(Base64.decodeBase64(samlResp), "UTF-8");
		

		
		boolean assertionSigned = true;
		if (authParams.get("assertionsSigned") != null) {
			assertionSigned = Boolean.parseBoolean(authParams.get("assertionsSigned").getValues().get(0));
		}
		
		boolean responseSigned = false;
		if (authParams.get("responsesSigned") != null) {
			responseSigned = Boolean.parseBoolean(authParams.get("responsesSigned").getValues().get(0));
		}
		
		boolean assertionEncrypted = false;
		if (authParams.get("assertionEncrypted") != null) {
			assertionEncrypted = Boolean.parseBoolean(authParams.get("assertionEncrypted").getValues().get(0));
		}
		
		if (logger.isDebugEnabled()) {
			logger.debug("=========saml2resp============");
			logger.debug(xml);
			logger.debug("=========saml2resp============");
		}


		xml = xml.replaceAll("<!--.*-->", "");

		
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		try {
			DocumentBuilder builder = factory.newDocumentBuilder();

			Element root = builder
					.parse(new InputSource(new StringReader(xml)))
					.getDocumentElement();

			
			
			Response samlResponse = (Response) XMLObjectSupport.getUnmarshaller(root)
					.unmarshall(root);
			
			if (isMultiIdp) {
				
				
				try {
					String dn = authParams.get("idpDir").getValues().get(0);
					
					
					
					
					
					LDAPSearchResults res = cfgMgr.getMyVD().search(dn, 2, equal("issuer",samlResponse.getIssuer().getValue()).toString() , new ArrayList<String>());
					if (! res.hasMore()) {
						throw new ServletException("No IdP found");
					}
					
					LDAPEntry entry = res.next();
					java.security.cert.CertificateFactory cf= java.security.cert.CertificateFactory.getInstance("X.509");
					sigCert = (java.security.cert.X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.decodeBase64(entry.getAttribute("idpSig").getStringValue())));
					
					
				} catch (LDAPException e) {
					throw new ServletException("Could not load IdP data",e);
				} catch (CertificateException e) {
					throw new ServletException("Could not load IdP data",e);
				} 
			} else {
				sigCert = cfgMgr.getCertificate(sigCertName);
			}
			
			if (responseSigned) {
				if (samlResponse.getSignature() != null) {
					BasicCredential sigCred = new BasicCredential(sigCert.getPublicKey());
					sigCred.setUsageType(UsageType.SIGNING);

					try {
						SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
			            profileValidator.validate(samlResponse.getSignature());
			            SignatureValidator.validate(samlResponse.getSignature(), sigCred);
					} catch (org.opensaml.xmlsec.signature.support.SignatureException se) {
						throw new ServletException("Error validating response signature", se);
					}
					
					

				} else {
					throw new Exception("Response not signed");
				}
			}
			
			Assertion assertion = null;
			
			if (samlResponse.getEncryptedAssertions().size() > 0) {
				try {
					EncryptedAssertion encAssertion = samlResponse.getEncryptedAssertions().get(0);
					PrivateKey privKey = this.cfgMgr.getPrivateKey(spEncKey);
					
					PublicKey pubKey = this.cfgMgr.getCertificate(spEncKey).getPublicKey();
					Credential credential = new BasicCredential(pubKey, privKey);
					StaticKeyInfoCredentialResolver resolver = new StaticKeyInfoCredentialResolver(credential); 
					Decrypter decrypter = new Decrypter(null, resolver, new InlineEncryptedKeyResolver());
					decrypter.setRootInNewDocument(true);
			        assertion = decrypter.decrypt(encAssertion);
			        
			        
			        
				} catch (Exception e) {
					throw new ServletException("Error decrypting assertion",e);
				}
			} else {
				if (assertionEncrypted) {
					throw new Exception("Assertion not encrypted");
				}
				
				if (samlResponse.getAssertions().size() == 0) {
					throw new Exception("No assertions found");
				}
				
				assertion = (Assertion) samlResponse.getAssertions().get(0);
			}
			 

			if (assertionSigned) {
				if (assertion.getSignature() != null) {
					
					BasicCredential sigCred = new BasicCredential(sigCert.getPublicKey());
					sigCred.setUsageType(UsageType.SIGNING);

					try {
						SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
			            profileValidator.validate(assertion.getSignature());
			            SignatureValidator.validate(assertion.getSignature(), sigCred);
					} catch (org.opensaml.xmlsec.signature.support.SignatureException se) {
						throw new ServletException("Error validating response signature", se);
					}
					

	
			
					
	
				} else {
					throw new Exception("No assertion signature");
				}
			
			}
			
			//If it made it here, the assertion is valid, lets check the authncontextclassref
			Attribute authnContextClassRef = authParams.get("authCtxRef");
			
			if (authnContextClassRef != null && authnContextClassRef.getValues().size() > 0 && ! authnContextClassRef.getValues().get(0).isEmpty() && ! authnContextClassRef.getValues().get(0).equalsIgnoreCase("none") && (assertion.getAuthnStatements() == null ||
					assertion.getAuthnStatements().size() == 0 ||
					assertion.getAuthnStatements().get(0).getAuthnContext() == null ||
					assertion.getAuthnStatements().get(0).getAuthnContext().getAuthnContextClassRef() == null || 
							assertion.getAuthnStatements().get(0).getAuthnContext() == null ||
							assertion.getAuthnStatements().get(0).getAuthnContext().getAuthnContextClassRef() == null ||
							assertion.getAuthnStatements().get(0).getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef() == null ||
							! assertion.getAuthnStatements().get(0).getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef().equalsIgnoreCase(authnContextClassRef.getValues().get(0))
					)) {
				logger.warn("Can not validate the authentication context classref");
				as.setSuccess(false);
				holder.getConfig().getAuthManager().nextAuth(req, resp, session,false);
				return;
			}
			
			try {
				if (authParams.get("dontLinkToLDAP") == null || authParams.get("dontLinkToLDAP").getValues().get(0).equalsIgnoreCase("false")) {
					StringBuffer filter = new StringBuffer();
					filter.append('(').append(ldapAttrib).append('=').append(assertion.getSubject().getNameID().getValue()).append(')');
					
					LDAPSearchResults res = myvd.search(AuthUtil.getChainRoot(cfgMgr,act), 2, filter.toString(), new ArrayList<String>());
	
					if (res.hasMore()) {
						createUserFromDir(session, act, ldapAttrib, assertion,
								res);
					} else {
						createUnlinkedUser(session, act, ldapAttrib, dnLabel,
								defaultOC, assertion);
					}
				} else {
					createUnlinkedUser(session, act, ldapAttrib, dnLabel,
							defaultOC, assertion);
				}
			} catch (LDAPException e) {
				if (e.getResultCode() == 32) {
					createUnlinkedUser(session, act, ldapAttrib, dnLabel,
							defaultOC, assertion);
				} else {
					throw e;
				}
			}
			
			//logout management
			Attribute logoutURLAttr = authParams.get("idpRedirLogoutURL");
			if (logoutURLAttr != null && logoutURLAttr.getValues().size() > 0 && ! logoutURLAttr.getValues().get(0).isEmpty() && authParams.get("spSigKey") != null && authParams.get("spSigKey").getValues().size() > 0) {
				String logoutURL = logoutURLAttr.getValues().get(0);
				String sessionIndex = assertion.getAuthnStatements().get(0).getSessionIndex();
				String nameID = assertion.getSubject().getNameID().getValue();
				String nameIDFormat = assertion.getSubject().getNameID().getFormat();
				
				
				
				
				Saml2SingleLogout handler = new Saml2SingleLogout(logoutURL,sessionIndex,nameID,nameIDFormat,samlResponse.getDestination(),authParams.get("spSigKey").getValues().get(0),authParams.get("sigAlg").getValues().get(0));
				LogoutUtil.addLogoutHandler(req, handler);
				
			}

			as.setSuccess(true);
		} catch (Exception e) {
			logger.error("Error Parsing Assertion",e);
			throw new ServletException("error parsing assertion", e);
		}

		
		
		holder.getConfig().getAuthManager().nextAuth(req, resp, session,false);
	}

	private void createUnlinkedUser(HttpSession session, AuthChainType act,
			String ldapAttrib, String dnLabel, String defaultOC,
			Assertion assertion) {
		
		
		StringBuffer b = new StringBuffer();
		b.append(ldapAttrib).append("=").append(assertion.getSubject().getNameID().getValue()).append(",ou=").append(dnLabel).append(",ou=SAML2,").append(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot());
		String dn = b.toString();
		
		AuthInfo authInfo = new AuthInfo(dn,
				(String) session.getAttribute(ProxyConstants.AUTH_MECH_NAME),
				act.getName(), act.getLevel());
		((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).setAuthInfo(authInfo);

		com.tremolosecurity.saml.Attribute attrib = new com.tremolosecurity.saml.Attribute(
				"objectClass", defaultOC);
		authInfo.getAttribs().put(attrib.getName(), attrib);

		attrib = new com.tremolosecurity.saml.Attribute(ldapAttrib, assertion
				.getSubject().getNameID().getValue());
		authInfo.getAttribs().put(attrib.getName(), attrib);

		if (assertion.getAttributeStatements().size() > 0) {
			Iterator<org.opensaml.saml.saml2.core.Attribute> samlAttribs = assertion
					.getAttributeStatements().get(0).getAttributes().iterator();
			while (samlAttribs.hasNext()) {
				org.opensaml.saml.saml2.core.Attribute samlAttrib = samlAttribs
						.next();
				// com.tremolosecurity.saml.Attribute attrib = new
				// com.tremolosecurity.saml.Attribute(samlAttrib.getName());

				attrib = authInfo.getAttribs().get(samlAttrib.getName());
				if (attrib == null) {
					attrib = new com.tremolosecurity.saml.Attribute(
							samlAttrib.getName());
					authInfo.getAttribs().put(attrib.getName(), attrib);
				}

				Iterator<XMLObject> vals = samlAttrib.getAttributeValues()
						.iterator();
				while (vals.hasNext()) {
					XMLObject strVal = vals.next();
					//XSString strVal = (XSString) vals.next();
					if (!attrib.getValues().contains(strVal)) {
						if (strVal instanceof XSString) {
							attrib.getValues().add(((XSString) strVal).getValue());
						} else if (strVal instanceof XSAny) {
							attrib.getValues().add(((XSAny) strVal).getTextContent());
						}
						
					}
				}

			}
		}
	}

	private void createUserFromDir(HttpSession session, AuthChainType act,
			String ldapAttrib, Assertion assertion, LDAPSearchResults res)
			throws LDAPException {
		LDAPEntry entry = res.next();

		Iterator<LDAPAttribute> it = entry.getAttributeSet().iterator();
		AuthInfo authInfo = new AuthInfo(entry.getDN(),
				(String) session.getAttribute(ProxyConstants.AUTH_MECH_NAME),
				act.getName(), act.getLevel());
		((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).setAuthInfo(authInfo);

		com.tremolosecurity.saml.Attribute attrib = new com.tremolosecurity.saml.Attribute(
				ldapAttrib, assertion.getSubject().getNameID().getValue());
		authInfo.getAttribs().put(attrib.getName(), attrib);

		while (it.hasNext()) {
			LDAPAttribute ldapAttr = it.next();
			Attribute attr = new Attribute(ldapAttr.getName());
			String[] vals = ldapAttr.getStringValueArray();
			for (int i = 0; i < vals.length; i++) {
				attr.getValues().add(vals[i]);
			}
			authInfo.getAttribs().put(attr.getName(), attr);
		}

		if (assertion.getAttributeStatements().size() > 0) {
			Iterator<org.opensaml.saml.saml2.core.Attribute> samlAttribs = assertion
					.getAttributeStatements().get(0).getAttributes().iterator();
			while (samlAttribs.hasNext()) {
				org.opensaml.saml.saml2.core.Attribute samlAttrib = samlAttribs
						.next();
				// com.tremolosecurity.saml.Attribute attrib = new
				// com.tremolosecurity.saml.Attribute(samlAttrib.getName());

				attrib = authInfo.getAttribs().get(samlAttrib.getName());
				if (attrib == null) {
					attrib = new com.tremolosecurity.saml.Attribute(
							samlAttrib.getName());
					authInfo.getAttribs().put(attrib.getName(), attrib);
				}

				Iterator<XMLObject> vals = samlAttrib.getAttributeValues()
						.iterator();
				while (vals.hasNext()) {
					XMLObject strVal = vals.next();
					//XSString strVal = (XSString) vals.next();
					if (!attrib.getValues().contains(strVal)) {
						if (strVal instanceof XSString) {
							attrib.getValues().add(((XSString) strVal).getValue());
						} else if (strVal instanceof XSAny) {
							attrib.getValues().add(((XSAny) strVal).getTextContent());
						}
						
					}
				}

			}
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
		this.cfgMgr = (ConfigManager) ctx
				.getAttribute(ProxyConstants.TREMOLO_CONFIG);

		try {
			InitializationService.initialize();
		} catch (InitializationException e1) {
			logger.warn("Could not initialize opensaml",e1);
		}

		try {
			this.random = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			logger.error("could not load secure random");
		}
		
		this.defaultRelayStates = new HashMap<String,String>();
		
		if (init.containsKey("defaultRelayStates")) {
			for (String map : init.get("defaultRelayStates").getValues()) {
				String referer = map.substring(0,map.indexOf('|'));
				String relaystate = map.substring(map.indexOf('|') + 1);
				
				logger.info("Default Relay State - '" + referer + "' --> '" + relaystate + "'");
				this.defaultRelayStates.put(referer, relaystate);
			}
			
			
			
			
		}
		
		

	}

	@Override
	public String getFinalURL(HttpServletRequest request,
			HttpServletResponse response) {
		
		if (request.getMethod().equalsIgnoreCase("GET")) {
			//processing a logout request
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setNamespaceAware(true);
			
			try {
				return processLogoutResp(request,response,factory);
			} catch (ServletException e) {
				logger.error("Could not complete logout request",e);
				return "";
			}
		}
		
		
		String relayState = request.getParameter("RelayState");
			
		
		if (relayState != null) {
			return relayState;
		}
		

		
		String referer = request.getHeader("Referer");
		if (referer != null && referer.indexOf('?') > 0) {
			referer = referer.substring(0,referer.indexOf('?'));
		}
		
		String defaultRS = this.defaultRelayStates.get(referer);
		
		if (defaultRS != null) {
			return defaultRS;

		}
		
		return request.getRequestURL().substring(0,request.getRequestURL().indexOf("/","https://".length()));
	}
	
	private void printXML(Assertion assertion) throws Exception {
		Marshaller marshaller = new ResponseMarshaller();

		// Marshall the Subject
		Element assertionElement = marshaller.marshall(assertion);

		System.out.println( OpenSAMLUtils.xml2str(assertion));
	}
	
	private String processLogoutResp(HttpServletRequest request,
			HttpServletResponse response, DocumentBuilderFactory factory)
			throws ServletException {
		try {
			
			StringBuffer url = new StringBuffer();
			url.append(request.getRequestURL()).append('?').append(request.getQueryString());
			
			boolean isResponse = request.getParameter("SAMLResponse") != null;

			String saml = null;

			if (isResponse) {
				saml = this.inflate(request.getParameter("SAMLResponse"));
			} else {
				saml = this.inflate(request.getParameter("SAMLRequest"));
			}

			
			if (logger.isDebugEnabled()) {
				logger.debug(saml);
			}
			
			
			if (logger.isDebugEnabled()) {
				Enumeration enumer = request.getParameterNames();
				while (enumer.hasMoreElements()) {
					String name = (String) enumer.nextElement();
					if (logger.isDebugEnabled()) {
						logger.debug(name + "=" + request.getParameter(name));
					}
				}
			}
			
			String relayState = request.getParameter("RelayState");
			
			if (isResponse) {
				return procLogoutResp(request, response, factory, saml, relayState,url.toString());
			} else {
				return procLogoutReq(request, response, factory, saml, relayState,url.toString());
			}
			
			
			
			
		} catch (NullPointerException e) {
			throw new ServletException("AuthnRequest is missing elements",e);
		} catch (Exception e) {
			throw new ServletException("Could not parse http-relay request",e);
		}
	}
	
	private String procLogoutResp(HttpServletRequest request,
			HttpServletResponse response, DocumentBuilderFactory factory,
			String saml, String relayState, String url)
			throws ParserConfigurationException, SAXException, IOException,
			UnmarshallingException, Exception, UnsupportedEncodingException,
			NoSuchAlgorithmException, InvalidKeyException, SignatureException,
			ServletException {
		
		
		
		
		LogoutResponseUnmarshaller marshaller = new LogoutResponseUnmarshaller();
		DocumentBuilder builder = factory.newDocumentBuilder();

		Element root = builder
				.parse(new InputSource(new StringReader(saml)))
				.getDocumentElement();
		
		LogoutResponse logout = (LogoutResponse) marshaller.unmarshall(root);
		
		String issuer = logout.getIssuer().getValue();
		
		boolean found = false;
		
		String algType = null;
		String logoutURL = null;
		String sigKeyName = null;
		
		//Search for the right mechanism configuration
		for (String chainname : cfgMgr.getAuthChains().keySet()) {
			AuthChainType act = cfgMgr.getAuthChains().get(chainname);
			for (AuthMechType amt : act.getAuthMech()) {
				for (ParamType pt : amt.getParams().getParam()) {
					if (pt.getName().equalsIgnoreCase("entityID") && pt.getValue().equalsIgnoreCase(issuer)) {
						//found the correct mechanism
						found = true;
						
						
						
						
						for (ParamType ptx : amt.getParams().getParam()) {
							if (ptx.getName().equalsIgnoreCase("sigAlg")) {
								algType = ptx.getValue();
							} else if (ptx.getName().equalsIgnoreCase("logoutURL")) {
								logoutURL = ptx.getValue();
							} else if (ptx.getName().equalsIgnoreCase("idpSigKeyName")) {
								sigKeyName = ptx.getValue();
							}
						}
						
						break;
						
					}
				}
				
				if (found) {
					break;
				}
			}
			
			if (found) {
				break;
			}
		}
		
		
		if (! found) {
			throw new ServletException("Entity ID '" + issuer + "' not found");
		}
		
		
		
		
		
		
		
		
		
		String authnSig = request.getParameter("Signature");
		if (authnSig != null) {
			String sigAlg = request.getParameter("SigAlg");
			StringBuffer query = new StringBuffer();
			
			String qs = request.getQueryString();
			query.append(OpenSAMLUtils.getRawQueryStringParameter(qs, "SAMLResponse"));
			query.append('&');
			query.append(OpenSAMLUtils.getRawQueryStringParameter(qs, "RelayState"));
			query.append('&');
			query.append(OpenSAMLUtils.getRawQueryStringParameter(qs, "SigAlg"));
			

			
			
			
			java.security.cert.X509Certificate cert = this.cfgMgr.getCertificate(sigKeyName);
			
			String xmlAlg = SAML2Auth.xmlDigSigAlgs.get(algType);
			
			
			if (! sigAlg.equalsIgnoreCase(xmlAlg)) {
				throw new Exception("Invalid signature algorithm : '" + sigAlg + "'");
			}
			
			/*if (! logout.getDestination().equals(request.getRequestURL().toString())) {
				throw new Exception("Invalid destination");
			}*/
			
			java.security.Signature sigv = java.security.Signature.getInstance(SAML2Auth.javaDigSigAlgs.get(algType));
			
			
			
			sigv.initVerify(cert.getPublicKey());
			sigv.update(query.toString().getBytes("UTF-8"));
			
			if (! sigv.verify(Base64.decodeBase64(authnSig.getBytes("UTF-8")))) {
				throw new Exception("Signature verification failed");
			}
			
		} 
		
		response.sendRedirect(logoutURL);
		
		return logoutURL;
	}

	private String procLogoutReq(HttpServletRequest request,
			HttpServletResponse response, DocumentBuilderFactory factory,
			String saml, String relayState, String url)
			throws ParserConfigurationException, SAXException, IOException,
			UnmarshallingException, Exception, UnsupportedEncodingException,
			NoSuchAlgorithmException, InvalidKeyException, SignatureException,
			ServletException {
		
		
		
		
		LogoutRequestUnmarshaller marshaller = new LogoutRequestUnmarshaller();
		DocumentBuilder builder = factory.newDocumentBuilder();

		Element root = builder
				.parse(new InputSource(new StringReader(saml)))
				.getDocumentElement();
		
				org.opensaml.saml.saml2.core.impl.LogoutRequestImpl logout = (org.opensaml.saml.saml2.core.impl.LogoutRequestImpl) marshaller.unmarshall(root);
		
		String issuer = logout.getIssuer().getValue();
		
		boolean found = false;
		
		String algType = null;
		String logoutURL = null;
		String sigKeyName = null;
		
		//Search for the right mechanism configuration
		for (String chainname : cfgMgr.getAuthChains().keySet()) {
			AuthChainType act = cfgMgr.getAuthChains().get(chainname);
			for (AuthMechType amt : act.getAuthMech()) {
				for (ParamType pt : amt.getParams().getParam()) {
					if (pt.getName().equalsIgnoreCase("entityID") && pt.getValue().equalsIgnoreCase(issuer)) {
						//found the correct mechanism
						found = true;
						
						
						
						
						for (ParamType ptx : amt.getParams().getParam()) {
							if (ptx.getName().equalsIgnoreCase("sigAlg")) {
								algType = ptx.getValue();
							} else if (ptx.getName().equalsIgnoreCase("triggerLogoutURL")) {
								logoutURL = ptx.getValue();
							} else if (ptx.getName().equalsIgnoreCase("idpSigKeyName")) {
								sigKeyName = ptx.getValue();
							}
						}
						
						break;
						
					}
				}
				
				if (found) {
					break;
				}
			}
			
			if (found) {
				break;
			}
		}
		
		
		if (! found) {
			throw new ServletException("Entity ID '" + issuer + "' not found");
		}
		
		
		
		
		
		
		
		
		
		String authnSig = request.getParameter("Signature");
		if (authnSig != null) {
			String sigAlg = request.getParameter("SigAlg");
			StringBuffer query = new StringBuffer();
			
			String qs = request.getQueryString();
			query.append(OpenSAMLUtils.getRawQueryStringParameter(qs, "SAMLRequest"));
			query.append('&');
			if (request.getParameter("RelayState") != null) {
				query.append(OpenSAMLUtils.getRawQueryStringParameter(qs, "RelayState"));
				query.append('&');
			}
			
			query.append(OpenSAMLUtils.getRawQueryStringParameter(qs, "SigAlg"));
			

			
			
			
			java.security.cert.X509Certificate cert = this.cfgMgr.getCertificate(sigKeyName);
			
			String xmlAlg = SAML2Auth.xmlDigSigAlgs.get(algType);
			
			
			if (! sigAlg.equalsIgnoreCase(xmlAlg)) {
				throw new Exception("Invalid signature algorithm : '" + sigAlg + "'");
			}
			
			/*if (! logout.getDestination().equals(request.getRequestURL().toString())) {
				throw new Exception("Invalid destination");
			}*/
			
			java.security.Signature sigv = java.security.Signature.getInstance(SAML2Auth.javaDigSigAlgs.get(algType));
			
			
			
			sigv.initVerify(cert.getPublicKey());
			sigv.update(query.toString().getBytes("UTF-8"));
			
			if (! sigv.verify(Base64.decodeBase64(authnSig.getBytes("UTF-8")))) {
				throw new Exception("Signature verification failed");
			}
			
		} 
		
		response.sendRedirect(logoutURL);
		
		return logoutURL;
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

}

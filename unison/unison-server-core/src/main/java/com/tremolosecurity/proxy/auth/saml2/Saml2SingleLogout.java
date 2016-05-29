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


package com.tremolosecurity.proxy.auth.saml2;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.ssl.util.Hex;
import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml2.core.impl.LogoutRequestMarshaller;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.SessionIndexBuilder;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.proxy.ProxyResponse;
import com.tremolosecurity.proxy.auth.SAML2Auth;
import com.tremolosecurity.proxy.logout.LogoutHandler;
import com.tremolosecurity.proxy.util.ProxyConstants;

public class Saml2SingleLogout implements LogoutHandler {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(Saml2SingleLogout.class.getName());
	
	String logoutURL;
	String sessionIndex;
	String nameID;
	String nameIDFormat;
	String assertionConsumerServiceURL;
	String signingKeyAlias;
	String digSigAlg;
	
	private static SecureRandom random;
	
	static {
		try {
			random = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			logger.error("could not load secure random");
		}
	}
	
	public Saml2SingleLogout(String logoutURL,String sessionIndex,String nameID,String nameIDFormat,String assertionConsumerServiceURL,String signingKeyAlias,String digSigAlg) {
		this.logoutURL = logoutURL;
		this.sessionIndex = sessionIndex;
		this.nameID = nameID;
		this.nameIDFormat = nameIDFormat;
		this.assertionConsumerServiceURL = assertionConsumerServiceURL;
		this.signingKeyAlias = signingKeyAlias;
		this.digSigAlg = digSigAlg;
	}
	
	@Override
	public void handleLogout(HttpServletRequest request,
			HttpServletResponse response) throws ServletException {
		
		if (request == null || response == null) {
			//do nothing
			return;
		}
		
		String xmlAlg = SAML2Auth.xmlDigSigAlgs.get(digSigAlg);
		
		if (xmlAlg == null) {
			throw new ServletException("Unknown Signiture algorithm : '" + digSigAlg + "'");
		}
		
		String javaAlg = SAML2Auth.javaDigSigAlgs.get(digSigAlg);
		
		
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		ConfigManager cfgMgr = holder.getConfig();
		
		
		LogoutRequestBuilder lrb = new LogoutRequestBuilder();
		LogoutRequest lr = lrb.buildObject();
		
		DateTime dt = new DateTime();
		lr.setIssueInstant(dt);
		
		lr.setDestination(logoutURL);
		
		byte[] idBytes = new byte[20];
		random.nextBytes(idBytes);
		
		String id = "f" + Hex.encode(idBytes);
		lr.setID(id);
		
		IssuerBuilder ib = new IssuerBuilder();
		Issuer issuer = ib.buildObject();
		issuer.setValue(assertionConsumerServiceURL);
		lr.setIssuer(issuer);
		
		NameIDBuilder nidbpb = new NameIDBuilder();
		NameID nid = nidbpb.buildObject();
		//nidp.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified");
		nid.setFormat(nameIDFormat);
		
		//nid.setSPNameQualifier(assertionConsumerServiceURL);
		nid.setValue(nameID);
		lr.setNameID(nid);
		
		SessionIndexBuilder sib = new SessionIndexBuilder();
		SessionIndex si = sib.buildObject();
		si.setSessionIndex(sessionIndex);
		lr.getSessionIndexes().add(si);
		
		try {
			// Get the Subject marshaller
			Marshaller marshaller = new LogoutRequestMarshaller();

			// Marshall the Subject
			Element assertionElement = marshaller.marshall(lr);

			String xml = XMLHelper.nodeToString(assertionElement);
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
			
			String b64 = new String(Base64.encodeBase64(baos.toByteArray()));
			StringBuffer redirURL = new StringBuffer();
			StringBuffer query = new StringBuffer();
			
			idBytes = new byte[20];
			random.nextBytes(idBytes);
			
			query.append("SAMLRequest=").append(URLEncoder.encode(b64,"UTF-8")).append("&RelayState=").append(URLEncoder.encode(Hex.encode(idBytes),"UTF-8"));
			
			query.append("&SigAlg=").append(URLEncoder.encode(xmlAlg,"UTF-8"));
			//http://www.w3.org/2000/09/xmldsig#rsa-sha1
			
			java.security.Signature signer = java.security.Signature.getInstance(javaAlg);
			
			PrivateKey sigKey = cfgMgr.getPrivateKey(signingKeyAlias); 
			
			if (sigKey == null) {
				throw new ServletException("Signing Key : '" + signingKeyAlias + "' not found");
			}
			
			signer.initSign(sigKey);
			signer.update(query.toString().getBytes("UTF-8"));
			String base64Sig = new String(Base64.encodeBase64(signer.sign()));
			query.append("&Signature=").append(URLEncoder.encode(base64Sig,"UTF-8"));
			
			
			
			redirURL.append(logoutURL).append("?").append(query.toString());
			
			if (logger.isDebugEnabled()) {
				logger.debug("Logout URL : '" + redirURL.toString() + "'");
			}
			
			//((ProxyResponse) response).removeHeader("Location");
			response.sendRedirect(redirURL.toString());
			
		} catch (Exception e) {
			throw new ServletException("Could not generate logout request",e);
		}
		
	}

}

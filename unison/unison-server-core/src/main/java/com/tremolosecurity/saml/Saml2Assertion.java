/*
Copyright 2015, 2017 Tremolo Security, Inc.

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


package com.tremolosecurity.saml;


import java.io.StringReader;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.codec.binary.Hex;
import org.apache.xml.security.utils.Base64;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.EncryptionParameters;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import com.tremolosecurity.proxy.util.OpenSAMLUtils;
import com.tremolosecurity.proxy.util.ProxyTools;



public  class Saml2Assertion {

	
	
	String subject;
	String authMethod;
	PrivateKey sigKey;
	X509Certificate sigCert;
	X509Certificate encCert;
	
	
	
	org.joda.time.DateTime notBefore;
	org.joda.time.DateTime notAfter;
	org.joda.time.DateTime issueInstant;
	
	ArrayList<Attribute> attribs;
	
	private SecureRandom random;
	private String issuer;
	private String recepient;
	private String audience;
	
	
	boolean signAssertion;
	boolean signResponse;
	boolean encAssertion;
	
	String nameIDFormat;
	String authnContextRef;
	
	public Saml2Assertion(String subject,PrivateKey key,X509Certificate cert,X509Certificate encCert,String issuer,String recepient,String audience,boolean signAssertion,boolean signResponse,boolean encAssertion,String nameIDFormat,String authnContextRef) {
		this.subject = subject;
		
		this.sigKey = key;
		this.sigCert = cert;
		this.encCert = encCert;
		
		
		long now = System.currentTimeMillis();
		
		this.notBefore = (new DateTime(now - (5 * 60 * 1000))).withZone(DateTimeZone.UTC);
		this.notAfter = (new DateTime(now + (5 * 60 * 1000))).withZone(DateTimeZone.UTC);
		this.attribs = new ArrayList<Attribute>();
		this.issueInstant = (new DateTime()).withZone(DateTimeZone.UTC);
		
		this.issuer = issuer;
		this.recepient = recepient;
		this.audience = audience;
		
		this.signAssertion = signAssertion;
		this.signResponse = signResponse;
		this.encAssertion = encAssertion;
		
		this.nameIDFormat = nameIDFormat;
		this.authnContextRef = authnContextRef;
		
		try {
			this.random = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
	}
	
	
	
	

	public String generateSaml2Response() throws Exception {
		byte[] idBytes = new byte[20];
		random.nextBytes(idBytes);
		
		StringBuffer b = new StringBuffer();
		b.append('f').append(Hex.encodeHexString(idBytes));
		String id = b.toString();
		
		Assertion assertion = null;
		
		if (this.signAssertion) {
			AssertionBuilder assertionBuilder = new AssertionBuilder();
			assertion = assertionBuilder.buildObject();
			assertion.setDOM(this.generateSignedAssertion(id));
			
		} else {
			assertion = this.generateAssertion(id);
		}
		
		random.nextBytes(idBytes);
		
		
		b.setLength(0);
		b.append('f').append(Hex.encodeHexString(idBytes));
		id = b.toString();
		
		
		//assertion.setID(id);
		ResponseBuilder rb = new ResponseBuilder();
		Response r = rb.buildObject();
		r.setID(id);
		r.setIssueInstant(this.issueInstant);
		r.setDestination(recepient);
		
		IssuerBuilder issuerBuilder = new IssuerBuilder();
		
		Issuer issuer = issuerBuilder.buildObject();
		
		issuer.setValue(this.issuer);
		r.setIssuer(issuer);
		
		StatusBuilder statusBuilder = new StatusBuilder();
		Status s = statusBuilder.buildObject();
		StatusCodeBuilder scb = new StatusCodeBuilder();
		StatusCode sc = scb.buildObject();
		sc.setValue(StatusCode.SUCCESS);
		s.setStatusCode(sc);
		r.setStatus(s);
		
		
		
		
		
		if (this.encAssertion) {
			DataEncryptionParameters encryptionParameters = new DataEncryptionParameters();
			encryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);
			
			
			KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
			
			
			
			keyEncryptionParameters.setEncryptionCredential(new BasicX509Credential(this.encCert));
	        keyEncryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);

	        Encrypter encrypter = new Encrypter(encryptionParameters, keyEncryptionParameters);
	        encrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);

	        try {
	            EncryptedAssertion encryptedAssertion = encrypter.encrypt(assertion);
	            r.getEncryptedAssertions().add(encryptedAssertion);
	        } catch (EncryptionException e) {
	            throw new RuntimeException(e);
	        }
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			/*
			
			Credential keyEncryptionCredential = CredentialSupport.getSimpleCredential(this.encCert.getPublicKey(), null);
			EncryptionParameters encParams = new EncryptionParameters();
			encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);
			        
			KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
			kekParams.setEncryptionCredential(keyEncryptionCredential);
			kekParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
			KeyInfoGeneratorFactory kigf =
			    Configuration.getGlobalSecurityConfiguration()
			    .getKeyInfoGeneratorManager().getDefaultManager()
			    .getFactory(keyEncryptionCredential);
			kekParams.setKeyInfoGenerator(kigf.newInstance());
			        
			Encrypter samlEncrypter = new Encrypter(encParams, kekParams);
			samlEncrypter.setKeyPlacement(KeyPlacement.PEER);
			        
			try {
			    EncryptedAssertion encryptedAssertion = samlEncrypter.encrypt(assertion);
			    r.getEncryptedAssertions().add(encryptedAssertion);
			} catch (EncryptionException e) {
			    throw new Exception("Could not encrypt response",e);
			}
	        */
		} else {
			r.getAssertions().add(assertion);
		}
		
		if (this.signResponse) {
			if (this.sigCert == null) {
				throw new Exception("No signature key found");
			}
			BasicX509Credential signingCredential = CredentialSupport.getSimpleCredential(this.sigCert, this.sigKey);
			
			Signature signature = OpenSAMLUtils.buildSAMLObject(Signature.class);
			
			//SecurityHelper.prepareSignatureParams(signature, signingCredential, null, null);
			
			
			signature.setSigningCredential(signingCredential);
			signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
			signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
			
			r.setSignature(signature); 
			//Element e = Configuration.getMarshallerFactory().getMarshaller(r).marshall(r); 
			
			try {
	            XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(r).marshall(r);
	        } catch (MarshallingException e) {
	            throw new RuntimeException(e);
	        }
			
			Signer.signObject(signature); 
		}
		
		

		// Get the Subject marshaller
		Marshaller marshaller = new ResponseMarshaller();

		// Marshall the Subject
		Element responseElement = marshaller.marshall(r);
		
		return net.shibboleth.utilities.java.support.xml.SerializeSupport.nodeToString(responseElement);

		
		

	}

		
	private Assertion generateAssertion(String id2) {
		byte[] idBytes = new byte[20];
		random.nextBytes(idBytes);
		
		
		StringBuffer b = new StringBuffer();
		b.append('f').append(Hex.encodeHexString(idBytes));
		String id = b.toString();
		
		
		AssertionBuilder assertionBuilder = new AssertionBuilder();
		
		Assertion assertion = assertionBuilder.buildObject();
		
		assertion.setID(id);
		
		IssuerBuilder issuerBuilder = new IssuerBuilder();
		
		Issuer issuer = issuerBuilder.buildObject();
		
		issuer.setValue(this.issuer);
		
		assertion.setIssuer(issuer);
		
		
		// Get the subject builder based on the subject element name
		SubjectBuilder builder = new SubjectBuilder();

		// Create the subject
		Subject subject = builder.buildObject();

		SubjectConfirmationBuilder scb = new SubjectConfirmationBuilder();
		SubjectConfirmation sc = scb.buildObject();
		sc.setMethod(SubjectConfirmation.METHOD_BEARER);
		
		SubjectConfirmationDataBuilder scdb = new SubjectConfirmationDataBuilder();
		SubjectConfirmationData scd = scdb.buildObject();
		scd.setNotOnOrAfter(this.notAfter);
		scd.setRecipient(this.recepient);
		
		sc.setSubjectConfirmationData(scd);
		subject.getSubjectConfirmations().add(sc);
		NameIDBuilder nameIDBuilder = new NameIDBuilder();
		
		NameID nameID = nameIDBuilder.buildObject();
		nameID.setValue(this.subject);
		nameID.setFormat(this.nameIDFormat);
		
		// Added an NameID and two SubjectConfirmation items - creation of these items is not shown
		subject.setNameID(nameID);
		assertion.setSubject(subject);
		
		AuthnStatementBuilder authnStmtBuilder = new AuthnStatementBuilder();
		AuthnStatement authn = authnStmtBuilder.buildObject();
		authn.setAuthnInstant(this.issueInstant);
		AuthnContextBuilder authnCtxBuilder = new AuthnContextBuilder();
		AuthnContext authnCtx = authnCtxBuilder.buildObject();
		AuthnContextClassRefBuilder accrb = new AuthnContextClassRefBuilder();
		AuthnContextClassRef accrf = accrb.buildObject();
		accrf.setAuthnContextClassRef(this.authnContextRef);
		authnCtx.setAuthnContextClassRef(accrf);
		authn.setAuthnContext(authnCtx);
		//AuthnContextClassRefBuilder accrb = new AuthnContextClassRefBuilder();
		//AuthnContextClassRef accr = accrb.buildObject();
		//accr.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified");
		authn.setSessionIndex(id);
		//authnCtx.setAuthnContextClassRef(accr);
		//authn.setAuthnContext(authnCtx);
		
		assertion.getAuthnStatements().add(authn);
		
		
		AttributeStatementBuilder attrb = new AttributeStatementBuilder();
		AttributeStatement attrStmt = attrb.buildObject();
		
		boolean addAttrs = false;
		
		Iterator<Attribute> attrs = this.attribs.iterator();
		while (attrs.hasNext()) {
			Attribute attrib = attrs.next();
			AttributeBuilder attrBuilder = new AttributeBuilder();
			org.opensaml.saml.saml2.core.Attribute samlAttrib = attrBuilder.buildObject();
			samlAttrib.setName(attrib.getName());
			Iterator<String> attrVals = attrib.getValues().iterator();
			while (attrVals.hasNext()) {
				XSStringBuilder sb = new XSStringBuilder();
				XSString val = sb.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
				val.setValue(attrVals.next());
				samlAttrib.getAttributeValues().add(val);
				addAttrs = true;
			}
			
			attrStmt.getAttributes().add(samlAttrib);
		}
		
		if (addAttrs) {
			assertion.getAttributeStatements().add(attrStmt);
		}
		
		
		
		ConditionsBuilder cb = new ConditionsBuilder();
		Conditions conditions = cb.buildObject();
		conditions.setNotBefore(this.notBefore);
		conditions.setNotOnOrAfter(this.notAfter);
		
		
		
		AudienceRestrictionBuilder arb = new AudienceRestrictionBuilder();
		AudienceRestriction ar = arb.buildObject();
		AudienceBuilder ab = new AudienceBuilder();
		Audience a = ab.buildObject();
		
		a.setAudienceURI(this.audience);
		
		ar.getAudiences().add(a);
		
		conditions.getAudienceRestrictions().add(ar);
		
		assertion.setConditions(conditions);
		
		assertion.setIssueInstant(this.issueInstant);
		
		
		
		return assertion;
	}

	

	public ArrayList<Attribute> getAttribs() {
		return attribs;
	}

	public String getSubject() {
		return subject;
	}

	public String getAuthMethod() {
		return authMethod;
	}

	public org.joda.time.DateTime getNotBefore() {
		return notBefore;
	}

	public org.joda.time.DateTime getNotAfter() {
		return notAfter;
	}
	
	private Element generateSignedAssertion(String id) throws Exception {
		
		if (this.sigCert == null) {
			throw new Exception("No signature key found");
		}
		
		Assertion assertion = generateAssertion(id);
		
		BasicX509Credential signingCredential = CredentialSupport.getSimpleCredential(this.sigCert, this.sigKey);
		
		Signature signature = (Signature) OpenSAMLUtils.buildSAMLObject(Signature.class);
		
		
		
		
		signature.setSigningCredential(signingCredential);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		
		assertion.setSignature(signature);
		Element e = null;
		try {
            e = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
        } catch (MarshallingException e1) {
            throw new RuntimeException(e1);
        } 
		Signer.signObject(signature); 
		
		
		 
		
		////System.out.println(XMLHelper.nodeToString(e));
		
		AssertionBuilder ab = new AssertionBuilder();
		return e;
		
		////System.out.println(XMLHelper.nodeToString(e));
		
		//return assertion;
		
		
		
		
		
		
		
		
		
		/*
		//BasicCredential sigCred = new BasicCredential();
		//sigCred.setPrivateKey(sigKey);
		//sigCred.setEntityCertificate(this.cert);
		
		//sigCred.setUsageType(UsageType.SIGNING);
		
		KeyInfoBuilder kib = new KeyInfoBuilder();
		KeyInfo ki = kib.buildObject();
		
		
		
		signature.setSigningCredential(cred);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		signature.setKeyInfo(ki);
		
		assertion.setSignature(signature);
		
		try {
		Configuration.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
		} catch (MarshallingException e) {
			throw new Exception("Could not generate assertion",e);
		}
		
		try {
		Signer.signObject(signature);
		} catch (SignatureException e) {
			throw new Exception("Could not sign assertion",e);
		}
		return assertion;*/
	}
	
	
}

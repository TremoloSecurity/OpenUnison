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


package com.tremolosecurity.openunison.util;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletException;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.PropertyException;
import javax.xml.bind.Unmarshaller;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.Logger;

import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.cryptacular.codec.Base64Decoder;
import org.opensaml.saml.saml2.core.impl.AuthnRequestMarshaller;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml.saml2.metadata.impl.AssertionConsumerServiceBuilder;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorImpl;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorMarshaller;
import org.opensaml.saml.saml2.metadata.impl.IDPSSODescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.KeyDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.NameIDFormatBuilder;
import org.opensaml.saml.saml2.metadata.impl.SPSSODescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.SPSSODescriptorImpl;
import org.opensaml.saml.saml2.metadata.impl.SingleLogoutServiceBuilder;
import org.opensaml.saml.saml2.metadata.impl.SingleSignOnServiceBuilder;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.security.SecurityException;

import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.impl.KeyInfoBuilder;
import org.opensaml.xmlsec.signature.impl.X509CertificateBuilder;
import org.opensaml.xmlsec.signature.impl.X509DataBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechParamType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.config.xml.MechanismType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.config.xml.TrustType;
import com.tremolosecurity.openunison.util.queue.QueUtils;
import com.tremolosecurity.openunison.util.upgrade.AddChoiceToTasks;
import com.tremolosecurity.proxy.util.OpenSAMLUtils;


public class OpenUnisonUtils {

	static Logger logger;
	
	public static void main(String[] args) throws Exception {
		
		
		
		logger = org.apache.logging.log4j.LogManager.getLogger(OpenUnisonUtils.class.getName());
		
		Options options = new Options();
		options.addOption("unisonXMLFile", true, "The full path to the Unison xml file");
		options.addOption("keystorePath", true, "The full path to the Unison keystore");
		options.addOption("chainName", true, "The name of the authentication chain");
		options.addOption("mechanismName", true, "The name of the authentication mechanism for SAML2");
		options.addOption("idpName", true, "The name of the identity provider application");
		options.addOption("pathToMetaData", true, "The full path to the saml2 metadata file");
		options.addOption("createDefault", false, "If set, add default parameters");
		options.addOption("action", true, "export-sp-metadata, import-sp-metadata, export-secretkey, print-secretkey, import-idp-metadata, export-idp-metadata, clear-dlq, import-secretkey");
		options.addOption("urlBase",true,"Base URL, no URI; https://host:port");
		options.addOption("alias",true,"Key alias");
		options.addOption("newKeystorePath",true,"Path to the new keystore");
		options.addOption("newKeystorePassword",true,"Password for the new keystore");
		options.addOption("help", false, "Prints this message");
		options.addOption("signMetadataWithKey", true, "Signs the metadata with the specified key");
		options.addOption("dlqName", true, "The name of the dead letter queue");
		options.addOption("upgradeFrom106", false, "Updates workflows from 1.0.6");
		options.addOption("secretkey", true, "base64 encoded secret key");
		options.addOption("envFile", true, "Environment variables for parmaterized configs");
		
		
		CommandLineParser parser = new DefaultParser();
		CommandLine cmd = parser.parse(options, args,true);
		
		if (args.length == 0 || cmd.hasOption("help")) {
			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp( "OpenUnisonUtils", options );
		}
		
		logger.info("Loading Unison Configuration");
		String unisonXMLFile = loadOption(cmd,"unisonXMLFile",options);
		TremoloType ttRead = loadTremoloType(unisonXMLFile,cmd,options);
		
		String action = loadOption(cmd,"action",options);
		TremoloType ttWrite = null;
		if (action.equalsIgnoreCase("import-sp-metadata") || action.equalsIgnoreCase("import-idp-metadata")) {
			ttWrite = loadTremoloType(unisonXMLFile);
		} 
		 
		
		logger.info("Configuration loaded");
		
		
		logger.info("Loading the keystore...");
		String ksPath = loadOption(cmd,"keystorePath",options);
		
		KeyStore ks = loadKeyStore(ksPath,ttRead);
		
		logger.info("...loaded");
		
		
		
		
		
		if (action.equalsIgnoreCase("import-sp-metadata")) {
		
			importMetaData(options, cmd, unisonXMLFile, ttRead,ttWrite, ksPath, ks);
		} else if (action.equalsIgnoreCase("export-sp-metadata")) {
			exportSPMetaData(options, cmd, ttRead, ks);
			
		} else if (action.equalsIgnoreCase("print-secretkey")) {
			printSecreyKey(options, cmd, ttRead, ks);
		} else if (action.equalsIgnoreCase("import-secretkey")) {
			importSecreyKey(options, cmd, ttRead, ks,ksPath);
		} else  if (action.equalsIgnoreCase("export-secretkey")) {
			logger.info("Export Secret Key");
			
			logger.info("Loading key");
			String alias = loadOption(cmd,"alias",options);
			SecretKey key = (SecretKey) ks.getKey(alias, ttRead.getKeyStorePassword().toCharArray());
			logger.info("Loading new keystore path");
			String pathToNewKeystore = loadOption(cmd,"newKeystorePath",options);
			logger.info("Loading new keystore password");
			String ksPassword = loadOption(cmd,"newKeystorePassword",options);
			
			KeyStore newKS = KeyStore.getInstance("JCEKS");
			newKS.load(null, ttRead.getKeyStorePassword().toCharArray());
			newKS.setKeyEntry(alias, key, ksPassword.toCharArray(),null);
			newKS.store(new FileOutputStream(pathToNewKeystore), ksPassword.toCharArray());
			logger.info("Exported");
		} else  if (action.equalsIgnoreCase("import-idp-metadata")) {
			importIdpMetadata(options, cmd, unisonXMLFile, ttRead,ttWrite, ksPath, ks);
			
		
			
		} else if (action.equalsIgnoreCase("export-idp-metadata")) {
			exportIdPMetadata(options, cmd, ttRead, ks);
		} else if (action.equalsIgnoreCase("clear-dlq")) {
			logger.info("Getting the DLQ Name...");
			String dlqName = loadOption(cmd,"dlqName",options);
			QueUtils.emptyDLQ(ttRead, dlqName);
		} else if (action.equalsIgnoreCase("upgradeFrom106")) {
			logger.info("Upgrading OpenUnison's configuration from 1.0.6");
			
			String backupFileName = unisonXMLFile + ".bak";
			
			logger.info("Backing up to '" + backupFileName + "'");
			
			BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(unisonXMLFile)));
			PrintWriter out = new PrintWriter(new FileOutputStream(backupFileName));
			String line = null;
			while ((line = in.readLine()) != null) {
				out.println(line);
			}
			out.flush();
			out.close();
			in.close();
			
			ByteArrayOutputStream bout = new ByteArrayOutputStream();
			AddChoiceToTasks.convert(new FileInputStream(unisonXMLFile),bout);
			FileOutputStream  fsout = new FileOutputStream(unisonXMLFile);
			fsout.write(bout.toByteArray());
			fsout.flush();
			fsout.close();
			
			
		}
		
		
		
		
		
	}

	private static void importSecreyKey(Options options, CommandLine cmd, TremoloType tt, KeyStore ks, String ksPath) throws KeyStoreException, Base64DecodingException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		String alias = loadOption(cmd,"alias",options);
		logger.info("importing to " + alias);
		String base64Key = loadOption(cmd,"secretkey",options);
		
		SecretKey sc = new SecretKeySpec(Base64.decode(base64Key),"AES");
		
		ks.setKeyEntry(alias, sc, tt.getKeyStorePassword().toCharArray(), null);
		ks.store(new FileOutputStream(ksPath), tt.getKeyStorePassword().toCharArray());
		
		
		logger.info("import complete");
		
	}

	private static void exportIdPMetadata(Options options, CommandLine cmd, TremoloType tt, KeyStore ks)
			throws Exception, KeyStoreException, CertificateEncodingException, NoSuchAlgorithmException,
			UnrecoverableKeyException, SecurityException, MarshallingException, SignatureException {
		
		InitializationService.initialize();
		
		logger.info("Finding IdP...");
		String idpName = loadOption(cmd,"idpName",options);
		
		ApplicationType idp = null;
		
		for (ApplicationType app : tt.getApplications().getApplication()) {
			if (app.getName().equalsIgnoreCase(idpName)) {
				idp = app;
			}
		}
		
		if (idp == null) {
			throw new Exception("IdP '" + idpName + "' not found");
		}
		
		logger.info("Loading the base URL");
		String baseURL = loadOption(cmd,"urlBase",options);
		
		String url = baseURL + idp.getUrls().getUrl().get(0).getUri();
		
		SecureRandom random = new SecureRandom();
		byte[] idBytes = new byte[20];
		random.nextBytes(idBytes);
		
		StringBuffer b = new StringBuffer();
		b.append('f').append(Hex.encodeHexString(idBytes));
		String id = b.toString();
		
		EntityDescriptorBuilder edb = new EntityDescriptorBuilder();
		EntityDescriptor ed = edb.buildObject();
		ed.setID(id);
		ed.setEntityID(url);
		
		IDPSSODescriptorBuilder idpssdb = new IDPSSODescriptorBuilder();
		IDPSSODescriptor sd =  idpssdb.buildObject();//ed.getSPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");
		sd.addSupportedProtocol("urn:oasis:names:tc:SAML:2.0:protocol");
		ed.getRoleDescriptors().add(sd);
		
		
		HashMap<String,List<String>> params = new HashMap<String,List<String>>();
		for (ParamType pt : idp.getUrls().getUrl().get(0).getIdp().getParams()) {
			List<String> vals = params.get(pt.getName());
			if (vals == null) {
				vals = new ArrayList<String>();
				params.put(pt.getName(), vals);
			}
			vals.add(pt.getValue());
		}
		
		
		sd.setWantAuthnRequestsSigned(params.containsKey("requireSignedAuthn") && params.get("requireSignedAuthn").get(0).equalsIgnoreCase("true"));
		
		KeyDescriptorBuilder kdb = new KeyDescriptorBuilder();
		
		if (params.get("encKey") != null && ! params.get("encKey").isEmpty() && (ks.getCertificate(params.get("encKey").get(0)) != null)) {
			KeyDescriptor kd = kdb.buildObject();
			kd.setUse(UsageType.ENCRYPTION);
			KeyInfoBuilder kib = new KeyInfoBuilder();
			KeyInfo ki = kib.buildObject();
			
			X509DataBuilder x509b = new X509DataBuilder();
			X509Data x509 = x509b.buildObject();
			X509CertificateBuilder certb = new X509CertificateBuilder();
			org.opensaml.xmlsec.signature.X509Certificate cert = certb.buildObject();
			cert.setValue(Base64.encode(ks.getCertificate(params.get("encKey").get(0)).getEncoded()));
			x509.getX509Certificates().add(cert);
			ki.getX509Datas().add(x509);
			kd.setKeyInfo(ki);
			sd.getKeyDescriptors().add(kd);
			
		}
		
		if (params.get("sigKey") != null && ! params.get("sigKey").isEmpty() && (ks.getCertificate(params.get("sigKey").get(0)) != null)) {
			KeyDescriptor kd = kdb.buildObject();
			kd.setUse(UsageType.SIGNING);
			KeyInfoBuilder kib = new KeyInfoBuilder();
			KeyInfo ki = kib.buildObject();
			
			X509DataBuilder x509b = new X509DataBuilder();
			X509Data x509 = x509b.buildObject();
			X509CertificateBuilder certb = new X509CertificateBuilder();
			org.opensaml.xmlsec.signature.X509Certificate cert = certb.buildObject();
			cert.setValue(Base64.encode(ks.getCertificate(params.get("sigKey").get(0)).getEncoded()));
			x509.getX509Certificates().add(cert);
			ki.getX509Datas().add(x509);
			kd.setKeyInfo(ki);
			sd.getKeyDescriptors().add(kd);
			
		}
		
		HashSet<String> nameids = new HashSet<String>();
		
		for (TrustType trustType : idp.getUrls().getUrl().get(0).getIdp().getTrusts().getTrust()) {
			for (ParamType pt : trustType.getParam()) {
				if (pt.getName().equalsIgnoreCase("nameIdMap")) {
					String val = pt.getValue().substring(0,pt.getValue().indexOf('='));
					if (! nameids.contains(val)) {
						nameids.add(val);
					}
				}	
			}
		}
		
		NameIDFormatBuilder nifb = new NameIDFormatBuilder();
		
		for (String nidf : nameids) {
			NameIDFormat nif = nifb.buildObject();
			nif.setFormat(nidf);
			sd.getNameIDFormats().add(nif);
		}
		
		SingleSignOnServiceBuilder ssosb = new SingleSignOnServiceBuilder();
		SingleSignOnService sso = ssosb.buildObject();
		sso.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		sso.setLocation(url + "/httpPost");
		sd.getSingleSignOnServices().add(sso);
		
		sso = ssosb.buildObject();
		sso.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
		sso.setLocation(url + "/httpRedirect");
		sd.getSingleSignOnServices().add(sso);
		
		String signingKey = loadOptional(cmd,"signMetadataWithKey",options);
		
		if (signingKey != null && ks.getCertificate(signingKey) != null) {
			BasicX509Credential signingCredential = new BasicX509Credential((X509Certificate) ks.getCertificate(signingKey), (PrivateKey) ks.getKey(signingKey,tt.getKeyStorePassword().toCharArray()));
			
			Signature signature = OpenSAMLUtils.buildSAMLObject(Signature.class);
			
			
			signature.setSigningCredential(signingCredential);
			signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
			signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
			
			ed.setSignature(signature); 
			try {
	            XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(ed).marshall(ed);
	        } catch (MarshallingException e) {
	            throw new RuntimeException(e);
	        }
			Signer.signObject(signature); 
		}
		 
		
		// Get the Subject marshaller
		EntityDescriptorMarshaller marshaller = new EntityDescriptorMarshaller();

		// Marshall the Subject
		Element assertionElement = marshaller.marshall(ed);
		
		

		logger.info(net.shibboleth.utilities.java.support.xml.SerializeSupport.nodeToString(assertionElement));
	}

	private static void importIdpMetadata(Options options, CommandLine cmd, String unisonXMLFile, TremoloType ttRead,
			TremoloType ttWrite, String ksPath, KeyStore ks)
					throws ParserConfigurationException, SAXException, IOException, FileNotFoundException,
					UnmarshallingException, Exception, Base64DecodingException, CertificateException, KeyStoreException,
					NoSuchAlgorithmException, JAXBException, PropertyException {
		logger.info("Import SP Metadata into the IdP");
		
		logger.info("Loading Metadata...");
		String metadataFile = loadOption(cmd,"pathToMetaData",options);
		
		InitializationService.initialize();
		
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		
		DocumentBuilder builder = factory.newDocumentBuilder();

		Element root = builder
				.parse(new InputSource(new InputStreamReader(new FileInputStream(metadataFile)))).getDocumentElement();
		
		EntityDescriptor ed =  (EntityDescriptor) XMLObjectSupport.getUnmarshaller(root).unmarshall(root);
		
		logger.info("Loading IdP...");
		String idpName =  loadOption(cmd,"idpName",options);
		
		ApplicationType idp = null;
		
		for (ApplicationType app : ttWrite.getApplications().getApplication()) {
			if (app.getName().equalsIgnoreCase(idpName)) {
				idp = app;
			}
		}
		
		if (idp == null) {
			throw new Exception("IdP '" + idpName + "' not found");
		}
		
		SPSSODescriptor sp = ed.getSPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");
		
		TrustType trust = null;
		
		trust = new TrustType();
		
		
		if (sp.getID() == null) {
			trust.setName(ed.getEntityID());
		} else {
			trust.setName(sp.getID());
		}
		
		for (AssertionConsumerService svc : sp.getAssertionConsumerServices()) {
			if (svc.getBinding().equalsIgnoreCase("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")) {
				ParamType pt = new ParamType();
				pt.setName("httpPostRespURL");
				pt.setValue(svc.getLocation());
				trust.getParam().add(pt);
			}
		}
		
		
		
		ParamType pt = new ParamType();
		pt.setName("signAssertion");
		pt.setValue(Boolean.toString(sp.getWantAssertionsSigned().booleanValue()));
		trust.getParam().add(pt);
		
		
		if (pt.getValue().equalsIgnoreCase("false")) {
			
			pt = new ParamType();
			pt.setName("signResponse");
			pt.setValue("true");
			trust.getParam().add(pt);
		} else {
			pt = new ParamType();
			pt.setName("signResponse");
			pt.setValue("false");
			trust.getParam().add(pt);
		}
		
		
		boolean first = true;
		for (NameIDFormat nameid : sp.getNameIDFormats()) {
			if (first) {
				
				pt = new ParamType();
				pt.setName("defaultNameId");
				pt.setValue(nameid.getFormat());
				trust.getParam().add(pt);
				
				
				first = false;
			}
			
			pt = new ParamType();
			pt.setName("nameIdMap");
			pt.setValue(nameid.getFormat() + "=");
			trust.getParam().add(pt);
		}
		
		boolean encryptAssertion = false;
		boolean signAssertion = false;
		for (KeyDescriptor kd : sp.getKeyDescriptors()) {
			
			if (kd.getUse().equals(UsageType.SIGNING)) {
				String base64 = kd.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0).getValue();
				String name = "verify-" + ed.getEntityID() + "-sp-sig";
				
				ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decode(base64));
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				Collection<? extends Certificate> c = cf.generateCertificates(bais);
				
				if (c.size() > 1) {
					int j = 0;
					Iterator<? extends Certificate> i = c.iterator();
					while (i.hasNext()) {
						Certificate certificate = (Certificate) i.next();
						ks.setCertificateEntry(name + "-" + j, certificate);
					}
				} else {
					ks.setCertificateEntry(name, c.iterator().next());
				}
				
				pt = new ParamType();
				pt.setName("spSigKey");
				pt.setValue(name);
				trust.getParam().add(pt);
				
				signAssertion = true;
			} 
			
			if (kd.getUse().equals(UsageType.ENCRYPTION)) {
				String base64 = kd.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0).getValue();
				String name = "verify-" + ed.getEntityID() + "-sp-enc";
				
				ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decode(base64));
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				Collection<? extends Certificate> c = cf.generateCertificates(bais);
				
				if (c.size() > 1) {
					int j = 0;
					Iterator<? extends Certificate> i = c.iterator();
					while (i.hasNext()) {
						Certificate certificate = (Certificate) i.next();
						ks.setCertificateEntry(name + "-" + j, certificate);
					}
				} else {
					ks.setCertificateEntry(name, c.iterator().next());
				}
				
				
				pt = new ParamType();
				pt.setName("spEncKey");
				pt.setValue(name);
				trust.getParam().add(pt);
				
				encryptAssertion = true;
			}
		}
		
		pt = new ParamType();
		pt.setName("encAssertion");
		pt.setValue(encryptAssertion ? "true" : "false");
		trust.getParam().add(pt);
		
		if (! signAssertion) {
			pt = new ParamType();
			pt.setName("spSigKey");
			pt.setValue("");
			trust.getParam().add(pt);
		}
		
		if (! encryptAssertion) {
			pt = new ParamType();
			pt.setName("spEncKey");
			pt.setValue("");
			trust.getParam().add(pt);
		}
		
		pt = new ParamType();
		pt.setName("defaultAuthCtx");
		pt.setValue("");
		trust.getParam().add(pt);
		
		
		TrustType cur = null;
		for (TrustType trustType : idp.getUrls().getUrl().get(0).getIdp().getTrusts().getTrust()) {
			if (trustType.getName().equals(trust.getName())) {
				cur = trustType;
				break;
			}
		}
		
		if (cur != null) {
			idp.getUrls().getUrl().get(0).getIdp().getTrusts().getTrust().remove(cur);
		}
		
		idp.getUrls().getUrl().get(0).getIdp().getTrusts().getTrust().add(trust);
		
		OpenUnisonUtils.storeMethod(unisonXMLFile, ttWrite, ksPath, ks);
	}

	private static void printSecreyKey(Options options, CommandLine cmd,
			TremoloType tt, KeyStore ks) throws KeyStoreException,
			NoSuchAlgorithmException, UnrecoverableKeyException {
		String alias = loadOption(cmd,"alias",options);
		SecretKey key = (SecretKey) ks.getKey(alias, tt.getKeyStorePassword().toCharArray());
		String val = Base64.encode(key.getEncoded());
		logger.info(val);
	}

	private static void exportSPMetaData(Options options, CommandLine cmd,
			TremoloType tt, KeyStore ks) throws Exception, KeyStoreException,
			NoSuchAlgorithmException, UnrecoverableKeyException,
			CertificateEncodingException, MarshallingException {
		logger.info("Finding mechanism...");
		String mechanismName = loadOption(cmd,"mechanismName",options);
		MechanismType saml2Mech = loadMechanismType(mechanismName,tt);
		logger.info("...found");
		
		logger.info("Finding chain...");
		String chainName = loadOption(cmd,"chainName",options);
		
		AuthChainType act = loadChainType(chainName,tt);
		
		logger.info("Looking for correct mechanism on the chain...");
		AuthMechType currentMechanism = null;
		for (AuthMechType amt : act.getAuthMech()) {
			if (amt.getName().equalsIgnoreCase(mechanismName)) {
				currentMechanism = amt;
				break;
			}
		}
		
		if (currentMechanism == null) {
			System.err.println("Unknown chain on mechanism");
			System.exit(1);
		}
		
		
		InitializationService.initialize();
		
		logger.info("loading url base");
		
		String urlBase = loadOption(cmd,"urlBase",options);
		
		String url = urlBase + saml2Mech.getUri();
		EntityDescriptorBuilder edb = new EntityDescriptorBuilder();
		EntityDescriptorImpl ed = (EntityDescriptorImpl) edb.buildObject();
		ed.setEntityID(url);
		
		
		SPSSODescriptorBuilder spb = new SPSSODescriptorBuilder();
		SPSSODescriptorImpl sp = (SPSSODescriptorImpl) spb.buildObject();
		ed.getRoleDescriptors().add(sp);
		
		HashMap<String,ParamType> params = new HashMap<String,ParamType>();
		for (ParamType pt : currentMechanism.getParams().getParam()) {
			params.put(pt.getName(), pt);
		}
		
		boolean assertionsSigned = params.get("assertionsSigned") != null && params.get("assertionsSigned").getValue().equalsIgnoreCase("true");
		sp.setWantAssertionsSigned(assertionsSigned);
		sp.addSupportedProtocol("urn:oasis:names:tc:SAML:2.0:protocol");
		
		
		SingleLogoutServiceBuilder slsb = new SingleLogoutServiceBuilder();
		SingleLogoutService sls = slsb.buildObject();
		sls.setLocation(url);
		sls.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
		sp.getSingleLogoutServices().add(sls);
		
		sls = slsb.buildObject();
		sls.setLocation(url);
		sls.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		sp.getSingleLogoutServices().add(sls);
		
		AssertionConsumerServiceBuilder acsb = new AssertionConsumerServiceBuilder();
		AssertionConsumerService acs = acsb.buildObject();
		acs.setLocation(url);
		acs.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		acs.setIndex(0);
		acs.setIsDefault(true);
		sp.getAssertionConsumerServices().add(acs);
		
		acs = acsb.buildObject();
		acs.setLocation(url);
		acs.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
		acs.setIndex(1);
		sp.getAssertionConsumerServices().add(acs);
		
		if (params.get("spSigKey") != null && ! params.get("spSigKey").getValue().isEmpty()) {
			String alias = params.get("spSigKey").getValue();
			X509Certificate certFromKS = (X509Certificate) ks.getCertificate(alias);
			
			if (certFromKS == null) {
				throw new Exception("Certificate '" + params.get("spSigKey").getValue() + "' not found");
			}
			
			PrivateKey keyFromKS = (PrivateKey) ks.getKey(alias, tt.getKeyStorePassword().toCharArray());
			KeyDescriptorBuilder kdb = new KeyDescriptorBuilder();
			KeyDescriptor kd = kdb.buildObject();
			kd.setUse(UsageType.SIGNING);
			KeyInfoBuilder kib = new KeyInfoBuilder();
			KeyInfo ki = kib.buildObject();
			
			X509DataBuilder x509b = new X509DataBuilder();
			X509Data x509 = x509b.buildObject();
			X509CertificateBuilder certb = new X509CertificateBuilder();
			org.opensaml.xmlsec.signature.X509Certificate cert = certb.buildObject();
			cert.setValue(new String(Base64.encode(certFromKS.getEncoded())));
			x509.getX509Certificates().add(cert);
			ki.getX509Datas().add(x509);
			kd.setKeyInfo(ki);
			sp.getKeyDescriptors().add(kd);
			
			
			
		}
		
		if (params.get("spEncKey") != null && ! params.get("spEncKey").getValue().isEmpty()) {
			String alias = params.get("spEncKey").getValue();
			X509Certificate certFromKS = (X509Certificate) ks.getCertificate(alias);
			
			if (certFromKS == null) {
				throw new Exception("Certificate '" + params.get("spEncKey").getValue() + "' not found");
			}
			
			PrivateKey keyFromKS = (PrivateKey) ks.getKey(alias, tt.getKeyStorePassword().toCharArray());
			KeyDescriptorBuilder kdb = new KeyDescriptorBuilder();
			KeyDescriptor kd = kdb.buildObject();
			kd.setUse(UsageType.ENCRYPTION);
			KeyInfoBuilder kib = new KeyInfoBuilder();
			KeyInfo ki = kib.buildObject();
			
			X509DataBuilder x509b = new X509DataBuilder();
			X509Data x509 = x509b.buildObject();
			X509CertificateBuilder certb = new X509CertificateBuilder();
			org.opensaml.xmlsec.signature.X509Certificate cert = certb.buildObject();
			cert.setValue(new String(Base64.encode(certFromKS.getEncoded())));
			x509.getX509Certificates().add(cert);
			ki.getX509Datas().add(x509);
			kd.setKeyInfo(ki);
			sp.getKeyDescriptors().add(kd);
			
			
			
		}
		
		
		EntityDescriptorMarshaller marshaller = new EntityDescriptorMarshaller();

		// Marshall the Subject
		Element assertionElement = marshaller.marshall(ed);

		String xml = net.shibboleth.utilities.java.support.xml.SerializeSupport.prettyPrintXML(assertionElement);
		
		logger.info(xml);
	}

	private static void importMetaData(Options options, CommandLine cmd,
			String unisonXMLFile, TremoloType ttRead, TremoloType ttWrite, String ksPath, KeyStore ks)
			throws Exception, Base64DecodingException, CertificateException,
			KeyStoreException, IOException, NoSuchAlgorithmException,
			FileNotFoundException, JAXBException, PropertyException {
		logger.info("Finding mechanism...");
		String mechanismName = loadOption(cmd,"mechanismName",options);
		MechanismType saml2Mech = loadMechanismType(mechanismName,ttWrite);
		logger.info("...found");
		
		logger.info("Finding chain...");
		String chainName = loadOption(cmd,"chainName",options);
		
		AuthChainType act = loadChainType(chainName,ttWrite);
		
		
		boolean createDefault = cmd.hasOption("createDefault");
		logger.info("Create default configuration? : " + createDefault);
		
		logger.info("Loading metadata...");
		String pathToMetaData = loadOption(cmd,"pathToMetaData",options);
		logger.info("...loaded");
		EntityDescriptor ed = loadIdPMetaData(pathToMetaData,ks,ttRead);
		IDPSSODescriptor idp = ed.getIDPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");
		
		logger.info("Looking for correct mechanism on the chain...");
		AuthMechType currentMechanism = null;
		for (AuthMechType amt : act.getAuthMech()) {
			if (amt.getName().equalsIgnoreCase(mechanismName)) {
				currentMechanism = amt;
				break;
			}
		}
		
		boolean newMech = true;
		
		if (currentMechanism != null) {
			logger.info("Updating existing mechanism");
			newMech = false;
		} else {
			logger.info("Creating new mechanism");
			currentMechanism = new AuthMechType();
			currentMechanism.setName(mechanismName);
			currentMechanism.setRequired("required");
			currentMechanism.setParams(new AuthMechParamType());
			act.getAuthMech().add(currentMechanism);
			newMech = true;
		}
		
		HashMap<String,ParamType> params = new HashMap<String,ParamType>();
		for (ParamType pt : currentMechanism.getParams().getParam()) {
			params.put(pt.getName(), pt);
		}
		
		
		
		importMetaData(ks, ed, idp, currentMechanism, params);
		
		if (newMech && createDefault) {
			setDefaults(ks, ed, idp, currentMechanism, params);
		}
		
		storeMethod(unisonXMLFile, ttWrite, ksPath, ks);
	}

	private static void storeMethod(String unisonXMLFile, TremoloType tt,
			String ksPath, KeyStore ks) throws KeyStoreException, IOException,
			NoSuchAlgorithmException, CertificateException,
			FileNotFoundException, JAXBException, PropertyException {
		logger.info("Storing the keystore");
		ks.store(new FileOutputStream(ksPath), tt.getKeyStorePassword().toCharArray());
		
		logger.info("Saving the unison xml file");
		
		JAXBContext jc = JAXBContext.newInstance("com.tremolosecurity.config.xml");
		Marshaller marshaller = jc.createMarshaller();
		marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
		OutputStream os = new FileOutputStream(unisonXMLFile);
		JAXBElement<TremoloType> root = new JAXBElement<TremoloType>(new QName("http://www.tremolosecurity.com/tremoloConfig","tremoloConfig","tns"),TremoloType.class,tt);
		marshaller.marshal(root, os);
		os.flush();
		os.close();
	}

	private static void setDefaults(KeyStore ks, EntityDescriptor ed,
			IDPSSODescriptor idp, AuthMechType currentMechanism,
			HashMap<String, ParamType> params) {
		
		if (params.get("assertionsSigned") == null || params.get("assertionsSigned").getValue().equalsIgnoreCase("false")) {
			setProperty("responsesSigned","true",params,currentMechanism);
		} else {
			setProperty("responsesSigned","false",params,currentMechanism);
		}
		
		setProperty("jumpPage","",params,currentMechanism);
		setProperty("sigAlg","RSA-SHA1",params,currentMechanism);
		setProperty("authCtxRef","",params,currentMechanism);
		setProperty("forceToSSL","false",params,currentMechanism);
		setProperty("ldapAttribute","uid",params,currentMechanism);
		setProperty("dnOU","SAML2",params,currentMechanism);
		setProperty("defaultOC","inetOrgPerson",params,currentMechanism);
		setProperty("dontLinkToLDAP","false",params,currentMechanism);
		setProperty("responsesSigned","true",params,currentMechanism);
		setProperty("assertionsSigned","false",params,currentMechanism);
		
		
		
	}

	private static void importMetaData(KeyStore ks, EntityDescriptor ed,
			IDPSSODescriptor idp, AuthMechType currentMechanism,
			HashMap<String, ParamType> params) throws Base64DecodingException,
			CertificateException, KeyStoreException {
		setProperty("entityID",ed.getEntityID(),params,currentMechanism);
		setProperty("entityID",ed.getEntityID(),params,currentMechanism);
		
		for (SingleSignOnService sso : idp.getSingleSignOnServices() ) {
			if (sso.getBinding().equalsIgnoreCase("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")) {
				setProperty("idpURL",sso.getLocation(),params,currentMechanism);
				
			} else if (sso.getBinding().equalsIgnoreCase("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")) {
				
				setProperty("idpRedirURL",sso.getLocation(),params,currentMechanism);
			}
		}
		
		for (SingleLogoutService slo : idp.getSingleLogoutServices()) {
			if (slo.getBinding().equalsIgnoreCase("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")) {
				
				setProperty("idpRedirLogoutURL",slo.getLocation(),params,currentMechanism);
			}
		}
		
		for (KeyDescriptor kd : idp.getKeyDescriptors()) {
			
			if (kd.getUse().equals(UsageType.SIGNING)) {
				String base64 = kd.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0).getValue();
				String name = "verify-" + ed.getEntityID() + "-idp-sig";

				
				ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decode(base64));
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				Collection<? extends Certificate> c = cf.generateCertificates(bais);
				
				if (c.size() > 1) {
					int j = 0;
					Iterator<? extends Certificate> i = c.iterator();
					while (i.hasNext()) {
						Certificate certificate = (Certificate) i.next();
						ks.setCertificateEntry(name + "-" + j, certificate);
					}
				} else {
					ks.setCertificateEntry(name, c.iterator().next());
				}
				
				
				setProperty("idpSigKeyName",name,params,currentMechanism);
				
			}
			
			
		}
	}
	
	private static void setProperty(String name,String value,HashMap<String,ParamType> params,AuthMechType amt) {
		ParamType pt = params.get(name);
		if (pt == null) {
			pt = new ParamType();
			pt.setName(name);
			amt.getParams().getParam().add(pt);
			params.put(name, pt);
		}
		
		pt.setValue(value);
	}
	
	private static EntityDescriptor loadIdPMetaData(String pathToMetaData,KeyStore ks,TremoloType tt) throws Exception {
		
		InitializationService.initialize();
		
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		
		DocumentBuilder builder = factory.newDocumentBuilder();

		Element root = builder
				.parse(new InputSource(new FileInputStream(pathToMetaData))).getDocumentElement();
		
		
		
		EntityDescriptor ed =  (EntityDescriptor) XMLObjectSupport.getUnmarshaller(root).unmarshall(root);
		
		
		
		return ed;
	}
	
	
	private static KeyStore loadKeyStore(String ksPath, TremoloType tt) throws Exception {
		KeyStore ks = KeyStore.getInstance("JCEKS");
		
		InputStream in = new FileInputStream(ksPath);
		ks.load(in, tt.getKeyStorePassword().toCharArray());
		
		return ks;
	}

	private static AuthChainType loadChainType(String chainName, TremoloType tt) {
		for (AuthChainType act : tt.getAuthChains().getChain()) {
			if (act.getName().equalsIgnoreCase(chainName)) {
				return act;
			}
		}
		
		System.err.println("Unable to find '" + chainName + "'");
		System.exit(1);
		return null;
	}

	private static MechanismType loadMechanismType(String mechanismName,TremoloType tt) throws Exception {
		for (MechanismType mt : tt.getAuthMechs().getMechanism()) {
			if (mt.getName().equalsIgnoreCase(mechanismName)) {
				return mt;
				
			}
		}
		
		System.err.println("Could not find mechanism '" + mechanismName + "'");
		System.exit(1);
		return null;
	}
	
	private static TremoloType loadTremoloType(String unisonXMLFile,CommandLine cmd,Options options) throws Exception {
		JAXBContext jc = JAXBContext.newInstance("com.tremolosecurity.config.xml");
		Unmarshaller unmarshaller = jc.createUnmarshaller();
		InputStream in = null;
		
		
		String envFile = cmd.getOptionValue("envFile");
		if (envFile != null) {
			BufferedReader fin = new BufferedReader(new InputStreamReader(new FileInputStream(envFile)));
			String line = null;
			while ((line = fin.readLine()) != null) {
				String name = line.substring(0, line.indexOf('='));
				String val = line.substring(line.indexOf('=') + 1);
				System.setProperty(name, val);
			}
			
			String withProps = OpenUnisonUtils.includeEnvironmentVariables(unisonXMLFile);
			in = new ByteArrayInputStream(withProps.getBytes("UTF-8"));
			
		} else {
			in = new FileInputStream(unisonXMLFile);
		}
		
		
		
		Object obj = unmarshaller.unmarshal(in);
		
		JAXBElement<TremoloType> cfg = (JAXBElement<TremoloType>) obj;
		return cfg.getValue();
	}
	
	private static TremoloType loadTremoloType(String unisonXMLFile) throws Exception {
		JAXBContext jc = JAXBContext.newInstance("com.tremolosecurity.config.xml");
		Unmarshaller unmarshaller = jc.createUnmarshaller();
		FileInputStream in = new FileInputStream(unisonXMLFile);
		
		
		
		
		
		
		Object obj = unmarshaller.unmarshal(in);
		
		JAXBElement<TremoloType> cfg = (JAXBElement<TremoloType>) obj;
		return cfg.getValue();
	}

	static String loadOption(CommandLine cmd,String name,Options options) {
		String val = cmd.getOptionValue(name);
		if (val == null) {
			logger.warn("Could not find option '" + name + "'");
			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp( "OpenUnisonUtils", options );
			System.exit(1);
			return null;
		} else {
			return val;
		}
	}
	
	static String loadOptional(CommandLine cmd,String name,Options options) {
		String val = cmd.getOptionValue(name);
		if (val == null) {
			
			return null;
		} else {
			return val;
		}
	}
	
	private static String includeEnvironmentVariables(String srcPath) throws IOException {
		StringBuffer b = new StringBuffer();
		String line = null;
		
		BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(srcPath)));
		
		while ((line = in.readLine()) != null) {
			b.append(line).append('\n');
		}
		
		String cfg = b.toString();
		if (logger.isDebugEnabled()) {
			logger.debug("---------------");
			logger.debug("Before environment variables : '" + srcPath + "'");
			logger.debug(cfg);
			logger.debug("---------------");
		}
		
		int begin,end;
		
		b.setLength(0);
		begin = 0;
		end = 0;
		
		String finalCfg = null;
		
		begin = cfg.indexOf("#[");
		while (begin > 0) {
			if (end == 0) {
				b.append(cfg.substring(0,begin));
			} else {
				b.append(cfg.substring(end,begin));
			}
			
			end = cfg.indexOf(']',begin + 2);
			
			String envVarName = cfg.substring(begin + 2,end);
			String value = System.getenv(envVarName);
			
			if (value == null) {
				value = System.getProperty(envVarName);
			}
			
			if (logger.isDebugEnabled()) {
				logger.debug("Environment Variable '" + envVarName + "'='" + value + "'");
			}
			
			b.append(value);
			
			begin = cfg.indexOf("#[",end + 1);
			end++;
			
		}
		
		if (end == 0) {
			finalCfg = cfg;
		} else {
			b.append(cfg.substring(end));
			finalCfg = b.toString();
		}
		
		if (logger.isDebugEnabled()) {
			logger.debug("---------------");
			logger.debug("After environment variables : '" + srcPath + "'");
			logger.debug(finalCfg);
			logger.debug("---------------");
		}
		
		return finalCfg;
		
		
	}

}



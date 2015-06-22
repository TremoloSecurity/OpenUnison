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

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;

import javax.crypto.SecretKey;
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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.impl.AuthnRequestMarshaller;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.impl.AssertionConsumerServiceBuilder;
import org.opensaml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.opensaml.saml2.metadata.impl.EntityDescriptorImpl;
import org.opensaml.saml2.metadata.impl.EntityDescriptorMarshaller;
import org.opensaml.saml2.metadata.impl.KeyDescriptorBuilder;
import org.opensaml.saml2.metadata.impl.SPSSODescriptorBuilder;
import org.opensaml.saml2.metadata.impl.SPSSODescriptorImpl;
import org.opensaml.saml2.metadata.impl.SingleLogoutServiceBuilder;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.impl.KeyInfoBuilder;
import org.opensaml.xml.signature.impl.X509CertificateBuilder;
import org.opensaml.xml.signature.impl.X509DataBuilder;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechParamType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.config.xml.MechanismType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.TremoloType;

public class OpenUnisonUtils {

	public static void main(String[] args) throws Exception {
		Options options = new Options();
		options.addOption("unisonXMLFile", true, "The full path to the Unison xml file");
		options.addOption("keystorePath", true, "The full path to the Unison keystore");
		options.addOption("chainName", true, "The name of the authentication chain");
		options.addOption("mechanismName", true, "The name of the authentication mechanism for SAML2");
		options.addOption("pathToMetaData", true, "The full path to the saml2 metadata file");
		options.addOption("createDefault", false, "If set, add default parameters");
		options.addOption("action", true, "export-sp-metadata, import-sp-metadata, export-secretkey, print-secretkey");
		options.addOption("urlBase",true,"Base URL, no URI; https://host:port");
		options.addOption("alias",true,"Key alias");
		options.addOption("newKeystorePath",true,"Path to the new keystore");
		options.addOption("newKeystorePassword",true,"Password for the new keystore");
		options.addOption("help", false, "Prints this message");
		
		CommandLineParser parser = new DefaultParser();
		CommandLine cmd = parser.parse(options, args,true);
		
		if (args.length == 0 || cmd.hasOption("help")) {
			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp( "OpenUnisonUtils", options );
		}
		
		System.out.println("Loading Unison Configuration");
		String unisonXMLFile = loadOption(cmd,"unisonXMLFile",options);
		TremoloType tt = loadTremoloType(unisonXMLFile);
		System.out.println("Configuration loaded");
		
		
		System.out.println("Loading the keystore...");
		String ksPath = loadOption(cmd,"keystorePath",options);
		
		KeyStore ks = loadKeyStore(ksPath,tt);
		
		System.out.println("...loaded");
		
		String action = loadOption(cmd,"action",options);
		
		
		
		if (action.equalsIgnoreCase("import-sp-metadata")) {
		
			importMetaData(options, cmd, unisonXMLFile, tt, ksPath, ks);
		} else if (action.equalsIgnoreCase("export-sp-metadata")) {
			exportSPMetaData(options, cmd, tt, ks);
			
		} else if (action.equalsIgnoreCase("print-secretkey")) {
			printSecreyKey(options, cmd, tt, ks);
		} else  if (action.equalsIgnoreCase("export-secretkey")) {
			System.out.println("Export Secret Key");
			
			System.out.println("Loading key");
			String alias = loadOption(cmd,"alias",options);
			SecretKey key = (SecretKey) ks.getKey(alias, tt.getKeyStorePassword().toCharArray());
			System.out.println("Loading new keystore path");
			String pathToNewKeystore = loadOption(cmd,"newKeystorePath",options);
			System.out.println("Loading new keystore password");
			String ksPassword = loadOption(cmd,"newKeystorePassword",options);
			
			KeyStore newKS = KeyStore.getInstance("JCEKS");
			newKS.load(null, tt.getKeyStorePassword().toCharArray());
			newKS.setKeyEntry(alias, key, ksPassword.toCharArray(),null);
			newKS.store(new FileOutputStream(pathToNewKeystore), ksPassword.toCharArray());
			System.out.println("Exported");
		}
		
		
	}

	private static void printSecreyKey(Options options, CommandLine cmd,
			TremoloType tt, KeyStore ks) throws KeyStoreException,
			NoSuchAlgorithmException, UnrecoverableKeyException {
		String alias = loadOption(cmd,"alias",options);
		SecretKey key = (SecretKey) ks.getKey(alias, tt.getKeyStorePassword().toCharArray());
		String val = Base64.encode(key.getEncoded());
		System.out.println(val);
	}

	private static void exportSPMetaData(Options options, CommandLine cmd,
			TremoloType tt, KeyStore ks) throws Exception, KeyStoreException,
			NoSuchAlgorithmException, UnrecoverableKeyException,
			CertificateEncodingException, MarshallingException {
		System.out.println("Finding mechanism...");
		String mechanismName = loadOption(cmd,"mechanismName",options);
		MechanismType saml2Mech = loadMechanismType(mechanismName,tt);
		System.out.println("...found");
		
		System.out.println("Finding chain...");
		String chainName = loadOption(cmd,"chainName",options);
		
		AuthChainType act = loadChainType(chainName,tt);
		
		System.out.println("Looking for correct mechanism on the chain...");
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
		
		
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		System.out.println("loading url base");
		
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
		
		if (params.get("spSigKey") != null) {
			String alias = params.get("spSigKey").getValue();
			X509Certificate certFromKS = (X509Certificate) ks.getCertificate(alias);
			PrivateKey keyFromKS = (PrivateKey) ks.getKey(alias, tt.getKeyStorePassword().toCharArray());
			KeyDescriptorBuilder kdb = new KeyDescriptorBuilder();
			KeyDescriptor kd = kdb.buildObject();
			kd.setUse(UsageType.SIGNING);
			KeyInfoBuilder kib = new KeyInfoBuilder();
			KeyInfo ki = kib.buildObject();
			
			X509DataBuilder x509b = new X509DataBuilder();
			X509Data x509 = x509b.buildObject();
			X509CertificateBuilder certb = new X509CertificateBuilder();
			org.opensaml.xml.signature.X509Certificate cert = certb.buildObject();
			cert.setValue(new String(Base64.encode(certFromKS.getEncoded())));
			x509.getX509Certificates().add(cert);
			ki.getX509Datas().add(x509);
			kd.setKeyInfo(ki);
			sp.getKeyDescriptors().add(kd);
			
			
			
		}
		
		if (params.get("spEncKey") != null) {
			String alias = params.get("spEncKey").getValue();
			X509Certificate certFromKS = (X509Certificate) ks.getCertificate(alias);
			PrivateKey keyFromKS = (PrivateKey) ks.getKey(alias, tt.getKeyStorePassword().toCharArray());
			KeyDescriptorBuilder kdb = new KeyDescriptorBuilder();
			KeyDescriptor kd = kdb.buildObject();
			kd.setUse(UsageType.ENCRYPTION);
			KeyInfoBuilder kib = new KeyInfoBuilder();
			KeyInfo ki = kib.buildObject();
			
			X509DataBuilder x509b = new X509DataBuilder();
			X509Data x509 = x509b.buildObject();
			X509CertificateBuilder certb = new X509CertificateBuilder();
			org.opensaml.xml.signature.X509Certificate cert = certb.buildObject();
			cert.setValue(new String(Base64.encode(certFromKS.getEncoded())));
			x509.getX509Certificates().add(cert);
			ki.getX509Datas().add(x509);
			kd.setKeyInfo(ki);
			sp.getKeyDescriptors().add(kd);
			
			
			
		}
		
		
		EntityDescriptorMarshaller marshaller = new EntityDescriptorMarshaller();

		// Marshall the Subject
		Element assertionElement = marshaller.marshall(ed);

		String xml = XMLHelper.prettyPrintXML(assertionElement);
		
		System.out.println(xml);
	}

	private static void importMetaData(Options options, CommandLine cmd,
			String unisonXMLFile, TremoloType tt, String ksPath, KeyStore ks)
			throws Exception, Base64DecodingException, CertificateException,
			KeyStoreException, IOException, NoSuchAlgorithmException,
			FileNotFoundException, JAXBException, PropertyException {
		System.out.println("Finding mechanism...");
		String mechanismName = loadOption(cmd,"mechanismName",options);
		MechanismType saml2Mech = loadMechanismType(mechanismName,tt);
		System.out.println("...found");
		
		System.out.println("Finding chain...");
		String chainName = loadOption(cmd,"chainName",options);
		
		AuthChainType act = loadChainType(chainName,tt);
		
		
		boolean createDefault = cmd.hasOption("createDefault");
		System.out.println("Create default configuration? : " + createDefault);
		
		System.out.println("Loading metadata...");
		String pathToMetaData = loadOption(cmd,"pathToMetaData",options);
		System.out.println("...loaded");
		EntityDescriptor ed = loadIdPMetaData(pathToMetaData,ks,tt);
		IDPSSODescriptor idp = ed.getIDPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");
		
		System.out.println("Looking for correct mechanism on the chain...");
		AuthMechType currentMechanism = null;
		for (AuthMechType amt : act.getAuthMech()) {
			if (amt.getName().equalsIgnoreCase(mechanismName)) {
				currentMechanism = amt;
				break;
			}
		}
		
		boolean newMech = true;
		
		if (currentMechanism != null) {
			System.out.println("Updating existing mechanism");
			newMech = false;
		} else {
			System.out.println("Creating new mechanism");
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
		
		storeMethod(unisonXMLFile, tt, ksPath, ks);
	}

	private static void storeMethod(String unisonXMLFile, TremoloType tt,
			String ksPath, KeyStore ks) throws KeyStoreException, IOException,
			NoSuchAlgorithmException, CertificateException,
			FileNotFoundException, JAXBException, PropertyException {
		System.out.println("Storing the keystore");
		ks.store(new FileOutputStream(ksPath), tt.getKeyStorePassword().toCharArray());
		
		System.out.println("Saving the unison xml file");
		
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
		
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		
		DocumentBuilder builder = factory.newDocumentBuilder();

		Element root = builder
				.parse(new InputSource(new FileInputStream(pathToMetaData))).getDocumentElement();
		
		
		
		EntityDescriptor ed =  (EntityDescriptor) Configuration.getUnmarshallerFactory().getUnmarshaller(root).unmarshall(root);
		
		
		
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
			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp( "OpenUnisonUtils", options );
			System.exit(1);
			return null;
		} else {
			return val;
		}
	}

}



/*
Copyright 2022 Tremolo Security, Inc.

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

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import org.apache.commons.codec.binary.Hex;
import org.apache.xml.security.utils.Base64;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorMarshaller;
import org.opensaml.saml.saml2.metadata.impl.IDPSSODescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.KeyDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.NameIDFormatBuilder;
import org.opensaml.saml.saml2.metadata.impl.SingleSignOnServiceBuilder;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.impl.KeyInfoBuilder;
import org.opensaml.xmlsec.signature.impl.X509CertificateBuilder;
import org.opensaml.xmlsec.signature.impl.X509DataBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Element;

import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.TrustType;
import com.tremolosecurity.proxy.util.OpenSAMLUtils;
import com.tremolosecurity.server.GlobalEntries;

public class Saml2MetadataUtils {
	public static String generateIdpMetadata(String idpName,String baseURL) throws Exception {
		InitializationService.initialize();
		
		
		KeyStore ks = GlobalEntries.getGlobalEntries().getConfigManager().getKeyStore();
		
		ApplicationType idp = null;
		
		for (ApplicationType app : GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getApplications().getApplication()) {
			if (app.getName().equalsIgnoreCase(idpName)) {
				idp = app;
			}
		}
		
		if (idp == null) {
			throw new Exception("IdP '" + idpName + "' not found");
		}
		
		
		
		baseURL = baseURL.substring(0,baseURL.indexOf('/',9));
		
		
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
		
		
		 
		
		// Get the Subject marshaller
		EntityDescriptorMarshaller marshaller = new EntityDescriptorMarshaller();

		// Marshall the Subject
		Element assertionElement = marshaller.marshall(ed);
		
		

		return net.shibboleth.utilities.java.support.xml.SerializeSupport.nodeToString(assertionElement);
	}
}

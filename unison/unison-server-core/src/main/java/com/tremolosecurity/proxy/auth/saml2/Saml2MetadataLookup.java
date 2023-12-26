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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;
import org.apache.xml.security.c14n.Canonicalizer;
import org.cryptacular.util.CertUtil;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.UsageType;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.StringUtils;

import com.tremolosecurity.server.GlobalEntries;

import edu.emory.mathcs.backport.java.util.Arrays;

public class Saml2MetadataLookup {
	static Logger logger = Logger.getLogger(Saml2MetadataLookup.class);
	String metadataURL;
	
	String entityID;
	String ssoPostURL;
	String ssoRedirectURL;
	String sloRedirectURL;
	String sloPostURL;
	
	String sigCertName;
	
	byte[] currentDigest;
	
	
	
	public Saml2MetadataLookup(String metadataURL,String sigCertName) {
		this.metadataURL = metadataURL;
		this.sigCertName = sigCertName;
		
		this.currentDigest = null;

		
	}
	
	public synchronized void pullMetaData() throws Exception {
		
		String metadata;
		
		if (this.metadataURL.startsWith("http")) {
		
			// first thing is to retrieve the metadata
			BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(GlobalEntries.getGlobalEntries().getConfigManager().getHttpClientSocketRegistry());
			RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).build();
			CloseableHttpClient http = HttpClients.custom().setConnectionManager(bhcm).setDefaultRequestConfig(rc).build();
			
			
			
			try {
				HttpGet metadataOp = new HttpGet(this.metadataURL);
				CloseableHttpResponse resp = http.execute(metadataOp);
				metadata = EntityUtils.toString(resp.getEntity());
				resp.close();
			
			} finally {
				try {
					if (http != null) {
						http.close();
					}
				} catch (IOException e) {
					
				}
				
				try {
					if (bhcm != null) {
						bhcm.close();
					}
				} finally {
					
				}
				
			}
		} else  {
			//metadata = new String(Files.   (this.metadataURL).readAllBytes());
			metadata = new String(Files.readAllBytes(new File(this.metadataURL).toPath()));
		}
		
		// clear all excess whitespace
		metadata = this.removeBom(metadata.strip());
		
		
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		Canonicalizer canon = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
		canon.canonicalize(metadata.getBytes("UTF-8"),baos,true);
		
		
		MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
		byte[] canonXml = baos.toByteArray(); 
		digest.update(canonXml);
		
		byte[] newDigest = digest.digest();
		
		if (this.currentDigest == null || ! Arrays.equals(this.currentDigest, newDigest)) {
			
			logger.warn(new StringBuilder().append("Metadata '").append(this.metadataURL).append("' has changed, updating").toString());
		
			InitializationService.initialize();
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setNamespaceAware(true);
			DocumentBuilder builder = factory.newDocumentBuilder();
			Element root = builder.parse(new InputSource(new ByteArrayInputStream(metadata.getBytes("UTF-8")))).getDocumentElement();
			EntityDescriptor ed =  (EntityDescriptor) XMLObjectSupport.getUnmarshaller(root).unmarshall(root);
			IDPSSODescriptor idp = ed.getIDPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");
			
			this.entityID = ed.getEntityID();
			
			for (SingleSignOnService sso : idp.getSingleSignOnServices() ) {
				if (sso.getBinding().equalsIgnoreCase("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")) {
					this.ssoPostURL = sso.getLocation();
				} else if (sso.getBinding().equalsIgnoreCase("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")) {
					this.ssoRedirectURL = sso.getLocation();
				}
			}
			
			for (SingleLogoutService slo : idp.getSingleLogoutServices()) {
				if (slo.getBinding().equalsIgnoreCase("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")) {
					this.sloRedirectURL = slo.getLocation();
				}
			}
			
			int i = 0,j = 0;
			for (KeyDescriptor kd : idp.getKeyDescriptors()) {
				
				if (kd.getUse().equals(UsageType.SIGNING)) {
					String base64 = kd.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0).getValue();
					String name;
					
					if (i == 0) {
						name = this.sigCertName;
					} else {
						name = new StringBuilder().append(this.sigCertName).append("-").append(i).toString();
					}
					
					i++;
					
					base64 = StringUtils.deleteWhitespace(base64);
					
					GlobalEntries.getGlobalEntries().getConfigManager().getKeyStore().setCertificateEntry(name, CertUtil.decodeCertificate(Base64.getDecoder().decode(base64)));
					
					
				}
				
				
				
				
				
				
			}
			
			this.currentDigest = newDigest;
		
		} else {
			logger.debug(new StringBuilder().append("Metadata '").append(this.metadataURL).append("' has not changed").toString());
		}
		
		
		
	}
	
	private  boolean isContainBOM(String metadata) throws IOException {

	      
	      boolean result = false;

	      byte[] bom = new byte[3];
	      try (InputStream is = new ByteArrayInputStream(metadata.getBytes())) {

	          // read 3 bytes of a file.
	          is.read(bom);

	          // BOM encoded as ef bb bf
	          String content = new String(Hex.encodeHex(bom));
	          if ("efbbbf".equalsIgnoreCase(content)) {
	              result = true;
	          }

	      }

	      return result;
	  }
	
	private String removeBom(String metadata) throws IOException {

	      if (isContainBOM(metadata)) {

	          byte[] bytes = metadata.getBytes();

	          ByteBuffer bb = ByteBuffer.wrap(bytes);

	          

	          byte[] bom = new byte[3];
	          // get the first 3 bytes
	          bb.get(bom, 0, bom.length);

	          // remaining
	          byte[] contentAfterFirst3Bytes = new byte[bytes.length - 3];
	          bb.get(contentAfterFirst3Bytes, 0, contentAfterFirst3Bytes.length);

	          

	          return new String(contentAfterFirst3Bytes);

	      } else {
	          return metadata;
	      }

	  }

	


	public String getMetadataURL() {
		return metadataURL;
	}

	public String getEntityID() {
		return entityID;
	}

	public String getSsoPostURL() {
		return ssoPostURL;
	}

	public String getSsoRedirectURL() {
		return ssoRedirectURL;
	}

	public String getSloRedirectURL() {
		return sloRedirectURL;
	}

	public String getSloPostURL() {
		return sloPostURL;
	}

	public String getSigCertName() {
		return sigCertName;
	}
}

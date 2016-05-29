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


package com.tremolosecurity.proxy.auth.ssl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Vector;

import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.saml.Attribute;

public class OCSP implements CRLManager {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(OCSP.class.getName());
	String url;
	
	
	@Override
	public void init(String name, HashMap<String, Attribute> init,
			ConfigManager mgr) throws Exception {
		this.url = init.get("crl." + name + ".path").getValues().get(0);

	}

	@Override
	public boolean isValid(X509Certificate cert, X509Certificate issuer) {
		try {
			OCSPReq ocspRequest = generateOcspRequest(issuer,cert.getSerialNumber());
			URL url = new URL(this.url);
			HttpURLConnection url_con = (HttpURLConnection)url.openConnection(); 
	
			url_con.setDoOutput(true); 
			url_con.connect();
			OutputStream os = url_con.getOutputStream(); 
			os.write(ocspRequest.getEncoded());
			
			InputStream is = url_con.getInputStream(); 
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			
			byte[] buffer = new byte[1024];
			int len = 0;
			
			do {
				len = is.read(buffer);
				if (len > 0) {
					baos.write(buffer, 0, len);
				}
			} while (len > 0);
			
			ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
			
	
			OCSPResp ocspResponse = new OCSPResp(bais); 
			
			BasicOCSPResp resp = (BasicOCSPResp) ocspResponse.getResponseObject();
			
			//System.err.println(resp.getResponses()[0].getCertStatus());
			
			return resp.getResponses()[0].getCertStatus() == null || (! (resp.getResponses()[0].getCertStatus() instanceof org.bouncycastle.cert.ocsp.RevokedStatus));
			
		} catch (Exception e) {
			logger.error("Error validating certificate",e);
			return false;
		}
	}

	@Override
	public void validate() {
		

	}
	
	private OCSPReq generateOcspRequest(X509Certificate issuerCert,
			BigInteger serialNumber) throws OCSPException, CertificateEncodingException, OperatorCreationException, IOException {

		BcDigestCalculatorProvider util = new BcDigestCalculatorProvider();
		
		// Generate the id for the certificate we are looking for
		CertificateID id = new CertificateID(util.get(  CertificateID.HASH_SHA1),
				new X509CertificateHolder(issuerCert.getEncoded()), serialNumber);
		OCSPReqBuilder ocspGen = new OCSPReqBuilder();
        
        ocspGen.addRequest(id);

		BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
		Extension ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true, new DEROctetString(nonce.toByteArray()));
        ocspGen.setRequestExtensions(new Extensions(new Extension[] { ext }));

        return ocspGen.build();
	}

}

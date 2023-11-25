/*******************************************************************************
 * Copyright 2015 Tremolo Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.proxy.auth.ssl.util;

import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import jakarta.servlet.ServletException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.GeneralName;

import com.tremolosecurity.proxy.auth.CertificateExtractSubjectAttribute;

public class UpnExtractor implements CertificateExtractSubjectAttribute {

	@Override
	public void addSubjects(HashMap<String, String> subjects, X509Certificate[] certs) throws ServletException {
		String upn;
		try {
			upn = loadNTPrincipal(certs);
			if (upn != null) {
				subjects.put("userPrincipalName", upn);
			}
		} catch (CertificateParsingException | IOException e) {
			throw new ServletException("Could not set piv identifier",e);
		}
		

	}
	
	private String loadNTPrincipal(X509Certificate[] certs) throws CertificateParsingException, IOException {
		X509Certificate cert = certs[0];
		Collection<List<?>> subjectAlternativeNames = cert.getSubjectAlternativeNames();
        if( subjectAlternativeNames != null && ! subjectAlternativeNames.isEmpty() ){
        	for( List<?> subjectAltName : subjectAlternativeNames ){
              if( ((Integer) subjectAltName.get(0)) == GeneralName.otherName ){
                  ASN1InputStream asn1Input = new ASN1InputStream((byte[]) subjectAltName.get(1));
                  ASN1Primitive derObject = asn1Input.readObject();
                  DLSequence seq = (DLSequence) derObject;
                  ASN1ObjectIdentifier id = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
                  if (id.getId().equals("1.3.6.1.4.1.311.20.2.3")) {
                      ASN1TaggedObject obj = (ASN1TaggedObject) seq.getObjectAt(1);
                      
                      DERUTF8String str =  null;
                      while (str == null) {
                    	  
	                      if (obj.getExplicitBaseObject() instanceof DERTaggedObject) {
	                    	  obj = (ASN1TaggedObject) obj.getExplicitBaseObject();
	                      } else if (obj.getExplicitBaseObject() instanceof DERUTF8String) {
	                    	  str = (DERUTF8String) obj.getExplicitBaseObject();
	                      } else {
	                    	  asn1Input.close();
	                    	  return null;
	                      }
                      }
                      asn1Input.close();
                      return str.getString();
                  }
              }
        	}
        }
        return null;
	}

}

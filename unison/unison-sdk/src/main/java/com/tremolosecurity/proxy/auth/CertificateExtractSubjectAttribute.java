package com.tremolosecurity.proxy.auth;

import java.security.cert.X509Certificate;
import java.util.HashMap;

import javax.servlet.ServletException;

/**
 * Implement this class to extract a subject attribute from a certificate
 *
 */
public interface CertificateExtractSubjectAttribute {
	
	/**
	 * Implement this method to add values to the list of potential subjects
	 * @param subjects 
	 * @param certs
	 * @throws ServletException
	 */
	public void addSubjects(HashMap<String,String> subjects,X509Certificate[] certs) throws ServletException;

}

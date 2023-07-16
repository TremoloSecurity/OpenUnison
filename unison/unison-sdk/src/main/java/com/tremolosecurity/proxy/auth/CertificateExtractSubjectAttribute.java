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
package com.tremolosecurity.proxy.auth;

import java.security.cert.X509Certificate;
import java.util.HashMap;

import jakarta.servlet.ServletException;

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

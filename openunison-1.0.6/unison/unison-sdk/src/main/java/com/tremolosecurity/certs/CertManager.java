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


package com.tremolosecurity.certs;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import javax.crypto.SecretKey;


import com.tremolosecurity.util.NVP;

public interface CertManager {

	public abstract ArrayList<String> getSslKeys();

	public abstract ArrayList<NVP> getSslKeysList();

	public abstract ArrayList<String> getSessionKeys();

	public abstract ArrayList<NVP> getSessionKeysList();

	public abstract ArrayList<String> getLocalKeys();

	public abstract ArrayList<NVP> getLocalKeysList();

	public abstract ArrayList<String> getRemoteCerts();

	public abstract ArrayList<NVP> getRemoteCertsList();

	public abstract ArrayList<String> getLastMilKeys();

	public abstract ArrayList<NVP> getLastMilKeysList();

	public abstract void reload() throws Exception;

	public abstract ArrayList<String> getTrustedCerts();

	public abstract ArrayList<NVP> getTrustedCertsList();

	public abstract X509Certificate getCert(String alias) throws Exception;

	public abstract SecretKey getSecretKey(String alias) throws Exception;

	public abstract String generateCSR(String alias) throws Exception;

	public abstract String exportCert(String alias, boolean add)
			throws Exception;

	public abstract void createKey(String alias) throws Exception;

	public abstract void createCertificate(CertData certData) throws Exception;

	public abstract void generateKeyStore(String[] aliases, String storePass,
			OutputStream out) throws Exception;

	public abstract void storeCert(String alias, byte[] cert) throws Exception;

	public abstract void remove(String alias) throws Exception;

	public abstract PrivateKey getPrivateKey(String alias) throws Exception;

	public abstract boolean isTrusted(X509Certificate cert) throws Exception;

	public abstract void resetPassword(String keyStorePassword)
			throws Exception;
	
	public abstract void importKey(String alias,PrivateKey privateKey,X509Certificate cert) throws Exception;

	public abstract void importKey(String alias, byte[] key) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException;

}
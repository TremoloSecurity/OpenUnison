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


package com.tremolosecurity.config.util;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;

import javax.crypto.SecretKey;
import javax.net.ssl.KeyManagerFactory;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.xml.bind.JAXBException;

import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.HttpParams;

import com.novell.ldap.LDAPException;
import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.MechanismType;
import com.tremolosecurity.config.xml.ResultGroupType;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.provisioning.core.ProvisioningEngine;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.auth.AuthMechanism;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.server.StopableThread;


public interface UnisonConfigManager {



	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getConfigXmlPath()
	 */
	public abstract String getConfigXmlPath();

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getAuthMechs()
	 */
	public abstract HashMap<String, MechanismType> getAuthMechs();

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getCfg()
	 */
	public abstract TremoloType getCfg();

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#initialize()
	 */
	public abstract void initialize(String name) throws JAXBException, Exception,
			IOException, FileNotFoundException, InstantiationException,
			IllegalAccessException, ClassNotFoundException, LDAPException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException,
			ProvisioningException;

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getAuthChains()
	 */
	public abstract HashMap<String, AuthChainType> getAuthChains();

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#findURL(java.lang.String)
	 */
	public abstract UrlHolder findURL(String url) throws Exception;

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getResultGroup(java.lang.String)
	 */
	public abstract ResultGroupType getResultGroup(String name);

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getMyVD()
	 */
	public abstract MyVDConnection getMyVD();

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getSecretKey(java.lang.String)
	 */
	public abstract SecretKey getSecretKey(String alias);

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getApp(java.lang.String)
	 */
	public abstract ApplicationType getApp(String name);

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#loadFilters()
	 */
	public abstract void loadFilters();

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#loadAuthMechs()
	 */
	public abstract void loadAuthMechs() throws ServletException;

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getAuthMech(java.lang.String)
	 */
	public abstract AuthMechanism getAuthMech(String uri);

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getCertificate(java.lang.String)
	 */
	public abstract X509Certificate getCertificate(String alias);

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getProvisioningEngine()
	 */
	public abstract ProvisioningEngine getProvisioningEngine();

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#reloadConfig()
	 */
	public abstract void reloadConfig() throws Exception;

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getPrivateKey(java.lang.String)
	 */
	public abstract PrivateKey getPrivateKey(String alias);

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getKeyStore()
	 */
	public abstract KeyStore getKeyStore();

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getKeyManagerFactory()
	 */
	public abstract KeyManagerFactory getKeyManagerFactory();

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#addThread(com.tremolosecurity.server.StopableThread)
	 */
	public abstract void addThread(StopableThread r);

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#clearThreads()
	 */
	public abstract void clearThreads();



	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#addReloadNotifier(com.tremolosecurity.config.util.ReloadNotification)
	 */
	public abstract void addReloadNotifier(ReloadNotification notifier);

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#notifyReload()
	 */
	public abstract void notifyReload();

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#isForceToSSL()
	 */
	public abstract boolean isForceToSSL();

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getOpenPort()
	 */
	public abstract int getOpenPort();

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getSecurePort()
	 */
	public abstract int getSecurePort();

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getExternalOpenPort()
	 */
	public abstract int getExternalOpenPort();

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getExternalSecurePort()
	 */
	public abstract int getExternalSecurePort();

	

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#createAnonUser(javax.servlet.http.HttpSession)
	 */
	public abstract void createAnonUser(HttpSession sharedSession);

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getAuthPath()
	 */
	public abstract String getAuthPath();

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getAuthFormsPath()
	 */
	public abstract String getAuthFormsPath();

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getAuthIdPPath()
	 */
	public abstract String getAuthIdPPath();

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getPaasUserPrinicipalAttribute()
	 */
	public abstract String getPaasUserPrinicipalAttribute();

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#setPaasUserPrinicipalAttribute(java.lang.String)
	 */
	public abstract void setPaasUserPrinicipalAttribute(
			String paasUserPrinicipalAttribute);

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getPaasRoleAttribute()
	 */
	public abstract String getPaasRoleAttribute();

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#setPaasRoleAttribute(java.lang.String)
	 */
	public abstract void setPaasRoleAttribute(String paasRoleAttribute);

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getContextPath()
	 */
	public abstract String getContextPath();

	/* (non-Javadoc)
	 * @see com.tremolosecurity.config.util.ConfigManager#getContext()
	 */
	public abstract ServletContext getContext();

}
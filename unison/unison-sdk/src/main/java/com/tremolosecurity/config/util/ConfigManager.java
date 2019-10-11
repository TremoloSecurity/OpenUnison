/*
Copyright 2015, 2018 Tremolo Security, Inc.

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
import java.util.Map;

import javax.crypto.SecretKey;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.xml.bind.JAXBException;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.config.Registry;
import org.apache.http.conn.socket.ConnectionSocketFactory;
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
import com.tremolosecurity.proxy.HttpUpgradeRequestManager;
import com.tremolosecurity.proxy.auth.AuthMechanism;
import com.tremolosecurity.proxy.auth.sys.AuthManager;
import com.tremolosecurity.proxy.az.CustomAuthorization;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.server.StopableThread;


/**
 * The ConfigManager is the connection into all of Unison's resources and configurations
 */
public interface ConfigManager {

	/**
	 * Returns the error pages
	 */
	public abstract Map<Integer,String> getErrorPages();

	/**
	 * Returns the full path to Unison's XML configuration
	 * @return
	 */
	public abstract String getConfigXmlPath();

	/**
	 * Returns a map of all configured authentication mechanism configurations
	 * @return
	 */
	public abstract HashMap<String, MechanismType> getAuthMechs();

	/**
	 * Returns the un-marshaled XML configuration
	 * @return
	 */
	public abstract TremoloType getCfg();

	/**
	 * Initializes a Unison configuration
	 * @param registryName 
	 * @throws JAXBException
	 * @throws Exception
	 * @throws IOException
	 * @throws FileNotFoundException
	 * @throws InstantiationException
	 * @throws IllegalAccessException
	 * @throws ClassNotFoundException
	 * @throws LDAPException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws ProvisioningException
	 */
	public abstract void initialize(String registryName) throws JAXBException, Exception,
			IOException, FileNotFoundException, InstantiationException,
			IllegalAccessException, ClassNotFoundException, LDAPException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException,
			ProvisioningException;

	
	/**
	 * Returns a map of Authentication Chain configurations based on the name of the chain
	 * @return
	 */
	public abstract HashMap<String, AuthChainType> getAuthChains();

	/**
	 * Finds an application configuration based on a URL
	 * @param url
	 * @return
	 * @throws Exception
	 */
	public abstract UrlHolder findURL(String url) throws Exception;

	/**
	 * Returns a Result Group configuration based on its name
	 * @param name
	 * @return
	 */
	public abstract ResultGroupType getResultGroup(String name);

	/**
	 * Return the internal MyVD connection, can be used for searches and authentication
	 * @return
	 */
	public abstract MyVDConnection getMyVD();

	/**
	 * Returns a secret key from Unison's key store
	 * @param alias
	 * @return
	 */
	public abstract SecretKey getSecretKey(String alias);

	/**
	 * Returns an application configuration based on the application's name
	 * @param name
	 * @return
	 */
	public abstract ApplicationType getApp(String name);

	/**
	 * Loads all filter configurations, DO NOT CALL
	 */
	public abstract void loadFilters();

	/**
	 * Loads all authentication mechanisms, DO NOT CALL
	 * @throws ServletException
	 */
	public abstract void loadAuthMechs() throws ServletException;

	/**
	 * Retrieves an authentication mechanism implementation based on the URI of a request
	 * @param uri
	 * @return
	 */
	public abstract AuthMechanism getAuthMech(String uri);
	
	
	/**
	 * Retrieves a certificate from Unison's internal certificate store
	 * @param alias
	 * @return
	 */
	public abstract X509Certificate getCertificate(String alias);

	/**
	 * Retrieves the Unison provisioning subsystem
	 * @return
	 */
	public abstract ProvisioningEngine getProvisioningEngine();

	/**
	 * Reloads all configuration items, clears all threads
	 * @throws Exception
	 */
	public abstract void reloadConfig() throws Exception;
	
	
	/**
	 * Returns a private key from Unison's internal key store
	 * @param alias
	 * @return
	 */
	public abstract PrivateKey getPrivateKey(String alias);

	/**
	 * Returns Unison's key store
	 * @return
	 */
	public abstract KeyStore getKeyStore();

	
	/**
	 * Returns Unison's Key Management Factory
	 * @return
	 */
	public abstract KeyManagerFactory getKeyManagerFactory();

	/**
	 * Adds a thread to the managed list of threads.  Useful for "clean up" processes
	 * @param r
	 */
	public abstract void addThread(StopableThread r);

	/**
	 * Stop all threads and clear them from Unison
	 */
	public abstract void clearThreads();

	/**
	 * Returns the global htto client configuration
	 * @return
	 */
	public abstract RequestConfig getGlobalHttpClientConfig();

	/**
	 * Returns the protocol registry for the http client
	 * @return
	 */
	public abstract Registry<ConnectionSocketFactory> getHttpClientSocketRegistry();
	
	/**
	 * Provide notifications to classes when the configuration is reloaded
	 * @param notifier
	 */
	public abstract void addReloadNotifier(ReloadNotification notifier);

	
	/**
	 * Notify listeners that the configuration is bring reloaded
	 */
	public abstract void notifyReload();

	
	/**
	 * True if all connections in plain text are to be redirected to encrypted text (HTTP/S only)
	 * @return
	 */
	public abstract boolean isForceToSSL();

	/**
	 * Returns the open port this service is listening on
	 * @return
	 */
	public abstract int getOpenPort();
	
	/**
	 * Returns the secure port this service is listening on
	 * @return
	 */
	public abstract int getSecurePort();

	/**
	 * Returns the open port, as seen by a client.  For instance if Unison
	 * is running on port 8080 but there is a firewall port forwarding from
	 * port 80 this would return 80
	 * @return
	 */
	public abstract int getExternalOpenPort();

	
	/**
	 * Returns the secure port, as seen by a client.  For instance if Unison
	 * is running on port 8443 but there is a firewall port forwarding from
	 * port 443 this would return 443
	 * @return
	 */
	public abstract int getExternalSecurePort();



	
	/**
	 * Resets the session's state to an anonymous user
	 * @param sharedSession
	 */
	public abstract void createAnonUser(HttpSession sharedSession);

	/**
	 * Returns the path to Unison's "auth" directory.  If Unison is embedded this directory can be at different levels
	 * @return
	 */
	public abstract String getAuthPath();
	
	/**
	 * Returns where Unison stores JSP pages for authentication (typically /auth/forms).  If 
	 * Unison is embedded this path may change.
	 * @return
	 */
	public abstract String getAuthFormsPath();

	/**
	 * Returns the path where Unison identity providers are configured.  Typicaly /auth/idp however this
	 * may change if Unison is embedded.
	 * @return
	 */
	public abstract String getAuthIdPPath();

	
	/**
	 * When Unison is embedded, returns the name of the user attribute that will act as the user identifier.
	 * @return
	 */
	public abstract String getPaasUserPrinicipalAttribute();

	/**
	 * When Unison is embedded, sets the name of the user attribute that will act as the user identifier.
	 * @return
	 */
	public abstract void setPaasUserPrinicipalAttribute(
			String paasUserPrinicipalAttribute);

	/**
	 * When Unison is embedded, returns the name of the user attribute that will act as the roles identifier.
	 * @return
	 */
	public abstract String getPaasRoleAttribute();

	/**
	 * When Unison is embedded, sets the name of the user attribute that will act as the roles identifier.
	 * @return
	 */
	public abstract void setPaasRoleAttribute(String paasRoleAttribute);

	/**
	 * Returns the context path for Unison
	 * @return
	 */
	public abstract String getContextPath();

	/**
	 * Returns Unison's servlet context
	 * @return
	 */
	public abstract ServletContext getContext();
	
	public abstract AuthManager getAuthManager();
	
	
	/**
	 * Returns a map of custom authorization implementations and names
	 * @return
	 */
	public abstract Map<String,CustomAuthorization> getCustomAuthorizations();

	/**
	 * Returns an implementation of the upgrade manager
	 * @return
	 */
	public abstract HttpUpgradeRequestManager getUpgradeManager();
	
	
	/**
	 * Returns the SSLContext
	 * @return
	 */
	public abstract SSLContext getSSLContext();
	
	

}
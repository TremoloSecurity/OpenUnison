/*******************************************************************************
 * Copyright 2017, 2018 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.openunison.undertow;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;
import javax.servlet.DispatcherType;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import com.tremolosecurity.openunison.util.config.OpenUnisonConfigLoader;
import io.undertow.UndertowOptions;
import org.apache.jasper.deploy.JspPropertyGroup;
import org.apache.jasper.deploy.TagLibraryInfo;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.xnio.Options;
import org.xnio.Sequence;
import org.yaml.snakeyaml.Yaml;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.openunison.OpenUnisonServletFilter;
import com.tremolosecurity.server.GlobalEntries;

import io.undertow.Handlers;
import io.undertow.Undertow;
import io.undertow.Undertow.Builder;
import io.undertow.jsp.HackInstanceManager;
import io.undertow.jsp.JspServletBuilder;
import io.undertow.server.handlers.PathHandler;
import io.undertow.server.handlers.RedirectHandler;
import io.undertow.server.handlers.resource.FileResourceManager;
import io.undertow.servlet.Servlets;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.DeploymentManager;
import io.undertow.servlet.api.ErrorPage;

public class OpenUnisonOnUndertow {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(OpenUnisonOnUndertow.class.getName());
	static Gson gson = new GsonBuilder().setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES).create();
	static Undertow undertow;
	
	public static void main(String[] args) throws Exception {
		OpenUnisonConfig config = null;
		logger.info("Starting OpenUnison on Undertow " + OpenUnisonServletFilter.version);
		if (args.length == 0) {
			logger.error("One argument required, path to yaml or json config");
			System.exit(1);
		} else if (args[0].endsWith(".yaml")) {
			logger.info("Parsing YAML : '" + args[0] + "'");
			Yaml yaml = new Yaml();
			Map<String,Object> map= (Map<String, Object>) yaml.load(new FileInputStream(args[0]));
			JSONObject jsonObject=new JSONObject(map);
			String json = jsonObject.toJSONString();
			config = gson.fromJson(json, OpenUnisonConfig.class);
		} else {
			logger.info("Parsing JSON : '" + args[0] + "'");
			
			config = gson.fromJson(new InputStreamReader(new FileInputStream(args[0])), OpenUnisonConfig.class);
		}
		
		final OpenUnisonConfig fconfig = config;


		if (config.getContextRoot() == null) {
			config.setContextRoot("/");
		}

		

		logger.info("Config Open Port : '" + config.getOpenPort() + "'");
		logger.info("Disable HTTP2 : '" + config.isDisableHttp2() + "'");
		logger.info("Allow unescaped characters : '" + config.isAllowUnEscapedChars() + "'");
		logger.info("Config Open External Port : '" + config.getOpenExternalPort() + "'");
		logger.info("Config Secure Port : '" + config.getSecurePort() + "'");
		logger.info("Config Secure External Port : '" + config.getSecureExternalPort() + "'");
		logger.info("Config Context Root :  '" + config.getContextRoot() + "'");
		logger.info("Force to Secure : '" + config.isForceToSecure() + "'");
		logger.info("ActiveMQ Directory : '" + config.getActivemqDir() + "'");
		logger.info("Quartz Directory : '" + config.getQuartzDir() + "'");
		logger.info("Config TLS Client Auth Mode : '" + config.getClientAuth() + "'");
		logger.info("Config TLS Allowed Client Subjects : '" + config.getAllowedClientNames() + "'");
		logger.info("Config TLS Protocols : '" + config.getAllowedTlsProtocols() + "'");
		logger.info("Config TLS Ciphers : '" + config.getCiphers() + "'");
		logger.info("Config Path to Deployment : '" + config.getPathToDeployment() + "'");
		logger.info("Config Path to Environment File : '" + config.getPathToEnvFile() + "'");
		logger.info("Redirect to contex root : '" + config.isRedirectToContextRoot() + "'");
		logger.info("Support socket shutdown : " + config.isSocketShutdownListener());
		if (config.isSocketShutdownListener()) {
			logger.info("Socket shutdown host : '" + config.getSocketShutdownHost() + "'");
			logger.info("Socket shutdown port : '" + config.getSocketShutdownPort() + "'");
			logger.info("Socket shutdown command : '" + config.getSocketShutdownCommand() + "'");
		}

		logger.info("Creating unisonServiceProps");
		
		File f = File.createTempFile("unisonService", "props");
		logger.info("Temporary unisonServiceProps : '" + f.getAbsolutePath() + "'");
		Properties unisonServiceProps = new Properties();
		unisonServiceProps.put("com.tremolosecurity.openunison.forceToSSL",Boolean.toString(config.isForceToSecure()));
		unisonServiceProps.put("com.tremolosecurity.openunison.openPort",Integer.toString(config.getOpenPort()));
		unisonServiceProps.put("com.tremolosecurity.openunison.securePort", Integer.toString(config.getSecurePort()));
		unisonServiceProps.put("com.tremolosecurity.openunison.externalOpenPort",Integer.toString(config.getOpenExternalPort()));
		unisonServiceProps.put("com.tremolosecurity.openunison.externalSecurePort", Integer.toString(config.getSecureExternalPort()));
		
		if (config.getActivemqDir() != null) {
			unisonServiceProps.put("com.tremolosecurity.openunison.activemqdir", config.getActivemqDir());
		}
		
		if (config.getQuartzDir() != null) {
			unisonServiceProps.put("com.tremolosecurity.openunison.quartzdir", config.getQuartzDir());
		}

		
		
		unisonServiceProps.store(new FileOutputStream(f), "OpenUnison Configuration");
		System.getProperties().put("com.tremolosecurity.unison.unisonServicePropsPath", f.getAbsolutePath());
		System.getProperties().put("com.tremolosecurity.unison.unisonXML", config.getPathToDeployment() + "/webapp/WEB-INF/unison.xml");
		
		logger.info("Loading environment file : '" + config.getPathToEnvFile() + "'");
		
		Properties env = new Properties();
		env.load(new FileInputStream(config.getPathToEnvFile()));
		
		for (Object name : env.keySet()) {
			logger.info("Adding property : '" + name + "'");
			System.setProperty((String) name,env.getProperty((String) name));
		}
		
		logger.info("Loading keystore for Undertow");
		
		String unisonXML = config.getPathToDeployment() + "/webapp/WEB-INF/unison.xml";
		
		logger.info("OpenUnison XML File : '" + unisonXML + "'");
		
		String unisonXMLContent = OpenUnisonConfigLoader.generateOpenUnisonConfig(unisonXML);





		JAXBContext jc = JAXBContext.newInstance("com.tremolosecurity.config.xml");
		Unmarshaller unmarshaller = jc.createUnmarshaller();
		
		Object obj = unmarshaller.unmarshal(new ByteArrayInputStream(unisonXMLContent.getBytes("UTF-8")));
		
		JAXBElement<TremoloType> cfg = (JAXBElement<TremoloType>) obj;
		
		TremoloType unisonConfiguration = cfg.getValue();
		
		logger.info("Loading keystore : '" + unisonConfiguration.getKeyStorePath() + "'");
		
		logger.info("Building Undertow");
		Builder buildUndertow = Undertow.builder();

		buildUndertow.setServerOption(UndertowOptions.NO_REQUEST_TIMEOUT,60000);
		
		logger.info("Check if enabling HTTP2 - " + config.isDisableHttp2());
		if (! config.isDisableHttp2()) {
			logger.info("Enabling HTTP2");
			buildUndertow.setServerOption(UndertowOptions.ENABLE_HTTP2, true);
			
		}

		if (config.getOpenPort() > 0) {
			buildUndertow.addHttpListener(config.getOpenPort(), "0.0.0.0");
			logger.info("Adding open port : '" + config.getOpenPort() + "'");
		}
		
		if (config.getSecurePort() > 0) {
			setupTlsListener(config, unisonConfiguration, buildUndertow);
		}
		
		File pathToWebApp = new File(config.getPathToDeployment() + "/webapp");
		logger.info("Path to webapp : '" + pathToWebApp.getAbsolutePath() + "'");
		logger.info("Path directory? : '" + pathToWebApp.isDirectory() + "'");
		logger.info("Path exists : '" + pathToWebApp.exists() + "'");
		
		
		DeploymentInfo servletBuilder = Servlets.deployment()  
				.setClassLoader(OpenUnisonOnUndertow.class.getClassLoader())
                .setEagerFilterInit(true)
				.setContextPath(config.getContextRoot())
                .setDeploymentName("openunison")
                .addFilter(
                		
	                		Servlets.filter("openunison",com.tremolosecurity.openunison.OpenUnisonServletFilter.class)
	                		.addInitParam("mode", "appliance")
                		
                		
                )
                .addFilterUrlMapping("openunison", "/*", DispatcherType.REQUEST)
                .setResourceManager(new FileResourceManager(pathToWebApp,1024,true))
                .addServlet(JspServletBuilder.createServlet("Default Jsp Servlet", "*.jsp"))
                .addServlet(
                		Servlets.servlet("identityProvider",com.tremolosecurity.idp.server.IDP.class)
                		.addMapping("/auth/idp/*")
						);
						
		if (config.getWelcomePages() != null) {
			servletBuilder.addWelcomePages(config.getWelcomePages());
		}

		if (config.getErrorPages() != null) {
			logger.info("Adding error pages");
			ArrayList<ErrorPage> errorPages = new ArrayList<ErrorPage>();
			for (ErrorPageConfig ep : config.getErrorPages()) {
				if (ep.getCode() == 0) {
					logger.info("Adding default page: " + ep.getLocation());
					errorPages.add(new ErrorPage(ep.getLocation()));
				} else {
					logger.info("Adding page for " + ep.getCode() + " : " + ep.getLocation());
					errorPages.add(new ErrorPage(ep.getLocation(),ep.getCode()));
				}
			}
			servletBuilder.addErrorPages(errorPages);
		}
		
		
		JspServletBuilder.setupDeployment(servletBuilder, new HashMap<String, JspPropertyGroup>(), new HashMap<String, TagLibraryInfo>(), new HackInstanceManager());
		
		DeploymentManager manager = Servlets.defaultContainer().addDeployment(servletBuilder);



		manager.deploy();
		
		
		PathHandler path = Handlers.path(Handlers.redirect(config.getContextRoot()))
				.addPrefixPath(config.getContextRoot(), manager.start());
				
		

        if (config.isForceToLowerCase()) {
			buildUndertow.setHandler(new OpenUnisonPathHandler(path));
		} else {
			buildUndertow.setHandler(path);
		}


		if (! config.getContextRoot().equals("/")) {
			if (! config.isRedirectToContextRoot()) {
				logger.info("Not redirecting to context");
				servletBuilder = Servlets.deployment()
						.setClassLoader(OpenUnisonOnUndertow.class.getClassLoader())
						.setEagerFilterInit(true)
						.setContextPath("/")
						.setDeploymentName("root");
				manager = Servlets.defaultContainer().addDeployment(servletBuilder);
				manager.deploy();

				path.addPrefixPath("/",manager.start());
			} else {
				logger.info("Redirecting to context");
				path.addPrefixPath("/", new RedirectHandler(config.getContextRoot()));
			}
			


		}

		


		if (config.isAllowUnEscapedChars()) {
			buildUndertow.setServerOption(UndertowOptions.ALLOW_UNESCAPED_CHARACTERS_IN_URL, true);
		}

		undertow = buildUndertow.build();
		
		Runtime.getRuntime().addShutdownHook(new Thread() {
		    public void run() {
		    	logger.info("Shutting down");
		    	undertow.stop();
		    	GlobalEntries.getGlobalEntries().getConfigManager().clearThreads();
		    }
		});
		
		if (config.isSocketShutdownListener()) {
			new Thread() {
				public void run() {
					logger.info("Starting shutdown socket listener");
					try {
						ServerSocket socket = new ServerSocket(fconfig.getSocketShutdownPort(),0,InetAddress.getByName(fconfig.getSocketShutdownHost()));
						while (true) {
							logger.info("shutdown waiting for input");
							Socket clientSocket = null;
							try {
								clientSocket = socket.accept();
							} catch (Throwable t) {
								logger.warn("Could not accept connection",t);
								continue;
							}
							logger.info("request received");
						    //PrintWriter out =
						    //    new PrintWriter(clientSocket.getOutputStream(), true);
						    BufferedReader in = new BufferedReader(
						        new InputStreamReader(clientSocket.getInputStream()));
						    logger.info("reading data");
						    String command = in.readLine();
							logger.info("'" + command + "'");
						    if (command != null) {
						    	command.trim();
							}
						    logger.info("'" + command + "'");
						    if (fconfig.getSocketShutdownCommand().equalsIgnoreCase(command)) {
						    	logger.info("Stopping threads");
								GlobalEntries.getGlobalEntries().getConfigManager().clearThreads();

						    	logger.info("Shutting down undertow");
								undertow.stop();

								logger.info("Closing input stream");

								try {
									in.close();
								} catch (Throwable t) {}

								/*try {
									out.close();
								} catch (Throwable t) {}*/

								logger.info("Closing client socket");
								try {
									clientSocket.close();
								} catch (Throwable t) {}

								logger.info("Closing server socket");
								try {
									socket.close();
								} catch (Throwable t) {}

								logger.info("Sleeping for 10 seconds");
								try {
									Thread.sleep(10000);
									logger.info("Exiting");
									System.exit(0);
									return;
								} catch (Exception e) {}

						    } else {
						    	command = null;
						    	logger.info("invalid command");
								try {
									in.close();
								} catch (Throwable t) {}

								/*try {
									out.close();
								} catch (Throwable t) {}
*/
								try {
									clientSocket.close();
								} catch (Throwable t) {}

						    }
						}
					} catch (IOException e) {
						logger.error("Could not start shutdown listener",e);
					}
				}
			}.start();
		}
		
		undertow.start();
		
		
		
		
		
	}

	private static void setupTlsListener(OpenUnisonConfig config, TremoloType unisonConfiguration,
			Builder buildUndertow) throws KeyStoreException, IOException, NoSuchAlgorithmException,
			CertificateException, FileNotFoundException, UnrecoverableKeyException, KeyManagementException {
		
		


		KeyStore keystore = KeyStore.getInstance("PKCS12");
		try {
			keystore.load(new FileInputStream(unisonConfiguration.getKeyStorePath()), unisonConfiguration.getKeyStorePassword().toCharArray());
		} catch (Throwable t) {
			keystore = KeyStore.getInstance("JCEKS");
			keystore.load(new FileInputStream(unisonConfiguration.getKeyStorePath()), unisonConfiguration.getKeyStorePassword().toCharArray());
		}
		KeyStore forUndertow = KeyStore.getInstance("PKCS12");
		forUndertow.load(null);
		Key key = keystore.getKey(config.getSecureKeyAlias(), unisonConfiguration.getKeyStorePassword().toCharArray());
		
		ArrayList<X509Certificate> chain = new ArrayList<X509Certificate>();
		chain.add((X509Certificate) keystore.getCertificate(config.getSecureKeyAlias()));
		
		addSigners(chain.get(0), chain, keystore);
		
		Certificate[] certChain = new Certificate[chain.size()];
		for (int i=0;i<certChain.length;i++) {
			certChain[i] = chain.get(i);
		}
		
		forUndertow.setKeyEntry(config.getSecureKeyAlias(), key, unisonConfiguration.getKeyStorePassword().toCharArray(), certChain);
		
		SSLContext sslcontext = SSLContext.getInstance("TLS");  
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(forUndertow, unisonConfiguration.getKeyStorePassword().toCharArray());
		
		
		
		KeyStore trustStore = KeyStore.getInstance("PKCS12");
		trustStore.load(null);
		
		HashSet<X500Principal> issuers = new HashSet<X500Principal>();
		for (String trustalias : config.getAllowedClientNames()) {
			
			issuers.add(new X500Principal(trustalias));
		}
		
		Enumeration<String> aliases = keystore.aliases();
		
		while (aliases.hasMoreElements()) {
			String aliasx = aliases.nextElement();
			
			X509Certificate cert = (X509Certificate) keystore.getCertificate(aliasx);
			if (cert != null) {
				
				if (issuers.contains(cert.getSubjectX500Principal())) {
					trustStore.setCertificateEntry(aliasx,cert);
		
				}
				
			}
		}
		
		
		
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(trustStore);
		
		
		
		
		
		
		sslcontext.init(kmf.getKeyManagers(),tmf.getTrustManagers(),new SecureRandom()); 
		
		String host = "0.0.0.0";
		
		buildUndertow.addHttpsListener(config.getSecurePort(), host, sslcontext);
		
		SSLContext context = SSLContext.getDefault();
		SSLSocketFactory sf = context.getSocketFactory();
		String[] cipherSuites = sf.getSupportedCipherSuites();
		
		HashSet<String> allowedCiphers = new HashSet<String>();
		
		if (config.getCiphers() == null || config.getCiphers().size() == 0) {
			allowedCiphers.add("TLS_RSA_WITH_RC4_128_SHA");
			allowedCiphers.add("TLS_RSA_WITH_AES_128_CBC_SHA");
			allowedCiphers.add("TLS_RSA_WITH_AES_256_CBC_SHA");
			allowedCiphers.add("TLS_RSA_WITH_3DES_EDE_CBC_SHA");
			allowedCiphers.add("TLS_RSA_WITH_AES_128_CBC_SHA256");
			allowedCiphers.add("TLS_RSA_WITH_AES_256_CBC_SHA256");
		} else {
			allowedCiphers.addAll(config.getCiphers());
		}
		
		String[] enabledCiphers = new String[allowedCiphers.size()];
		allowedCiphers.toArray(enabledCiphers);
		
		buildUndertow.setSocketOption(Options.SSL_ENABLED_CIPHER_SUITES, Options.SSL_ENABLED_CIPHER_SUITES.cast(Sequence.of(enabledCiphers)));
		
		if (config.getClientAuth().equalsIgnoreCase("want")) {
			buildUndertow.setSocketOption(Options.SSL_CLIENT_AUTH_MODE, org.xnio.SslClientAuthMode.REQUESTED);				
		} else if (config.getClientAuth().equalsIgnoreCase("required")) {
			buildUndertow.setSocketOption(Options.SSL_CLIENT_AUTH_MODE, org.xnio.SslClientAuthMode.REQUIRED);
		}
		
		HashSet<String> allowedTLSProtocols = new HashSet<String>();
		if (config.getAllowedTlsProtocols() == null || config.getAllowedTlsProtocols().size() == 0) {
			allowedTLSProtocols.add("TLSv1.2");
		} else {
			allowedTLSProtocols.addAll(config.getAllowedTlsProtocols());
		}
		
		String[] protocols = sslcontext.createSSLEngine().getEnabledProtocols();
		ArrayList<String> protToUse = new ArrayList<String>();
		for (String protocol : protocols) {
			if (allowedTLSProtocols.contains(protocol)) {
				protToUse.add(protocol);
				logger.info("Supporting TLS Protocol : '" + protocol + "'");
			} else {
				logger.info("NOT Supporting TLS Protocol : '" + protocol + "'");
			}
		}
		
		protocols = new String[protToUse.size()];
		protToUse.toArray(protocols);
		
		buildUndertow.setSocketOption(Options.SSL_ENABLED_PROTOCOLS, Options.SSL_ENABLED_PROTOCOLS.cast(Sequence.of(protocols)));
				
		logger.info("Configured TLS Listener on Port " + config.getSecurePort());
	}
	

	
	private static void addSigners(X509Certificate cert,
			ArrayList<X509Certificate> chain,KeyStore ks) throws KeyStoreException {
		Principal signer = cert.getIssuerX500Principal();
		Enumeration enumer = ks.aliases();
		while (enumer.hasMoreElements()) {
			String alias = (String) enumer.nextElement();
			X509Certificate curCert = (X509Certificate) ks.getCertificate(alias);
			if (curCert == null) {
				continue;
			}
			
			if (curCert.equals(cert)) {
				continue;
			} else if (curCert.getSubjectX500Principal().equals(signer)) {
				chain.add(curCert);
				if (! curCert.getIssuerX500Principal().equals(curCert.getSubjectX500Principal())) {
					addSigners(curCert, chain, ks);
				}
			}
		}
		
	}

}

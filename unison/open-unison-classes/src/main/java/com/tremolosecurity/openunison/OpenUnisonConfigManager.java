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


package com.tremolosecurity.openunison;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.util.Enumeration;
import java.util.Properties;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.net.ssl.KeyManagerFactory;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;

import com.tremolosecurity.openunison.util.config.OpenUnisonConfigLoader;
import net.sourceforge.myvd.server.ServerCore;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.UnisonConfigManagerImpl;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.myvd.MyVDConnection;


public class OpenUnisonConfigManager extends UnisonConfigManagerImpl {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(OpenUnisonConfigManager.class.getName());
	
	TremoloType unisonConfig;
	boolean forceToSSL;
	int openPort;
	int securePort;
	int externalOpenPort;
	int externalSecurePort;
	String configXML;
	
	public OpenUnisonConfigManager(String configXML, ServletContext ctx,
			String name,FilterConfig filterCfg) throws Exception {
		super(configXML, ctx, name);
		
		this.configXML = configXML;
		
		String configPath = null;
		if (System.getProperties().containsKey("com.tremolosecurity.unison.unisonServicePropsPath")) {
			configPath = System.getProperties().getProperty("com.tremolosecurity.unison.unisonServicePropsPath");
		} else {
			try {
				configPath = InitialContext.doLookup("java:comp/env/unisonServiceConfigPath");
			} catch (NamingException ne) {
				try {
					configPath = InitialContext.doLookup("java:/env/unisonServiceConfigPath");
				} catch (NamingException ne2) {
					logger.warn("No context bound, assuming WEB-INF/unisonService.props");
				}
			}
			
			 
			if (configPath == null) {
				configPath = "WEB-INF/unisonService.props";
			}
		}
		
		
		Properties service = new Properties();
		
		if (configPath.startsWith("WEB-INF")) {
			service.load( new ByteArrayInputStream(OpenUnisonConfigLoader.generateOpenUnisonConfig(filterCfg.getServletContext().getRealPath(("/" + configPath))).getBytes("UTF-8")));
		} else {
			service.load(new ByteArrayInputStream(OpenUnisonConfigLoader.generateOpenUnisonConfig(configPath).getBytes("UTF-8")));
		}
		
		this.forceToSSL = Boolean.parseBoolean(this.loadConfigParam(OpenUnisonConstants.UNISON_CONFIG_FORCE_TO_SSL, "false", service));
		this.openPort = Integer.parseInt(this.loadConfigParam(OpenUnisonConstants.UNISON_CONFIG_OPEN_PORT, "8080", service));
		this.securePort = Integer.parseInt(this.loadConfigParam(OpenUnisonConstants.UNISON_CONFIG_SECURE_PORT, "8443", service));
		this.externalOpenPort = Integer.parseInt(this.loadConfigParam(OpenUnisonConstants.UNISON_CONFIG_EXTERNAL_OPEN_PORT, "80", service));
		this.externalSecurePort = Integer.parseInt(this.loadConfigParam(OpenUnisonConstants.UNISON_CONFIG_EXTERNAL_SECURE_PORT, "443", service));
		
		System.setProperty(OpenUnisonConstants.UNISON_CONFIG_ACTIVEMQDIR,this.loadConfigParam(OpenUnisonConstants.UNISON_CONFIG_ACTIVEMQDIR, (filterCfg != null ? filterCfg.getServletContext().getRealPath("/WEB-INF/activemq") : "" ), service));
		System.setProperty(OpenUnisonConstants.UNISON_CONFIG_QUARTZDIR,this.loadConfigParam(OpenUnisonConstants.UNISON_CONFIG_QUARTZDIR, (filterCfg != null ? filterCfg.getServletContext().getRealPath("/WEB-INF/classes") : ""), service));
		
		
		
	}
	
	private String loadConfigParam(String name,String defaultValue,Properties props) {
		String tmp = props.getProperty(name);
		if (tmp == null) {
			tmp = defaultValue;
		}
		
		logger.info("Loading configuration - " + name + "='" + tmp + "'");
		
		return tmp;
		
	}

	@Override
	public JAXBElement<TremoloType> loadUnisonConfiguration(
			Unmarshaller unmarshaller) throws Exception {
		InputStream in;
		if (configXML.startsWith("WEB-INF")) {
			in = new ByteArrayInputStream(OpenUnisonConfigLoader.generateOpenUnisonConfig(ctx.getRealPath("/" + configXML)).getBytes("UTF-8"));
		} else {
			in = new ByteArrayInputStream(OpenUnisonConfigLoader.generateOpenUnisonConfig(configXML).getBytes("UTF-8"));
		}
		
		Object obj = unmarshaller.unmarshal(in);
		
		JAXBElement<TremoloType> cfg = (JAXBElement<TremoloType>) obj;
		this.unisonConfig = cfg.getValue();
		
		
		
		return cfg;
	}

	@Override
	public void loadKeystore(String path, String myVdPath) throws Exception {
		if (unisonConfig.getKeyStorePath() != null && unisonConfig.getKeyStorePath().length() > 0) {
			
			ks = KeyStore.getInstance("PKCS12");
			String ksPath = unisonConfig.getKeyStorePath();
			
			try {
				InputStream in;
				
				if (ksPath.startsWith("WEB-INF")) {
					in = ctx.getResourceAsStream("/" + ksPath);
				} else {
					in = new FileInputStream(ksPath);
				}
				
				ks.load(in, unisonConfig.getKeyStorePassword().toCharArray());
			} catch (Throwable t) {
				ks = KeyStore.getInstance("JCEKS");
				InputStream in;
				
				if (ksPath.startsWith("WEB-INF")) {
					in = ctx.getResourceAsStream("/" + ksPath);
				} else {
					in = new FileInputStream(ksPath);
				}
				
				ks.load(in, unisonConfig.getKeyStorePassword().toCharArray());

			} 
			KeyStore cacerts = KeyStore.getInstance(KeyStore.getDefaultType());
			String cacertsPath = System.getProperty("javax.net.ssl.trustStore");
			if (cacertsPath == null) {
				cacertsPath = System.getProperty("java.home") + "/lib/security/cacerts";
			}
			
			cacerts.load(new FileInputStream(cacertsPath), null);
			
			Enumeration<String> enumer = cacerts.aliases();
			while (enumer.hasMoreElements()) {
				String alias = enumer.nextElement();
				java.security.cert.Certificate cert = cacerts.getCertificate(alias);
				ks.setCertificateEntry(alias, cert);
			}
			
			this.kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(this.ks, unisonConfig.getKeyStorePassword().toCharArray());
			
			
			
		}

	}

	@Override
	public boolean isForceToSSL() {
		return this.forceToSSL;
	}

	@Override
	public int getOpenPort() {
		return this.openPort;
	}

	@Override
	public int getSecurePort() {
		return this.securePort;
	}

	@Override
	public int getExternalOpenPort() {
		return this.externalOpenPort;
	}

	@Override
	public int getExternalSecurePort() {
		return this.externalSecurePort;
	}

	@Override
	public void loadMyVD(String path, String myVdPath) throws Exception {
		String myvdConfigPath = unisonConfig.getMyvdConfig();
		if (myvdConfigPath != null) {
			Properties props = new Properties();
			
			InputStream in;
			if (myvdConfigPath.startsWith("WEB-INF")) {
				in = new ByteArrayInputStream(OpenUnisonConfigLoader.generateOpenUnisonConfig(ctx.getRealPath("/" + myvdConfigPath)).getBytes("UTF-8"));
			} else {
				in = new ByteArrayInputStream(OpenUnisonConfigLoader.generateOpenUnisonConfig(myvdConfigPath).getBytes("UTF-8"));
			}
			
			props.load(in);
			this.myvd = new ServerCore(props);
			this.myvd.startService();
			
			this.con = new MyVDConnection(this.myvd);
		}
		
		
		

	}
	


	@Override
	public void postInitialize() {
		logger.info("Clearing DLQ");
		
		try {
			this.getProvisioningEngine().clearDLQ();
		} catch (ProvisioningException e) {
			logger.warn("Could not clear DLQ",e);
		}
		
	}

}

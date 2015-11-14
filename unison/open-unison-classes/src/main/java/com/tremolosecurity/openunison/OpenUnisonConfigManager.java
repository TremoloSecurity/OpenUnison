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

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.Properties;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.net.ssl.KeyManagerFactory;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;

import net.sourceforge.myvd.server.ServerCore;

import org.apache.log4j.Logger;

import com.tremolosecurity.config.util.UnisonConfigManagerImpl;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.proxy.myvd.MyVDConnection;


public class OpenUnisonConfigManager extends UnisonConfigManagerImpl {

	static Logger logger = Logger.getLogger(OpenUnisonConfigManager.class.getName());
	
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
		
		try {
			configPath = InitialContext.doLookup("java:comp/env/unisonServiceConfigPath");
		} catch (NamingException ne) {
			configPath = InitialContext.doLookup("java:/env/unisonServiceConfigPath");
		}
		
		 
		if (configPath == null) {
			configPath = "WEB-INF/unisonService.props";
		}
		
		
		Properties service = new Properties();
		
		if (configPath.startsWith("WEB-INF")) {
			service.load(filterCfg.getServletContext().getResourceAsStream(configPath));
		} else {
			service.load(new FileInputStream(configPath));
		}
		
		this.forceToSSL = Boolean.parseBoolean(this.loadConfigParam(OpenUnisonConstants.UNISON_CONFIG_FORCE_TO_SSL, "false", service));
		this.openPort = Integer.parseInt(this.loadConfigParam(OpenUnisonConstants.UNISON_CONFIG_OPEN_PORT, "8080", service));
		this.securePort = Integer.parseInt(this.loadConfigParam(OpenUnisonConstants.UNISON_CONFIG_SECURE_PORT, "8443", service));
		this.externalOpenPort = Integer.parseInt(this.loadConfigParam(OpenUnisonConstants.UNISON_CONFIG_EXTERNAL_OPEN_PORT, "80", service));
		this.externalSecurePort = Integer.parseInt(this.loadConfigParam(OpenUnisonConstants.UNISON_CONFIG_EXTERNAL_SECURE_PORT, "443", service));
		
		System.setProperty(OpenUnisonConstants.UNISON_CONFIG_ACTIVEMQDIR,this.loadConfigParam(OpenUnisonConstants.UNISON_CONFIG_ACTIVEMQDIR, filterCfg.getServletContext().getRealPath("/WEB-INF/activemq"), service));
		System.setProperty(OpenUnisonConstants.UNISON_CONFIG_QUARTZDIR,this.loadConfigParam(OpenUnisonConstants.UNISON_CONFIG_QUARTZDIR, filterCfg.getServletContext().getRealPath("/WEB-INF/classes"), service));
		
		
		
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
			in = ctx.getResourceAsStream("/" + configXML);
		} else {
			in = new FileInputStream(configXML);
		}
		
		Object obj = unmarshaller.unmarshal(in);
		
		JAXBElement<TremoloType> cfg = (JAXBElement<TremoloType>) obj;
		this.unisonConfig = cfg.getValue();
		
		
		
		return cfg;
	}

	@Override
	public void loadKeystore(String path, String myVdPath) throws Exception {
		if (unisonConfig.getKeyStorePath() != null && unisonConfig.getKeyStorePath().length() > 0) {
			
			ks = KeyStore.getInstance("JCEKS");
			String ksPath = unisonConfig.getKeyStorePath();
			
			InputStream in;
			
			if (ksPath.startsWith("/WEB-INF")) {
				in = ctx.getResourceAsStream(ksPath);
			} else {
				in = new FileInputStream(ksPath);
			}
			
			ks.load(in, unisonConfig.getKeyStorePassword().toCharArray());
			
			
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
			if (myvdConfigPath.startsWith("/WEB-INF")) {
				in = ctx.getResourceAsStream(myvdConfigPath);
			} else {
				in = new FileInputStream(myvdConfigPath);
			}
			
			props.load(in);
			this.myvd = new ServerCore(props);
			this.myvd.startService();
			
			this.con = new MyVDConnection(this.myvd);
		}
		
		
		

	}

}

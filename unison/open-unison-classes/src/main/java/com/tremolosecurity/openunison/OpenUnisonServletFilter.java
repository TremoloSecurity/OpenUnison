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


package com.tremolosecurity.openunison;

import java.io.FileInputStream;
import java.util.Properties;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;

import org.apache.logging.log4j.Logger;


import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.filter.UnisonServletFilter;
import com.tremolosecurity.proxy.SessionManager;
import com.tremolosecurity.proxy.SessionManagerImpl;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.server.GlobalEntries;


public class OpenUnisonServletFilter extends UnisonServletFilter {

	OpenUnisonConfigManager cfgMgr;

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(OpenUnisonServletFilter.class.getName());

	private SessionManager sessionManager;




	public static final String version = "1.0.21-2021031201";




	@Override
	public ConfigManager loadConfiguration(FilterConfig filterCfg,
			String registryName) throws Exception {


		String envFile = System.getProperty("unisonEnvironmentFile");
		if (envFile != null) {
			logger.info("Loading environment file : '" + envFile + "'");

			Properties env = new Properties();
			env.load(new FileInputStream(envFile));

			for (Object name : env.keySet()) {
				logger.info("Adding property : '" + name + "'");
				System.setProperty((String) name,env.getProperty((String) name));
			}
		}


		String configPath = null;

		if (System.getProperties().contains("com.tremolosecurity.unison.unisonXML")) {
			configPath = System.getProperties().getProperty("com.tremolosecurity.unison.unisonXML");
		} else {
			try {
				configPath = InitialContext.doLookup("java:comp/env/unisonConfigPath");
			} catch (NamingException ne) {
				try {
					configPath = InitialContext.doLookup("java:/env/unisonConfigPath");
				} catch (NamingException ne2) {
					logger.warn("No context paths present, assuming the config path is WEB-INF/unison.xml");
				}
			}


			if (configPath == null) {
				configPath = "WEB-INF/unison.xml";
			}
		}

		logger.info("Initializing OpenUnison " + version);

		logger.info("Unison Configuration File : '" + configPath  + "'");

		this.cfgMgr =  new OpenUnisonConfigManager(configPath,filterCfg.getServletContext(),registryName,filterCfg);

		GlobalEntries.getGlobalEntries().set(ProxyConstants.CONFIG_MANAGER,cfgMgr);

		return this.cfgMgr;
	}

	@Override
	public void postLoadConfiguration(FilterConfig filterCfg,
			String registryName, ConfigManager cfgMgr) {

		sessionManager = new SessionManagerImpl(cfgMgr,filterCfg.getServletContext());
		GlobalEntries.getGlobalEntries().set(ProxyConstants.TREMOLO_SESSION_MANAGER, sessionManager);
		filterCfg.getServletContext().setAttribute(ProxyConstants.TREMOLO_SESSION_MANAGER, sessionManager);

	}

	@Override
	public void init(FilterConfig filterCfg) throws ServletException {
		super.init(filterCfg);
	}

	@Override
	public void destroy() {
		logger.info("Shutting down");
		this.cfgMgr.clearThreads();
		this.sessionManager.stopSessionChecker();
		logger.info("Shut down complete");
	}



}

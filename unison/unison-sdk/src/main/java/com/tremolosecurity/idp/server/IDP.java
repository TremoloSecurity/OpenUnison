/*
Copyright 2015, 2016 Tremolo Security, Inc.

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


package com.tremolosecurity.idp.server;

import java.io.IOException;
import java.util.HashMap;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.ReloadNotification;
import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.config.xml.IdpType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.TrustType;
import com.tremolosecurity.config.xml.UrlType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;


public class IDP extends HttpServlet  implements ReloadNotification {
	public static final String ACTION_NAME = "TREMOLO_IDP_ACTION";
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(IDP.class.getName());
	HashMap<String,IdpHolder> idps;
	private ConfigManager cfgMgr;
	private ServletConfig config;
	
	static IDP idp;
	
	public static IDP getIdp() {
		return idp;
	}
	
	@Override
	protected void doDelete(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		
		IdpHolder idp = this.loadIdP(req, resp);
		if (idp == null) {
			resp.sendError(404);
			return;
		} else {
			idp.idp.doDelete(req, resp);
		}
		
	}

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		IdpHolder idp = this.loadIdP(req, resp);
		if (idp == null) {
			resp.sendError(404);
			return;
		} else {
			idp.idp.doGet(req, resp);
		}
	}

	@Override
	protected void doHead(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		IdpHolder idp = this.loadIdP(req, resp);
		if (idp == null) {
			resp.sendError(404);
			return;
		} else {
			idp.idp.doHead(req, resp);
		}
	}

	@Override
	protected void doOptions(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		IdpHolder idp = this.loadIdP(req, resp);
		if (idp == null) {
			resp.sendError(404);
			return;
		} else {
			idp.idp.doOptions(req, resp);
		}
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		IdpHolder idp = this.loadIdP(req, resp);
		if (idp == null) {
			resp.sendError(404);
			return;
		} else {
			idp.idp.doPost(req, resp);
		}
	}

	@Override
	protected void doPut(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		IdpHolder idp = this.loadIdP(req, resp);
		if (idp == null) {
			resp.sendError(404);
			return;
		} else {
			idp.idp.doPut(req, resp);
		}
	}

	
	
	private IdpHolder loadIdP(HttpServletRequest request,HttpServletResponse response) {
		String uri = request.getRequestURI();
		//System.out.println("URI : '" + uri + "'");
		ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		
		String idpURI = uri.substring(cfg.getAuthIdPPath().length());
		
		
		String idpName = "";
		
		if (idpURI.contains("/")) {
			idpName = idpURI.substring(0,idpURI.indexOf('/'));
			idpURI = idpURI.substring(idpURI.indexOf('/') + 1);
			
			request.setAttribute(IDP.ACTION_NAME, idpURI);
			
		} else {
			idpName = idpURI;
		}
		
		
		//System.out.println("idpName : '" + idpName + "'");

		
		return this.idps.get(idpName.toLowerCase());
	}

	@Override
	public void init(ServletConfig config) throws ServletException {
		super.init(config);
		
		this.cfgMgr = GlobalEntries.getGlobalEntries().getConfigManager();
		this.config = config;
		cfgMgr.addReloadNotifier(this);
		initIdPs(config, cfgMgr);
		
		idp = this;
	}

	private void initIdPs(ServletConfig config, ConfigManager cfgMgr)
			throws ServletException {
		idps = new HashMap<String,IdpHolder>();
		
		
		for (ApplicationType app : cfgMgr.getCfg().getApplications().getApplication()) {
			
			for (UrlType url : app.getUrls().getUrl()) {
				if (url.getIdp() != null) {
					this.configIdp(app, url, url.getIdp(), config);
				}
			}
			
			
		}
	}
	
	
	public void configIdp(ApplicationType app,UrlType url,IdpType idp,ServletConfig config) throws ServletException {
		String idpName = app.getName();
		String className = idp.getClassName();
		
		IdentityProvider identityProvider = null;
		try {
			identityProvider = (IdentityProvider) Class.forName(className).newInstance();
		} catch (Exception e) {
			StringBuffer b = new StringBuffer();
			b.append("Could not instanciate identity provider '").append(idpName).append("'");
			logger.error(b.toString(),e);
			
			throw new ServletException(b.toString(),e);
		} 
		
		HashMap<String,Attribute> initParams = new HashMap<String,Attribute>();
		
		for (ParamType param : idp.getParams()) {
			Attribute attr = initParams.get(param.getName());
			if (attr == null) {
				attr = new Attribute(param.getName());
				initParams.put(attr.getName(), attr);
			}
			attr.getValues().add(param.getValue());
		}
		
		HashMap<String,HashMap<String,Attribute>> trusts  = new HashMap<String,HashMap<String,Attribute>>();
		
		for (TrustType trust : idp.getTrusts().getTrust()) {
			HashMap<String,Attribute> trustCfg = new HashMap<String,Attribute>();
		
			for (ParamType param : trust.getParam()) {
				Attribute attr = trustCfg.get(param.getName());
				if (attr == null) {
					attr = new Attribute(param.getName());
					trustCfg.put(attr.getName(), attr);
				}
				attr.getValues().add(param.getValue());
			}
			
			
			//System.out.println(trust.getName());
			trusts.put(trust.getName(),trustCfg);
		}
		
		try {
			identityProvider.init(app.getName(),config.getServletContext(), initParams,trusts,new MapIdentity(idp.getMappings()));
		} catch (ProvisioningException e) {
			throw new ServletException("Could not initiate IDP",e);
		}
		IdpHolder holder = new IdpHolder();
		holder.idp = identityProvider;
		holder.idpConfig = idp;
		this.idps.put(idpName.toLowerCase(), holder);
	}
	
	public void removeIdP(String name) {
		this.idps.remove(name.toLowerCase());
	}

	@Override
	public void reload() {
		try {
			initIdPs(config, cfgMgr);
		} catch (ServletException e) {
			logger.error("Error initializing IdPs",e);
		}
		
	}
	
	public ServletConfig getServletConfig() {
		return this.config;
	}

}

class IdpHolder {
	IdentityProvider idp;
	IdpType idpConfig;
}

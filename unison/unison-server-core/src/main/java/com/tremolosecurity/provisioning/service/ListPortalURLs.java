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


package com.tremolosecurity.provisioning.service;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

import java.io.IOException;
import java.util.ArrayList;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.Logger;

import com.google.gson.Gson;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.AzRuleType;
import com.tremolosecurity.config.xml.OrgType;
import com.tremolosecurity.config.xml.PortalUrlType;
import com.tremolosecurity.config.xml.PortalUrlsType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.service.util.Organization;
import com.tremolosecurity.provisioning.service.util.PortalURL;
import com.tremolosecurity.provisioning.service.util.PortalURLs;
import com.tremolosecurity.provisioning.service.util.ProvisioningError;
import com.tremolosecurity.provisioning.service.util.ProvisioningResult;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AzSys;
import com.tremolosecurity.proxy.az.AzRule;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;


public class ListPortalURLs extends HttpServlet {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(ListPortalURLs.class.getName());
	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		String userID = req.getParameter("uid");
		String uidAttr = req.getParameter("uidAttr");
		
		ConfigManager cfgMgr = GlobalEntries.getGlobalEntries().getConfigManager();
		
		try {
			StringBuffer b = new StringBuffer();
			
			
			LDAPSearchResults res = cfgMgr.getMyVD().search(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot(), 2, equal(uidAttr,userID).toString(), new ArrayList<String>());
			if (! res.hasMore()) {
				throw new ProvisioningException("Could not locate user '" + userID + "'");
			}
			LDAPEntry entry = res.next();
			while (res.hasMore()) res.next();
			
			AuthInfo auinfo = new AuthInfo();
			auinfo.setUserDN(entry.getDN());
			LDAPAttributeSet attrs = entry.getAttributeSet();
			for (Object obj : attrs) {
				LDAPAttribute attr = (LDAPAttribute) obj;
				
			
				
				Attribute attrib = new Attribute(attr.getName());
				String[] vals = attr.getStringValueArray();
				for (String val : vals) {
					attrib.getValues().add(val);
				}
				
				auinfo.getAttribs().put(attrib.getName(), attrib);
			}
		
			
			AzSys az = new AzSys();
			
			PortalUrlsType pt = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getPortal();
			
			PortalURLs urls = new PortalURLs();
			
			for (PortalUrlType url : pt.getUrls()) {
				if (url.getAzRules() != null && url.getAzRules().getRule().size() > 0) {
					ArrayList<AzRule> rules = new ArrayList<AzRule>();
					
					for (AzRuleType art : url.getAzRules().getRule()) {
						rules.add(new AzRule(art.getScope(),art.getConstraint(),art.getClassName(),cfgMgr,null));
					}
					
					
					if (! az.checkRules(auinfo, GlobalEntries.getGlobalEntries().getConfigManager(), rules,null)) {
						continue;
					}
				}
				
				PortalURL purl = new PortalURL();
				purl.setName(url.getName());
				purl.setLabel(url.getLabel());
				purl.setOrg(url.getOrg());
				purl.setUrl(url.getUrl());
				purl.setIcon(url.getIcon());
				
				urls.getUrls().add(purl);
			}
			
			
			Gson gson = new Gson();
			
			ProvisioningResult pres = new ProvisioningResult();
			pres.setSuccess(true);
			pres.setPortalURLs(urls);
			
			resp.getOutputStream().print(gson.toJson(pres));
		} catch (Exception e) {
			ProvisioningError pe = new ProvisioningError();
			pe.setError("Could not load urls : " + e.getMessage());
			ProvisioningResult res = new ProvisioningResult();
			res.setSuccess(false);
			res.setError(pe);
			Gson gson = new Gson();
			
			resp.getWriter().write(gson.toJson(res));
			logger.error("Could not load urls",e);
		}
	}

}

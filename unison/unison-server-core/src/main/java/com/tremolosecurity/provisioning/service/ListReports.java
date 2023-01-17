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
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
import com.tremolosecurity.config.xml.ReportType;
import com.tremolosecurity.config.xml.ReportsType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.service.util.Organization;
import com.tremolosecurity.provisioning.service.util.PortalURL;
import com.tremolosecurity.provisioning.service.util.PortalURLs;
import com.tremolosecurity.provisioning.service.util.ProvisioningError;
import com.tremolosecurity.provisioning.service.util.ProvisioningResult;
import com.tremolosecurity.provisioning.service.util.ReportInformation;
import com.tremolosecurity.provisioning.service.util.ReportResults;
import com.tremolosecurity.provisioning.service.util.ReportsList;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AzSys;
import com.tremolosecurity.proxy.az.AzRule;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;


public class ListReports extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = -6421832979913478507L;
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(ListReports.class.getName());
	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		String userID = req.getParameter("uid");
		String uidAttr = req.getParameter("uidAttr");
		
		try {
			StringBuffer b = new StringBuffer();
			
			
			LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot(), 2, equal(uidAttr,userID).toString(), new ArrayList<String>());
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
			
			
			HashSet<String> allowedOrgs = new HashSet<String>();
			OrgType root = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getOrg();
			
			
			
			this.checkOrg(allowedOrgs, root, az, auinfo);
			
			
			
			ReportsType reports = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getReports();
			
			ReportsList reportsList = new ReportsList();
			reportsList.setReports(new ArrayList<ReportInformation>());
			
			
			for (ReportType report : reports.getReport()) {
				if (allowedOrgs.contains(report.getOrgID())) {
					ReportInformation ri = new ReportInformation();
					ri.setName(report.getName());
					ri.setDescription(report.getDescription());
					ri.setOrgID(report.getOrgID());
					ri.setParameters(new ArrayList<String>());
					ri.getParameters().addAll(report.getParamater());
					
					reportsList.getReports().add(ri);
				}
			}
			
			
			Gson gson = new Gson();
			
			ProvisioningResult pres = new ProvisioningResult();
			pres.setSuccess(true);
			pres.setReportsList(reportsList);
			
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
	
	private void checkOrg(HashSet<String> allowedOrgs,OrgType ot, AzSys az, AuthInfo auinfo) throws MalformedURLException, ProvisioningException {
		ConfigManager cfgMgr = GlobalEntries.getGlobalEntries().getConfigManager();
		
		if (ot.getAzRules() != null && ot.getAzRules().getRule().size() > 0) {
			ArrayList<AzRule> rules = new ArrayList<AzRule>();
			
			for (AzRuleType art : ot.getAzRules().getRule()) {
				rules.add(new AzRule(art.getScope(),art.getConstraint(),art.getClassName(),cfgMgr,null));
			}
			
			
			if (! az.checkRules(auinfo, cfgMgr, rules,null)) {
				return;
			}
		}
		
		allowedOrgs.add(ot.getUuid());
		
		for (OrgType child : ot.getOrgs()) {
			checkOrg(allowedOrgs,child, az, auinfo);
		}
	}

}

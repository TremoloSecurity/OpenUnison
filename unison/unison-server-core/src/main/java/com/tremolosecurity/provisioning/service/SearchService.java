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


package com.tremolosecurity.provisioning.service;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.service.util.ProvisioningError;
import com.tremolosecurity.provisioning.service.util.ProvisioningResult;
import com.tremolosecurity.provisioning.service.util.TremoloUser;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;


public class SearchService extends HttpServlet {
	static Logger logger = Logger.getLogger(SearchService.class.getName());
	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		resp.setContentType("text/json");
		try {
			
			
			String filter = "";
			String base = "";
			int scope = 0;
			
			if (req.getParameter("uid") != null) {
				StringBuffer sfilter = new StringBuffer();
				sfilter.append("(uid=").append(req.getParameter("uid")).append(')');
				if (logger.isDebugEnabled()) {
					logger.debug("UID Filter : '" + sfilter.toString() + "'");
				}
				filter = sfilter.toString();
				base = "o=Tremolo";
				scope = 2;
			} else if (req.getParameter("dn") != null) {
				filter = "(objectClass=*)";
				base = req.getParameter("dn");
				if (logger.isDebugEnabled()) {
					logger.debug("Base DN : '" + base + "'");
				}
				scope = 0;
			} else if (req.getParameter("filter") != null) {
				filter = req.getParameter("filter");
				if (logger.isDebugEnabled()) {
					logger.debug("Filter : '" + filter + "'");
				}
				base = "o=Tremolo";
				scope = 2;
			}
			
			ArrayList<String> attrs = new ArrayList<String>();
			String[] attrNames = req.getParameterValues("attr");
			boolean uidFound = false;
			
			if (attrNames != null) {
				
				for (String attrName : attrNames) {
					if (attrName.equalsIgnoreCase("uid")) {
						uidFound = true;
					}
					
					attrs.add(attrName);
				}
				
				if (! uidFound) {
					attrs.add("uid");
				}
			}
			
			MyVDConnection con = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD();
			LDAPSearchResults res = con.search(base, scope, filter, attrs);
			
			if (! res.hasMore()) {
				ProvisioningException ex = new ProvisioningException("User not found");
				ex.setPrintStackTrace(false);
				throw ex;
			}
			
			LDAPEntry entry = res.next();
			TremoloUser user = new TremoloUser();
			
			user.setDn(entry.getDN());
			int lq = entry.getDN().lastIndexOf(',');
			int fq = entry.getDN().lastIndexOf('=', lq - 1) + 1;
			user.setDirectory(entry.getDN().substring(fq,lq));
			
			for (Object attr : entry.getAttributeSet()) {
				LDAPAttribute attribute = (LDAPAttribute) attr;
				Attribute usrAttr = new Attribute(attribute.getName());
				
				if (attribute.getName().equalsIgnoreCase("uid")) {
					user.setUid(attribute.getStringValue());
					
					if (! uidFound && attrs.size() > 1) {
						continue;
					}
				}
				
				for (String val : attribute.getStringValueArray()) {
					usrAttr.getValues().add(val);
				}
				
				user.getAttributes().add(usrAttr);
			}
			
			while (res.hasMore()) res.next();
			
			ArrayList<String> reqAttrs = new ArrayList<String>();
			reqAttrs.add("cn");
			
			StringBuffer b = new StringBuffer();
			b.append("(uniqueMember=").append(user.getDn()).append(")");
			res = con.search("o=Tremolo", 2,equal("uniqueMember",user.getDn()).toString() , reqAttrs);
			
			while (res.hasMore()) {
				
				entry = res.next();
				LDAPAttribute groups = entry.getAttribute("cn");
				for (String val : groups.getStringValueArray()) {
					user.getGroups().add(val);
				}
			}
			
			ProvisioningResult resObj = new ProvisioningResult();
			resObj.setSuccess(true);
			resObj.setUser(user);
			
			Gson gson = new GsonBuilder().setPrettyPrinting().create();
			//System.out.println(gson.toJson(user));
			resp.getOutputStream().print(gson.toJson(resObj));
			
		} catch (ProvisioningException pe) {
			if (pe.isPrintStackTrace()) {
				logger.error("Error searching for a user",pe);
			} else {
				logger.warn(pe.toString());
			}
			
			resp.setStatus(500);
			ProvisioningError pre = new ProvisioningError();
			pre.setError(pe.toString());
			ProvisioningResult resObj = new ProvisioningResult();
			resObj.setSuccess(false);
			resObj.setError(pre);
			Gson gson = new Gson();
			resp.getOutputStream().print(gson.toJson(resObj));
		} catch (Throwable t) {
			logger.error("Error searching",t);
			resp.setStatus(500);
			ProvisioningError pe = new ProvisioningError();
			pe.setError(t.toString());
			
			ProvisioningResult resObj = new ProvisioningResult();
			resObj.setSuccess(false);
			resObj.setError(pe);
			
			Gson gson = new Gson();
			resp.getOutputStream().print(gson.toJson(resObj));
		}
		
	}

}

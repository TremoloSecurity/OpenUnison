/*******************************************************************************
 * Copyright 2016, 2018 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.dynamicwf;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.Logger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.WorkflowType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.util.DynamicWorkflow;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.saml.Attribute;

public class LDAPDynaicWorkflows implements DynamicWorkflow {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(LDAPDynaicWorkflows.class.getName());
	static HashSet<String> ignore = new HashSet<String>();

	static {
		ignore.add("uniquemember");
		ignore.add("member");
		ignore.add("memberof");
	}

	@Override
	public List<Map<String, String>> generateWorkflows(WorkflowType wf, ConfigManager cfg,
			HashMap<String, Attribute> params) throws ProvisioningException {
		
		try {
			String base = params.get("searchBase").getValues().get(0);
			String filter = params.get("searchFilter").getValues().get(0);
			
			List<Map<String,String>> wfParams = new ArrayList<Map<String,String>>();
			
			LDAPSearchResults res = cfg.getMyVD().search(base, 2, filter, new ArrayList<String>());
			
			while (res.hasMore()) {
				HashMap<String,String> wfDef = new HashMap<String,String>();
				LDAPEntry group = res.next();
				
				String groupName = this.getAttributeEntry("groupNameAttribute", group,params);
				if (groupName == null) {
					throw new ProvisioningException("No groupName");
				}
				wfDef.put("groupName", groupName);
				
				if (params.get("approverAttribute") != null) {
					String approver = this.getAttributeEntry("approverAttribute", group,params);
					wfDef.put("approver", approver);
				} else {
					wfDef.put("approver", "");
				}
				
				if (params.get("descriptionAttribute") != null) {
					String description = this.getAttributeEntry("descriptionAttribute", group,params);
					wfDef.put("descriptionAttribute", description);
				} else {
					wfDef.put("descriptionAttribute", "");
				}


				for (Object o : group.getAttributeSet()) {
					LDAPAttribute attr = (LDAPAttribute) o;
					String lcasename = attr.getName().toLowerCase();
					if (! LDAPDynaicWorkflows.ignore.contains(lcasename)) {
						String attrName = attr.getName().replaceAll("[-]", "_");
						wfDef.put(attrName, attr.getStringValue());
					}	
				}

				
				wfParams.add(wfDef);
				
				
				
			}
			
			return wfParams;
		} catch (Exception e) {
			throw new ProvisioningException("Could not load ldap workflows",e);
		}
	}
	
	
	private String getAttributeEntry(String name,LDAPEntry entry,HashMap<String,Attribute> params) throws ProvisioningException {
		
		Attribute attrName = params.get(name);
		if (attrName == null) {
			return null;
		}
		
		
		
		LDAPAttribute attr = entry.getAttribute(attrName.getValues().get(0));
		if (attr != null) {
			return attr.getStringValue();
		} else {
			return null;
		}
	}


	@Override
	public List<Map<String, String>> generateWorkflows(WorkflowType wf, ConfigManager cfg,
			HashMap<String, Attribute> params, AuthInfo authInfo) throws ProvisioningException {
		return this.generateWorkflows(wf, cfg, params);
	}

}

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


package com.tremolosecurity.provisioning.customTasks;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

import java.util.ArrayList;
import java.util.Map;
import java.util.HashSet;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class LoadAttributes implements CustomTask {

	ArrayList<String> attrs;
	String nameAttr;
	transient ConfigManager cfg;
	
	String base;

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params)
			throws ProvisioningException {
		
		this.attrs = new ArrayList<String>();
		Attribute cfgAttrs = params.get("name");
		
		for (String name : cfgAttrs.getValues()) {
			attrs.add(name);
		}
		
		this.nameAttr = params.get("nameAttr").getValues().get(0);
		
		this.cfg = task.getConfigManager();

		if (params.get("base") != null) {
			this.base = params.get("base").getValues().get(0);
		}

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.cfg = task.getConfigManager();

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request)
			throws ProvisioningException {
		
		StringBuffer filter = new StringBuffer();
		
		
		
		
		ArrayList<String> params = new ArrayList<String>();
		params.addAll(this.attrs);
		
		try {
			if (this.base == null) {
				this.base = this.cfg.getCfg().getLdapRoot();
			}
			LDAPSearchResults res = this.cfg.getMyVD().search(this.base, 2, equal(this.nameAttr,user.getUserID()).toString(), params);
			if (res.hasMore()) {
				LDAPEntry entry = res.next();
				while (res.hasMore()) res.next();
				LDAPAttributeSet attrs = entry.getAttributeSet();
				for (Object obj : attrs) {
					LDAPAttribute attr = (LDAPAttribute) obj;
					Attribute userAttr = new Attribute(attr.getName());
					
					for (String val : attr.getStringValueArray()) {
						userAttr.getValues().add(val);
					}
					
					user.getAttribs().put(attr.getName(), userAttr);
				}
			}
		} catch (LDAPException e) {
			throw new ProvisioningException("Could not load user : " + user.getUserID(),e);
		}
		
		
		return true;
	}

}

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

import org.apache.logging.log4j.Logger;

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

public class LoadGroups implements CustomTask {

	static transient Logger logger = org.apache.logging.log4j.LogManager.getLogger(LoadGroups.class.getName());

	String nameAttr;
	boolean inverse;
	transient ConfigManager cfg;
	String base;

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {

		this.nameAttr = params.get("nameAttr").getValues().get(0);
		this.inverse = params.get("inverse") != null
				&& params.get("inverse").getValues().get(0).equalsIgnoreCase("true");

		logger.info("Name Attribute : '" + this.nameAttr + "'");
		logger.info("Inverse : '" + this.inverse + "'");

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
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {

		String filter = equal(this.nameAttr, user.getUserID()).toString();

		ArrayList<String> params = new ArrayList<String>();
		params.add("1.1");

		try {

			HashSet<String> currentGroups = new HashSet<String>();
			currentGroups.addAll(user.getGroups());
			if (logger.isDebugEnabled()) {
				logger.debug("Current Groups : '" + currentGroups + "'");
			}

			if (inverse) {
				user.getGroups().clear();
			}

			if (this.base == null) {
				this.base = this.cfg.getCfg().getLdapRoot();
			}

			LDAPSearchResults res = this.cfg.getMyVD().search(
					this.base, 2, filter.toString(),
					params);

			if (res.hasMore()) {
				LDAPEntry entry = res.next();
				while (res.hasMore()) res.next();
				
				String dn = entry.getDN();
				while (res.hasMore())
					res.next();

				filter = equal(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getGroupMemberAttribute(),
						dn).toString();

				params.clear();
				params.add("cn");

				res = this.cfg.getMyVD().search(
						this.base, 2,
						filter.toString(), params);

				while (res.hasMore()) {
					entry = res.next();
					String name = entry.getAttribute("cn").getStringValue();
					if (logger.isDebugEnabled()) {
						logger.debug("Group - " + name);
					}

					if (inverse) {
						if (!currentGroups.contains(name)) {
							if (logger.isDebugEnabled()) {
								logger.debug("Adding " + name);
							}
							user.getGroups().add(name);
						}
					} else {
						if (logger.isDebugEnabled()) {
							logger.debug("Adding " + name);
						}
						user.getGroups().add(name);
					}

				}

				if (logger.isDebugEnabled()) {
					logger.debug("New Groups : '" + user.getGroups() + "'");
				}

			}

		} catch (LDAPException e) {
			throw new ProvisioningException("Could not load user : " + user.getUserID(), e);
		}

		return true;
	}

}

/*******************************************************************************
 * Copyright 2015, 2018 Tremolo Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.provisioning.az;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;

import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.util.DN;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.az.AzException;
import com.tremolosecurity.proxy.az.CustomAuthorization;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class ManagerAuthorization implements CustomAuthorization {

	private static final String DISTINGUISHED_NAME = "distinguishedName";

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(ManagerAuthorization.class.getName());

	
	
	Workflow wf;
	
	int numLevels;
	
	boolean allowLowerManagers;
	
	String managerID;
	
	boolean managerIDDN;

	private transient ConfigManager configManager;
	
	
	
	@Override
	public void init(Map<String, Attribute> config) throws AzException {
		
		this.numLevels = Integer.parseInt(this.getConfigOption("numLevels", config));
		this.managerID = this.getConfigOption("managerID", config);
		this.managerIDDN = this.getConfigOption("managerIDIsDN", config).equalsIgnoreCase("true");
		this.allowLowerManagers = this.getConfigOption("allowLowerManagers", config).equalsIgnoreCase("true");
		
	}
	
	private String getConfigOption(String name,Map<String,Attribute> config) {
		Attribute attr = config.get(name);
		if (attr == null) {
			logger.warn(name + " not present");
			return null;
		} else {
			logger.info(name + "='" + attr.getValues().get(0) + "'");
			return attr.getValues().get(0);
		}
	}

	@Override
	public void loadConfigManager(ConfigManager cfg) throws AzException {
		this.configManager = cfg;
		
	}

	@Override
	public void setWorkflow(Workflow wf) throws AzException {
		this.wf = wf; 
		
	}

	@Override
	public boolean isAuthorized(AuthInfo subject,String...params) throws AzException {
		DN subjectDN = new DN(subject.getUserDN());
		
		List<User> managers;
		
		try {
			managers = this.findManager(this.numLevels, this.allowLowerManagers);
		} catch (Exception e) {
			throw new AzException("Could not load managers",e);
		}
		
		for (User manager : managers) {
			DN managerDN = new DN(manager.getAttribs().get(DISTINGUISHED_NAME).getValues().get(0));
			if (managerDN.equals(subjectDN)) {
				return true;
			}
		}
		
		//nothing found
		return false;
	}

	@Override
	public List<String> listPossibleApprovers(String...params) throws AzException {
		List<String> managers = new ArrayList<String>();
		
		List<User> managerUser = null;
		try {
			managerUser = this.findManager(this.numLevels, this.allowLowerManagers);
		} catch (Exception e) {
			throw new AzException("Could not load managers",e);
		}
		for (User user : managerUser) {
			managers.add(user.getAttribs().get(DISTINGUISHED_NAME).getValues().get(0));
		}
		
		return managers;
	}
	
	private List<User> findManager(int step,boolean keepAllManagers) throws Exception {
		User me = this.wf.getUser();
		
		List<User> managers = new ArrayList<User>();
		User manager = null;
		
		for (int i=0;i<step;i++) {
			manager = findMyManager(me);
			
			if (manager == null) {
				break;
			}
			
			if (keepAllManagers) {
				managers.add(manager);
			}
			me = manager;
		}
		
		if (! keepAllManagers && manager != null) {
			managers.add(manager);
		}
		
		return managers;
	}

	private User findMyManager(User me) throws Exception {
		Attribute mgrAttr = me.getAttribs().get(this.managerID);
		if (mgrAttr == null) {
			return null;
		} else {
			if (this.managerIDDN) {
				ArrayList<String> attrs = new ArrayList<String>();
				attrs.addAll(me.getAttribs().keySet());
				if (! attrs.isEmpty() && ! attrs.contains("*")) {
					attrs.add(this.configManager.getCfg().getProvisioning().getApprovalDB().getUserIdAttribute());
				}
				LDAPSearchResults res = this.configManager.getMyVD().search(mgrAttr.getValues().get(0), 0, "(objectClass=*)", attrs);
				if (! res.hasMore()) {
					return null;
				} else {
					LDAPEntry entry = res.next();
					User manager = new  User(entry);
					manager.setUserID(manager.getAttribs().get(this.configManager.getCfg().getProvisioning().getApprovalDB().getUserIdAttribute()).getValues().get(0));
					manager.getAttribs().put(DISTINGUISHED_NAME, new Attribute(DISTINGUISHED_NAME,entry.getDN()));
					return manager;
				}
			} else {
				
				String filter = equal(this.configManager.getCfg().getProvisioning().getApprovalDB().getUserIdAttribute(),mgrAttr.getValues().get(0)).toString();
				
				
				ArrayList<String> attrs = new ArrayList<String>();
				attrs.addAll(me.getAttribs().keySet());
				if (! attrs.isEmpty() && ! attrs.contains("*")) {
					attrs.add(this.configManager.getCfg().getProvisioning().getApprovalDB().getUserIdAttribute());
				}
				LDAPSearchResults res = this.configManager.getMyVD().search(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot(), 2, filter, attrs);
				if (! res.hasMore()) {
					return null;
				} else {
					LDAPEntry entry = res.next();
					User manager = new  User(entry);
					manager.setUserID(manager.getAttribs().get(this.configManager.getCfg().getProvisioning().getApprovalDB().getUserIdAttribute()).getValues().get(0));
					manager.getAttribs().put(DISTINGUISHED_NAME, new Attribute(DISTINGUISHED_NAME,entry.getDN()));
					return manager;
				}
			}
		}
	}

	
	
	

}

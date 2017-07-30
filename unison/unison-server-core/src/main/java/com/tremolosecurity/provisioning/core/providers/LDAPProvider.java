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


package com.tremolosecurity.provisioning.core.providers;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.logging.log4j.Logger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.connectionpool.PoolManager;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.UserStoreProviderWithAddGroup;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.util.ldap.pool.LdapConnection;
import com.tremolosecurity.provisioning.util.ldap.pool.LdapPool;
import com.tremolosecurity.proxy.ssl.TremoloSSLSocketFactory;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.*;

public class LDAPProvider implements UserStoreProviderWithAddGroup,LDAPInterface {

	
	public static final String NEW_USER_DN = "com.tremolosecurity.unison.provisioning.ldap.newUserDN";
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(LDAPProvider.class);
	LdapPool ldapPool;
	
	String dnPattern;
	String searchBase;
	String objectClass;
	private boolean isSSL;
	private String userDN;
	private String passwd;
	private String userIDAttribute;
	private ConfigManager cfgMgr;
	String name;
	private long idleTimeout;
	
	private boolean allowExternalUsers;
	private String lcUnisonBase;
	private String unisonBase;
	private String lcLDAPBase;
	private String ldapBase;
	private HashMap<String,String> unison2ldap;
	
	@Override
	public LdapConnection getLocalConnection() throws ProvisioningException {
		return this.ldapPool.getConnection();
	}
	
	@Override
	public void createUser(User user,Set<String> attributes,Map<String,Object> request) throws ProvisioningException {
		LdapConnection con;
		try {
			con = this.ldapPool.getConnection();
		} catch (Exception e) {
			throw new ProvisioningException("Could not get LDAP connection " + user.getUserID(),e);
		}
		
		try {
			doCreate(user, attributes, con.getConnection(),request);
		} finally {
			con.returnCon();
		}
		

	}

	private void doCreate(User user, Set<String> attributes,
			LDAPConnection con, Map<String, Object> request) throws ProvisioningException {
		
		
		int approvalID = 0;
		
		
		
		
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		String dn = this.getDN(user,request);
		LDAPAttributeSet attrs = new LDAPAttributeSet();
		
		attrs.add(new LDAPAttribute("objectClass",this.objectClass));
		
		Iterator<String> userAttrs = user.getAttribs().keySet().iterator();
		while (userAttrs.hasNext()) {
			String attrName = userAttrs.next();
			
			if (! attributes.contains(attrName)) {
				continue;
			}
			
			LDAPAttribute ldap = new LDAPAttribute(attrName);
			Attribute attr = user.getAttribs().get(attrName);
			
			Iterator<String> vals = attr.getValues().iterator();
			while (vals.hasNext()) {
				ldap.addValue(vals.next());
			}
			
			attrs.add(ldap);
		}
		
		try {
			con.add(new LDAPEntry(dn,attrs));
		} catch (LDAPException e) {
			throw new ProvisioningException("Could not add user " + user.getUserID(),e);
		}
		
		cfgMgr.getProvisioningEngine().logAction(this.name,true, ActionType.Add, approvalID, workflow, "dn", dn);
		
		for (String attrName : user.getAttribs().keySet()) {
			if (! attributes.contains(attrName)) {
				continue;
			}
			
			for (String val : user.getAttribs().get(attrName).getValues()) {
				this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add, approvalID, workflow, attrName, val);
			}
		}
		
		try {
			Iterator<String> groupNames = user.getGroups().iterator();
			while (groupNames.hasNext()) {
				String groupName = groupNames.next();
				StringBuffer b = new StringBuffer();
				b.append("(cn=").append(groupName).append(")");
				LDAPSearchResults res = con.search(searchBase, 2, b.toString(), new String[] {"1.1"}, false);
				if (! res.hasMore()) {
					throw new ProvisioningException("Group " + groupName + " does not exist");
				}
				
				String groupDN = res.next().getDN();
				
				while (res.hasMore()) res.next();
				
				LDAPAttribute attr = new LDAPAttribute(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getGroupMemberAttribute(),dn);
				
				LDAPModification mod = new LDAPModification(LDAPModification.ADD,attr);
				
				con.modify(groupDN, mod);
				
				this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add, approvalID, workflow, "group", groupName);
			}
		} catch (LDAPException e) {
			throw new ProvisioningException("Could not provision groups for user " + user.getUserID(),e);
		}
	}

	@Override
	public void syncUser(User user,boolean fromUserOnly,Set<String> attributes,Map<String,Object> request) throws ProvisioningException {
		
		try {
			StringBuffer filter = new StringBuffer();
			filter.append("(").append(this.userIDAttribute).append("=").append(user.getUserID()).append(")");
			
			LdapConnection con;
			try {
				con = this.ldapPool.getConnection();
			} catch (Exception e) {
				throw new ProvisioningException("Could not get LDAP connection " + user.getUserID(),e);
			}
			
			try {
				doSync(user, fromUserOnly, attributes, filter, con.getConnection(),request);
			} finally {
				con.returnCon();
			}
		
			
		} catch (LDAPException e) {
			throw new ProvisioningException("Could not sync user " + user.getUserID(),e);
		}
		

	}

	private void doSync(User user, boolean fromUserOnly,
			Set<String> attributes, StringBuffer filter, LDAPConnection con, Map<String, Object> request)
			throws LDAPException, ProvisioningException {
		
		
		int approvalID = 0;
		
		
		
		
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		boolean isExternal = false;
		
		LDAPSearchResults res = con.search(searchBase, 2, filter.toString(), this.toStringArray(attributes), false);
		if (! res.hasMore()) {
			
			if (this.allowExternalUsers) {
				res = this.searchExternalUser(user.getUserID());
				if (! res.hasMore()) {
					this.createUser(user,attributes,request);
					return;
				} else {
					isExternal = true;
				}
			} else {
				this.createUser(user,attributes,request);
				return;
			}
		}  
		
		Set<String> done = new HashSet<String>();
		LDAPEntry ldapUser = res.next();
		
		while (res.hasMore()) res.next();
		
		if (! isExternal) {
			ArrayList<LDAPModification> mods = new ArrayList<LDAPModification>();
			
			
			LDAPAttributeSet attrs = ldapUser.getAttributeSet();
			Iterator<LDAPAttribute> it = attrs.iterator();
			while (it.hasNext()) {
				LDAPAttribute ldapAttr = it.next();
				done.add(ldapAttr.getName());
				Attribute userAttr = user.getAttribs().get(ldapAttr.getName());
				if (userAttr == null) {
					if (fromUserOnly ) {
						//do nothing
					} else {
						mods.add(new LDAPModification(LDAPModification.DELETE,new LDAPAttribute(ldapAttr.getName())));
					}
				} else {
					Set<String> vals = new HashSet<String>();
					vals.addAll(userAttr.getValues());
					
					String[] ldapVals = ldapAttr.getStringValueArray();
					
					
					for (int i=0;i<ldapVals.length;i++) {
						String val = ldapVals[i];
						boolean found = false;
						for (String v : vals) {
							if (v.equalsIgnoreCase(val)) {
								found = true;
								val = v;
								break;
							}
						}
						
						if (found) {
							vals.remove(val);
						} else {
							if (! fromUserOnly ) {
								LDAPAttribute todel = new LDAPAttribute(userAttr.getName());
								todel.addValue(val);
								mods.add(new LDAPModification(LDAPModification.DELETE,todel));
							}
						}
					}
					
					if (vals.size() > 0) {
						Iterator<String> itv = vals.iterator();
						LDAPAttribute toadd = new LDAPAttribute(userAttr.getName());
						while (itv.hasNext()) {
							String val = itv.next();
							if (val == null) {
								continue;
							}
							toadd.addValue(val);
						}
						
						if (toadd.size() > 0) {
							mods.add(new LDAPModification(LDAPModification.ADD,toadd));
						}
					
					}
				}
			}
			
			
			Iterator<String> itattr = user.getAttribs().keySet().iterator();
			while (itattr.hasNext()) {
				String name = itattr.next();
				if (attributes.contains(name) && ! done.contains(name))  {
					Attribute attrib = user.getAttribs().get(name);
					
					String[] vals = new String[attrib.getValues().size()];
					int i=0;
					for (String val : attrib.getValues()) {
						vals[i] = val;
						i++;
					}
					LDAPAttribute attr = new LDAPAttribute(name,vals);
					mods.add(new LDAPModification(LDAPModification.ADD,attr));
					
				}
			}
			
			
			
			if (mods.size() > 0) {
				con.modify(ldapUser.getDN(), this.toModArray(mods));
			}
		
			for (LDAPModification mod : mods) {
				ActionType at = ActionType.Add;;
				switch (mod.getOp()) {
					case (LDAPModification.ADD) : at = ActionType.Add; break;
					case (LDAPModification.REPLACE) : at = ActionType.Replace; break;
					case (LDAPModification.DELETE) : at = ActionType.Delete; break;
				}
				
				String[] vals = mod.getAttribute().getStringValueArray();
				for (String val : vals) {
					this.cfgMgr.getProvisioningEngine().logAction(this.name,false, at, approvalID, workflow, mod.getAttribute().getBaseName(), val);
				}
			}
		}
		
		
		//Groups
		
		String userDN = ldapUser.getDN();
		if (isExternal) {
			userDN = this.mapUnison2Dir(userDN);
		}
		
		StringBuffer b = new StringBuffer();
		b.append("(").append(cfgMgr.getCfg().getGroupMemberAttribute()).append("=").append(userDN).append(")");
		res = con.search(searchBase, 2, b.toString(), new String[] {"cn"}, false);
		done.clear();
		while (res.hasMore()) {
			LDAPEntry groupEntry = res.next();
			
			if (! user.getGroups().contains(groupEntry.getAttribute("cn").getStringValue())) {
				if (! fromUserOnly) {
					
					
					
					con.modify(groupEntry.getDN(), new LDAPModification(LDAPModification.DELETE,new LDAPAttribute(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getGroupMemberAttribute(),userDN)));
					cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Delete, approvalID, workflow, "group", groupEntry.getAttribute("cn").getStringValue());
				}
			}
			
			done.add(groupEntry.getAttribute("cn").getStringValue());
		}
		
		Iterator<String> itgroups = user.getGroups().iterator();
		while (itgroups.hasNext()) {
			String groupName = itgroups.next();
			
			if (done.contains(groupName)) {
				continue;
			}
			
			b.setLength(0);
			b.append("(cn=").append(groupName).append(")");
			res = con.search(searchBase, 2,b.toString() , new String[] {"1.1"}, false);
			
			if (! res.hasMore()) {
				b.setLength(0);
				b.append("Group ").append(groupName).append(" does not exist");
				logger.warn(b.toString());
				continue;
			}
			
			String groupDN = res.next().getDN();
			while (res.hasMore()) res.next();
			
			
			
			con.modify(groupDN, new LDAPModification(LDAPModification.ADD,new LDAPAttribute(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getGroupMemberAttribute(),userDN)));
			cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add, approvalID, workflow, "group", groupName);
		}
			
		
	}

	@Override
	public void deleteUser(User user,Map<String,Object> request) throws ProvisioningException {
		
		int approvalID = 0;
		
		

		
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");		
		try {
			StringBuffer filter = new StringBuffer();
			filter.append("(").append(this.userIDAttribute).append("=").append(user.getUserID()).append(")");
			
			LdapConnection con;
			try {
				con = this.ldapPool.getConnection();
			} catch (Exception e) {
				throw new ProvisioningException("Could not get LDAP connection " + user.getUserID(),e);
			}
			
			try {
				LDAPSearchResults res = con.getConnection().search(searchBase, 2, filter.toString(), new String[]{"1.1"}, false);
				if (! res.hasMore()) {
					throw new ProvisioningException("User does not exist " + user.getUserID());
				}
				
				String dn = res.next().getDN();
				while (res.hasMore()) res.next();
				
				con.getConnection().delete(dn);
				this.cfgMgr.getProvisioningEngine().logAction(this.name,true, ActionType.Delete, approvalID, workflow, "dn", dn);
				
			} finally {
				con.returnCon();
			}
		} catch (LDAPException e) {
			throw new ProvisioningException("Could not delete user " + user.getUserID(),e);
		}

	}

	@Override
	public User findUser(String userID,Set<String> attributes,Map<String,Object> request) throws ProvisioningException {
		try {
			
			StringBuffer filter = new StringBuffer();
			filter.append("(").append(this.userIDAttribute).append("=").append(userID).append(")");
			
			LdapConnection con;
			try {
				con = this.ldapPool.getConnection();
			} catch (Exception e) {
				throw new ProvisioningException("Could not get LDAP connection " + userID,e);
			}
			
			try {
				return doFindUser(userID, attributes, filter, con.getConnection());
			} finally {
				con.returnCon();
			}
			
		} catch (LDAPException e) {
			throw new ProvisioningException("Could locate user " + userID,e);
		}
	}

	private User doFindUser(String userID, Set<String> attributes,
			StringBuffer filter, LDAPConnection con) throws LDAPException {
		
		LDAPEntry ldapUser = null;
		boolean isExternal = false;
		LDAPSearchResults res = con.search(searchBase, 2, filter.toString(), this.toStringArray(attributes), false);
		if (! res.hasMore()) {
			if (this.allowExternalUsers) {
				res = searchExternalUser(userID);
				if (! res.hasMore()) {
					return null;
				}
				isExternal = true;
			} else {
				return null;
			}
		}
		
		
		
		try {
			ldapUser = res.next();
			while (res.hasMore()) res.next();
		} catch (LDAPReferralException e) {
			
		}
		
		if (ldapUser == null) {
			
			return null;
			
			
		}
		
		User user = new User(userID);
		
		Iterator<LDAPAttribute> it = ldapUser.getAttributeSet().iterator();
		while (it.hasNext()) {
			LDAPAttribute attr  =  it.next();
			Attribute userAttr = new Attribute(attr.getName());
			String[] vals = attr.getStringValueArray();
			for (int i=0;i<vals.length;i++) {
				userAttr.getValues().add(vals[i]);
			}
			user.getAttribs().put(userAttr.getName(), userAttr);
		}
		
		StringBuffer b = new StringBuffer();
		
		
		
		
		//b.append("(uniqueMember=").append(ldapUser.getDN()).append(")");
		
		String userDN = ldapUser.getDN();
		if (isExternal) {
			userDN = this.mapUnison2Dir(userDN);
		}
		
		
		res = con.search(searchBase, 2, equal(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getGroupMemberAttribute(),userDN).toString(), new String[] {"cn"}, false);
		while (res.hasMore()) {
			LDAPEntry group = res.next();
			user.getGroups().add(group.getAttribute("cn").getStringValue());
		}
		
		
		return user;
	}

	private LDAPEntry loadExternalUser(String userID, LDAPEntry ldapUser)
			throws LDAPException {
		LDAPSearchResults res = searchExternalUser(userID);
		if (! res.hasMore()) {
			return null;
		} else {
			ldapUser = res.next();
			while (res.hasMore()) res.next();
		}
		
		if (ldapUser == null) {
			return null;
		}
		return ldapUser;
	}

	private LDAPSearchResults searchExternalUser(String userID)
			throws LDAPException {
		LDAPSearchResults res;
		ArrayList<String> attrs = new ArrayList<String>();
		attrs.add("1.1");
		StringBuffer filter = new StringBuffer();
		filter.append("(").append(this.userIDAttribute).append("=").append(userID).append(")");
		res = this.cfgMgr.getMyVD().search(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot(), 2, filter.toString(), attrs);
		return res;
	}

	@Override
	public void init(Map<String, Attribute> cfg,ConfigManager cfgMgr,String name)
			throws ProvisioningException {
		
		this.cfgMgr = cfgMgr;
		
		this.name = name;
		
		try {
			String host = cfg.get("host").getValues().get(0);
			int port = Integer.parseInt(cfg.get("port").getValues().get(0));
			this.userDN = cfg.get("adminDN").getValues().get(0);
			this.passwd = cfg.get("adminPasswd").getValues().get(0);
			this.dnPattern = cfg.get("dnPattern").getValues().get(0);
			this.searchBase = cfg.get("searchBase").getValues().get(0);
			this.objectClass = cfg.get("objectClass").getValues().get(0);
			
			this.userIDAttribute = cfg.get("userIDAttribute").getValues().get(0);
			
			if (cfg.get("useSSL") != null) {
				this.isSSL = Boolean.parseBoolean(cfg.get("useSSL").getValues().get(0));
			} else {
				this.isSSL = false;
			}
			
			int maxCons = Integer.parseInt(cfg.get("maxCons").getValues().get(0));
			int threadsPerCon = Integer.parseInt(cfg.get("threadsPerCons").getValues().get(0));
			
			Attribute timeout = cfg.get("idleTimeout");
			if (timeout == null) {
				this.idleTimeout = 10000;
			} else {
				this.idleTimeout = Long.parseLong(timeout.getValues().get(0));
			}
			
			this.ldapPool = new LdapPool(cfgMgr,host,port,this.userDN,this.passwd,this.isSSL,0,maxCons,this.idleTimeout);
			
			if (cfg.get("allowExternalUsers") != null) {
				this.allowExternalUsers = cfg.get("allowExternalUsers").getValues().get(0).equalsIgnoreCase("true");
			} else {
				this.allowExternalUsers = false;
			}
			
			logger.info("Allow External User : '"  + this.allowExternalUsers + "'");
			
			if (this.allowExternalUsers) {
				this.unison2ldap = new HashMap<String,String>();
				if (cfg.get("externalUserMapInUnison") != null && ! cfg.get("externalUserMapInUnison").getValues().get(0).isEmpty()) {
					this.unisonBase = cfg.get("externalUserMapInUnison").getValues().get(0);
					this.lcUnisonBase = unisonBase.toLowerCase();
					this.ldapBase = cfg.get("externalUserMapInDir").getValues().get(0);
					this.lcLDAPBase = ldapBase.toLowerCase();
				}
			}
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not initialize",e);
		}
	}
	
	private String getDN(User user,Map<String,Object> request) throws ProvisioningException {
		String ldnPattern;
		
		if (request.get(LDAPProvider.NEW_USER_DN) != null) {
			ldnPattern = (String) request.get(LDAPProvider.NEW_USER_DN);
		} else {
			ldnPattern = this.dnPattern;
		}
		
		StringBuffer dn = new StringBuffer();
		int last = 0;
		int index = ldnPattern.indexOf('$');
		while (index != -1) {
			int begin = index + 1;
			int end = ldnPattern.indexOf('}',begin + 1);

			dn.append(ldnPattern.substring(last,index));
			
			String attr = ldnPattern.substring(begin + 1,end);
			Attribute attrib = user.getAttribs().get(attr);
			
			if (attrib == null) {
				throw new ProvisioningException("User " + user.getUserID() + " does not have attribute " + attr);
			}
			
			dn.append(attrib.getValues().get(0));
			
			
			
			last = end + 1;
			index = ldnPattern.indexOf('$',last);
		}
		
		dn.append(ldnPattern.substring(last));
		
		return dn.toString();
		
	}

	private String[] toStringArray(Set<String> list) {
		String[] ret = new String[list.size()];
		Iterator<String> it = list.iterator();
		int i=0;
		while (it.hasNext()) {
			ret[i] = it.next();
			i++;
			
		}
		return ret;
	}
	
	private LDAPModification[] toModArray(List<LDAPModification> list) {
		LDAPModification[] ret = new LDAPModification[list.size()];
		Iterator<LDAPModification> it = list.iterator();
		int i=0;
		while (it.hasNext()) {
			ret[i] = it.next();
			i++;
			
		}
		return ret;
	}

	@Override
	public void setUserPassword(User user,Map<String,Object> request) throws ProvisioningException {
		StringBuffer filter = new StringBuffer();
		filter.append("(").append(this.userIDAttribute).append("=").append(user.getUserID()).append(")");
		
		
		int approvalID = 0;
		
		
		
		
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		
		try {
			
			LdapConnection con;
			try {
				con = this.ldapPool.getConnection();
			} catch (Exception e) {
				throw new ProvisioningException("Could not get LDAP connection " + user.getUserID(),e);
			}
			
			try {
				LDAPSearchResults res = con.getConnection().search(this.searchBase, 2, filter.toString(), new String[] {"1.1"}, false);
				if (! res.hasMore()) {
					throw new ProvisioningException("Could not find user");
				}
				
				String dn = res.next().getDN();
				
				LDAPModification mod = new LDAPModification(LDAPModification.REPLACE,new LDAPAttribute("userPassword",user.getPassword()));
				con.getConnection().modify(dn, mod);
				
				this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Replace, approvalID, workflow, "userPassword", "*********");
			} finally {
				con.returnCon();
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not set user's password",e);
		}
		
	}
	
	private String mapUnison2Dir(String unison) {
		if (this.unisonBase == null) {
			return unison;
		} else {
			String dir = this.unison2ldap.get(unison);
			if (dir != null) {
				return dir;
			} else {
				if (unison.toLowerCase().endsWith(this.unisonBase.toLowerCase())) {
					StringBuffer newDN = new StringBuffer();
					newDN.append(unison.substring(0,unison.length() - this.unisonBase.length())).append(this.ldapBase);
					dir = newDN.toString();
				} else {
					dir = unison;
				}
				this.unison2ldap.put(unison, dir);
				return dir;
			}
		}
	}

	@Override
	public void addGroup(String name, Map<String, String> additionalAttributes, User user, Map<String, Object> request)
			throws ProvisioningException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void deleteGroup(String name, User user, Map<String, Object> request) throws ProvisioningException {
		try {
			
			LdapConnection con;
			try {
				con = this.ldapPool.getConnection();
			} catch (Exception e) {
				throw new ProvisioningException("Could not get LDAP connection " + user.getUserID(),e);
			}
			
			try {
				LDAPSearchResults res = con.getConnection().search(this.searchBase, 2, and(equal("objectClass",this.cfgMgr.getCfg().getGroupObjectClass()),equal("cn",name)).toString(), new String[] {"1.1"}, false);
				if (res.hasMore()) {
					LDAPEntry entry = res.next();
					con.getConnection().delete(entry.getDN());
				}
				
				
			} finally {
				con.returnCon();
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not set user's password",e);
		}
	}
		
	

	@Override
	public boolean isGroupExists(String name, User user, Map<String, Object> request) throws ProvisioningException {
		try {
			
			LdapConnection con;
			try {
				con = this.ldapPool.getConnection();
			} catch (Exception e) {
				throw new ProvisioningException("Could not get LDAP connection " + user.getUserID(),e);
			}
			
			try {
				LDAPSearchResults res = con.getConnection().search(this.searchBase, 2, and(equal("objectClass",this.cfgMgr.getCfg().getGroupObjectClass()),equal("cn",name)).toString(), new String[] {"1.1"}, false);
				if (! res.hasMore()) {
					return false;
				}
				
				return true;
			} finally {
				con.returnCon();
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not set user's password",e);
		}
	}

	public String getSearchBase() {
		return this.searchBase;
	}
}


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

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.LDAPSocketFactory;
import com.novell.ldap.connectionpool.PoolManager;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningEngine;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.util.GenPasswd;
import com.tremolosecurity.provisioning.util.ldap.pool.LdapConnection;
import com.tremolosecurity.provisioning.util.ldap.pool.LdapPool;
import com.tremolosecurity.proxy.ssl.TremoloSSLSocketFactory;
import com.tremolosecurity.saml.Attribute;



public class ADProvider implements UserStoreProvider {

	static Logger logger = Logger.getLogger(ADProvider.class);
	
	LdapPool ldapPool;
	String dnPattern;
	String searchBase;
	public String getSearchBase() {
		return searchBase;
	}

	String objectClass;

	String userIDAttribute;
	
	private boolean isSSL;
	
	private boolean createShadowAccounts;
	
	private boolean supportExternalUsers;
	
	private String externalGroupAttr;

	private String userDN;

	private String passwd;
	
	private ConfigManager cfgMgr;
	
	String name;
	
	private long idleTimeout;
	
	@Override
	public void createUser(User user,Set<String> attributes,Map<String,Object> request) throws ProvisioningException {
		String dn = this.getDN(user);
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
		
		LdapConnection con;
		try {
			con = this.ldapPool.getConnection();
		} catch (Exception e) {
			StringBuffer b = new StringBuffer();
			b.append("Could not get LDAP connection ").append(user.getUserID());
			throw new ProvisioningException(b.toString(),e);
		} 
		
		try {
			doCreate(user, dn, attrs, con.getConnection(),request);
		} finally {
			con.returnCon();
		}
		

	}

	private void doCreate(User user, String dn, LDAPAttributeSet attrs,
			LDAPConnection con, Map<String, Object> request) throws ProvisioningException {
		
		
		int approvalID = 0;
		
		
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		
		
		try {
			if (logger.isDebugEnabled()) {
				logger.debug("To Add : '" + attrs + "'");
			}
			con.add(new LDAPEntry(dn,attrs));
			
			
			this.cfgMgr.getProvisioningEngine().logAction(name,true, ActionType.Add, approvalID, workflow,"dn", dn);
			
			for (Object obj : attrs) {
				LDAPAttribute attr = (LDAPAttribute) obj;
				String[] vals = attr.getStringValueArray();
				for (String val : vals) {
					this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add, approvalID, workflow,attr.getName(),val);
				}
			}
			
		} catch (LDAPException e) {
			StringBuffer b = new StringBuffer();
			b.append("Could not add user ").append(user.getUserID());
			throw new ProvisioningException(b.toString(),e);
		}
		
		
		if (this.createShadowAccounts) {
			StringBuffer password = new StringBuffer();
			GenPasswd gp = new GenPasswd(15);
			password.append('"').append(gp.getPassword()).append('"');
			byte[] unicodePwd;
			try {
				unicodePwd = password.toString().getBytes("UTF-16LE");
			} catch (UnsupportedEncodingException e) {
				throw new ProvisioningException("Could not generate password",e);
			}
			
			LDAPModification mod = new LDAPModification(LDAPModification.REPLACE,new LDAPAttribute("unicodePwd",unicodePwd));
			try {
				con.modify(dn, mod);
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Replace,  approvalID,workflow, "unicodePwd", "*******");
			} catch (LDAPException e) {
				throw new ProvisioningException("Could not set password",e);
			}
			
			try {
				LDAPSearchResults res = con.search(dn, 0, "(objectClass=*)", new String[] {"userAccountControl"}, false);
				res.hasMore();
				LDAPEntry entry = res.next();
				LDAPAttribute attr = entry.getAttribute("userAccountControl");
				
				int val = Integer.parseInt(attr.getStringValue());
				
				if ((val & 2) == 2) {
					val -= 2;
				}
				
				if ((val & 65536) != 65536) {
					val += 65536;
				}
				
				mod = new LDAPModification(LDAPModification.REPLACE,new LDAPAttribute("userAccountControl",Integer.toString(val)));
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Replace,  approvalID,workflow, "userAccountControl", Integer.toString(val));
				con.modify(dn, mod);
				
			} catch (LDAPException e) {
				throw new ProvisioningException("Could not set userAccountControl",e);
			}
			
			
		}
		
		try {
			Iterator<String> groupNames = user.getGroups().iterator();
			while (groupNames.hasNext()) {
				String groupName = groupNames.next();
				StringBuffer b = new StringBuffer();
				b.append("(cn=").append(groupName).append(")");
				LDAPSearchResults res = con.search(searchBase, 2, b.toString() , new String[] {"1.1"}, false);
				if (! res.hasMore()) {
					b.setLength(0);
					b.append("Group ").append(groupName).append(" does not exist");
					throw new ProvisioningException(b.toString());
				}
				
				String groupDN = res.next().getDN();
				
				try {
					while (res.hasMore()) res.next();
				} catch (LDAPReferralException e) {
					
				}
				
				LDAPAttribute attr = new LDAPAttribute("member",dn);
				
				LDAPModification mod = new LDAPModification(LDAPModification.ADD,attr);
				
				con.modify(groupDN, mod);
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID,workflow, "group", groupName);
				
				
			}
		} catch (LDAPException e) {
			StringBuffer b = new StringBuffer();
			b.append("Could not provision groups for user ").append(user.getUserID());
			throw new ProvisioningException(b.toString(),e);
		}
	}

	@Override
	public void syncUser(User user,boolean fromUserOnly,Set<String> attributes,Map<String, Object> request) throws ProvisioningException {
		try {
			StringBuffer filter = new StringBuffer();
			filter.append("(").append(this.userIDAttribute).append("=").append(user.getUserID()).append(")");
			
			LdapConnection con;
			try {
				con = this.ldapPool.getConnection();
			} catch (Exception e) {
				StringBuffer b = new StringBuffer();
				b.append("Could not get LDAP connection ").append(user.getUserID());
				throw new ProvisioningException(b.toString() ,e);
			}
			
			try {
				doSync(user, fromUserOnly, attributes, filter, con.getConnection(),request);
			} finally {
				con.returnCon();
			}
		
			
		} catch (LDAPException e) {
			StringBuffer b = new StringBuffer();
			b.append("Could not sync user ").append(user.getUserID());
			throw new ProvisioningException(b.toString(),e);
		}
		

	}

	private void doSync(User user, boolean fromUserOnly,
			Set<String> attributes, StringBuffer filter, LDAPConnection con, Map<String, Object> request)
			throws LDAPException, ProvisioningException {
		
	
		
		LDAPSearchResults res = con.search(searchBase, 2, filter.toString(), this.toStringArray(attributes), false);
		
		
		
		
		int approvalID = 0;
		
		boolean isExternal = false;
		
		LDAPEntry ldapUser = null;
		
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		if (! res.hasMore()) {
			
			if (this.supportExternalUsers) {
				ldapUser = this.getMyVDUser(filter);
				if (ldapUser == null) {
					this.createUser(user,attributes,request);
					
				} else {
					isExternal = true;

					
					ArrayList<LDAPModification> mods = new ArrayList<LDAPModification>();
					HashSet<String> done = new HashSet<String>();
					
					syncUser(user, fromUserOnly, attributes, con, approvalID,
							workflow, mods, done, ldapUser,isExternal);
				}
			} else {
				this.createUser(user,attributes,request);
			}
			
			
		} else {
			
			ArrayList<LDAPModification> mods = new ArrayList<LDAPModification>();
			HashSet<String> done = new HashSet<String>();
			
			
			try {
			
				ldapUser = res.next();
				
				try {
					while (res.hasMore()) res.next();
				} catch (LDAPReferralException e) {
					
				}
			} catch (LDAPReferralException e) {
				if (this.supportExternalUsers) {
					ldapUser = this.getMyVDUser(filter);
					
					if (ldapUser == null) {
						this.createUser(user, attributes,request);
						return;
					} else {
						isExternal = true;
					}
				} else {
					this.createUser(user, attributes,request);
					return;
				}
				
				
			}
			
			
			syncUser(user, fromUserOnly, attributes, con, approvalID,
					workflow, mods, done, ldapUser,isExternal);
			
		}
	}

	private void syncUser(User user, boolean fromUserOnly,
			Set<String> attributes, LDAPConnection con,
			 int approvalID, Workflow workflow,
			ArrayList<LDAPModification> mods, HashSet<String> done,
			LDAPEntry ldapUser, boolean isExternal) throws LDAPException, ProvisioningException {
		
		
		
		LDAPSearchResults res;
		
		if (! isExternal) {
			syncUserAttributes(user, fromUserOnly, attributes, con, approvalID,
					workflow, mods, done, ldapUser);
		}

		
		
		if (isExternal) {
			
			String fdn = ldapUser.getDN();
			
			
			
			/*if (fdn.contains("\\\\\\\\,")) { 
				fdn = fdn.replaceAll("\\\\\\\\,","\\5C,");               
			}
			
			
			
			if (fdn.contains("\\,")) { 
				fdn = fdn.replaceAll("\\\\,","\\\\5C,");               
			}*/
			
			//fdn = this.adEscape(fdn);
			
			
			
			
			
			
			
			res = con.search(searchBase, 2, equal(this.externalGroupAttr,fdn).toString(), new String[] {"cn"}, false);
		} else {
			
			String fdn = ldapUser.getDN();
			
			/*if (fdn.contains("\\,")) { 
				fdn = fdn.replaceAll("[\\\\][,]","\\\\5C,");               
			} */
			//fdn = this.adEscape(fdn);
			
			StringBuffer f = new StringBuffer();
			
			
			res = con.search(searchBase, 2, equal("member",fdn).toString(), new String[] {"cn"}, false);
		}
		
		done.clear();
		while (res.hasMore()) {
			LDAPEntry groupEntry = null;
			try {
			
			groupEntry = res.next();
			} catch (LDAPReferralException e) {
				break;
			}
			
			String memberDN = ldapUser.getDN();
			
			if (memberDN.contains("\\\\\\,")) { 
				memberDN = memberDN.replaceAll("\\\\\\\\,","\\,");               
			} 

			
			
			if (! user.getGroups().contains(groupEntry.getAttribute("cn").getStringValue())) {
				if (! fromUserOnly) {
					if (isExternal) {
						if (logger.isDebugEnabled()) {
							logger.debug("Deleting external '" + memberDN + "' from '" + groupEntry.getDN() + "'");
						}
						con.modify(groupEntry.getDN(), new LDAPModification(LDAPModification.DELETE,new LDAPAttribute(this.externalGroupAttr,memberDN)));
					} else {
						if (logger.isDebugEnabled()) {
							logger.debug("Deleting internal '" + memberDN + "' from '" + groupEntry.getDN() + "'");
						}
						con.modify(groupEntry.getDN(), new LDAPModification(LDAPModification.DELETE,new LDAPAttribute("member",memberDN)));
					}
					this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Delete,  approvalID, workflow, "group", groupEntry.getAttribute("cn").getStringValue());
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
			
			StringBuffer b = new StringBuffer();
			b.append("(cn=").append(groupName).append(")");
			
			res = con.search(searchBase, 2, b.toString(), new String[] {"1.1"}, false);
			
			if (! res.hasMore()) {
				
				if (! isExternal) {
					b.setLength(0);
					b.append("Group ").append(groupName).append(" does not exist");
					logger.warn(b.toString());
				}
				continue;
			}
			
			String groupDN = res.next().getDN();
			
			
			while (res.hasMore()) {
				try {
					res.next();
				} catch (LDAPException e) {
					//do nothing
				}
			}
			
			String memberDN = ldapUser.getDN();
			
			if (memberDN.contains("\\\\\\,")) { 
				memberDN = memberDN.replaceAll("\\\\\\\\,","\\,");               
			} 
			
			
			
			if (isExternal) {
				if (logger.isDebugEnabled()) {
					logger.debug("Adding external '" + memberDN + "' to '" + groupDN + "'");
				}
				con.modify(groupDN, new LDAPModification(LDAPModification.ADD,new LDAPAttribute(this.externalGroupAttr,memberDN)));
			} else {
				if (logger.isDebugEnabled()) {
					logger.debug("Adding internal '" + memberDN + "' to '" + groupDN + "'");
				}
				con.modify(groupDN, new LDAPModification(LDAPModification.ADD,new LDAPAttribute("member",memberDN)));
			}
			this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, "group", groupName);
		}
	}

	private void syncUserAttributes(User user, boolean fromUserOnly,
			Set<String> attributes, LDAPConnection con, int approvalID,
			Workflow workflow, List<LDAPModification> mods,
			HashSet<String> done, LDAPEntry ldapUser) throws LDAPException,
			ProvisioningException {
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
				HashSet<String> vals = new HashSet<String>();
				HashSet<String> valslcase = new HashSet<String>();
				
				for (String v : userAttr.getValues()) {
					String vlcase = v.toLowerCase();
					if (! valslcase.contains(vlcase)) {
						vals.add(v);
						valslcase.add(vlcase);
					}
				}
				
				
				
				
				String[] ldapVals = ldapAttr.getStringValueArray();
				
				
				for (int i=0;i<ldapVals.length;i++) {
					String ldapVal = ldapVals[i];
					boolean found = false;
					for (String objVal : vals) {
						if (logger.isDebugEnabled()) {
							logger.debug("From LDAP : '" + ldapVal + "' / From UserObject : '" + objVal + "'");
						}
						if (objVal.equalsIgnoreCase(ldapVal)) {
							found = true;
							ldapVal = objVal;
							
							if (logger.isDebugEnabled()) {
								logger.debug("matched, need to remove");
							}
							
							
							break;
						}
					}
					
					if (found) {
						
						if (logger.isDebugEnabled()) {
							logger.debug("found match, removing : '" + ldapVal + "' - vals pre - '" + vals + "'");
						}
						
						vals.remove(ldapVal);
						
						if (logger.isDebugEnabled()) {
							logger.debug("After remove : '" + vals + "'");
						}
					} else {
						if (! fromUserOnly ) {
							LDAPAttribute todel = new LDAPAttribute(userAttr.getName());
							todel.addValue(ldapVal);
							mods.add(new LDAPModification(LDAPModification.DELETE,todel));
						}
					}
				}
				
				if (vals.size() > 0) {
					Iterator<String> itv = vals.iterator();
					LDAPAttribute toadd = new LDAPAttribute(userAttr.getName());
					while (itv.hasNext()) {
						String val = itv.next();
						toadd.addValue(val);
					}
					
					mods.add(new LDAPModification(LDAPModification.ADD,toadd));
				
				}
			}
		}
		
		
		Iterator<String> itattr = user.getAttribs().keySet().iterator();
		while (itattr.hasNext()) {
			String name = itattr.next();
			if (logger.isDebugEnabled()) {
				logger.debug("post sync checking '" + name + "' / done : '" + done + "'");
			}
			
			if (attributes.contains(name) && ! done.contains(name))  {
				if (logger.isDebugEnabled()) {
					logger.debug("Not added yet, adding");
				}
				Attribute attrib = user.getAttribs().get(name);
				LDAPAttribute attr = new LDAPAttribute(name);
				for (String val : attrib.getValues()) {
					attr.addValue(val);
				}
				mods.add(new LDAPModification(LDAPModification.ADD,attr));
				
			}
		}
		
		if (logger.isDebugEnabled()) {
			logger.debug("Mods : '" + mods + "'");
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
				this.cfgMgr.getProvisioningEngine().logAction(name,false, at, approvalID, workflow, mod.getAttribute().getBaseName(), val);
			}
		}
	}

	@Override
	public void deleteUser(User user,Map<String, Object> request) throws ProvisioningException {
		
		try {
			StringBuffer filter = new StringBuffer();
			filter.append("(").append(this.userIDAttribute).append("=").append(user.getUserID()).append(")");
			
			LdapConnection con;
			try {
				con = this.ldapPool.getConnection();
			} catch (Exception e) {
				StringBuffer b = new StringBuffer();
				b.append("Could not get LDAP connection ").append(user.getUserID());
				throw new ProvisioningException(b.toString(),e);
			}
			
			try {
				doDelete(user, filter, con.getConnection(),request);
			} finally {
				con.returnCon();
			}
			
		} catch (LDAPException e) {
			StringBuffer b = new StringBuffer();
			b.append("Could not delete user ").append(user.getUserID());
			throw new ProvisioningException(b.toString(),e);
		}

	}

	private void doDelete(User user, StringBuffer filter, LDAPConnection con, Map<String, Object> request)
			throws LDAPException, ProvisioningException {
		
		
		boolean isExternal = false;
		
		int approvalID = 0;
		
		
		
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		String dn = null;
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		LDAPSearchResults res = con.search(searchBase, 2, filter.toString(), new String[]{"1.1"}, false);
		if (! res.hasMore()) {
			if (this.supportExternalUsers) {
				LDAPEntry entry = getMyVDUser(filter); 
				
				if (entry == null) {
					StringBuffer b = new StringBuffer("User does not exist ").append(user.getUserID());
					throw new ProvisioningException(b.toString());
				} else {
					dn = entry.getDN();
					isExternal = true;
				}
			} else {
				StringBuffer b = new StringBuffer();
				b.append("User does not exist ").append(user.getUserID());
				throw new ProvisioningException(b.toString());
			}
		} else {
			try {
				
				dn = res.next().getDN();
				
				
				while (res.hasMore()) res.next();
			
			} catch (LDAPReferralException e) {
				
			}
		}
		
		
		
		
		
		if (dn == null) {
			if (this.supportExternalUsers) {
				LDAPEntry entry = getMyVDUser(filter); 
				
				if (entry == null) {
					StringBuffer b = new StringBuffer();
					b.append("User does not exist ").append(user.getUserID());
					throw new ProvisioningException(b.toString());
				} else {
					dn = entry.getDN();
					isExternal = true;
				}
			} else {
				StringBuffer b = new StringBuffer();
				b.append("User does not exist ").append(user.getUserID());
				throw new ProvisioningException(b.toString());
			}
			
		}
		
		if (! isExternal) {
			con.delete(dn);
			this.cfgMgr.getProvisioningEngine().logAction(name,true, ActionType.Delete,  approvalID, workflow, "dn", dn);
		} else {
			for (String groupName : user.getGroups()) {
				StringBuffer b = new StringBuffer();
				b.append("(CN=").append(groupName).append(")");
				res = con.search(this.searchBase, LDAPConnection.SCOPE_SUB,b.toString() , new String[]{"1.1"}, false);
				
				if (res.hasMore()) {
					LDAPEntry entry = res.next();
					if (entry != null) {
						String groupdn = entry.getDN();
						LDAPAttribute attr = new LDAPAttribute(this.externalGroupAttr,dn);
						LDAPModification mod = new LDAPModification(LDAPModification.DELETE,attr);
						con.modify(groupdn, mod);
						this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Delete,  approvalID, workflow, this.externalGroupAttr, groupdn);
					}
				}
				
			}
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
				StringBuffer b = new StringBuffer();
				b.append("Could not get LDAP connection ").append(userID);
				throw new ProvisioningException(b.toString(),e);
			}
			
			try {
				return doFindUser(userID, attributes, filter, con.getConnection());
			} finally {
				con.returnCon();
			}
			
		} catch (LDAPException e) {
			StringBuffer b = new StringBuffer();
			b.append("Could not locate user ").append(userID);
			throw new ProvisioningException(b.toString(),e);
		}
	}

	private User doFindUser(String userID, Set<String> attributes,
			StringBuffer filter, LDAPConnection con) throws LDAPException {
		
		boolean externalUser = false;
		
		LDAPSearchResults res = con.search(searchBase, 2, filter.toString(), this.toStringArray(attributes), false);
		LDAPEntry ldapUser = null;
		if (! res.hasMore()) {
			ldapUser = getMyVDUser(filter);
			
			if (ldapUser == null) {
				return null;
			} else {
				externalUser = true;
			}
			
		} else {
		
			
			
			try {
				ldapUser = res.next();
				while (res.hasMore()) res.next();
			} catch (LDAPReferralException e) {
				
			}
			
			if (ldapUser == null) {
				ldapUser = getMyVDUser(filter);
				if (ldapUser == null) {
					return null;
				} else {
					externalUser = true;
				}
			}
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
		
		
		
		if (externalUser) {
			
			
			/*if (ldapf.contains("\\,")) { 
				ldapf = ldapf.replaceAll("\\\\\\\\,","\\5C,");               
			} */
			
			
			
			//ldapf = this.adEscape(ldapf);
			
			
			
			
			res = con.search(searchBase, 2, equal(this.externalGroupAttr,ldapUser.getDN()).toString(), new String[] {"cn"}, false);
			while (res.hasMore()) {
				LDAPEntry group = null;
				
				try {
					group = res.next();
				} catch (LDAPReferralException e) {
					continue;
				}
				
				user.getGroups().add(group.getAttribute("cn").getStringValue());
			}
		} else {
			StringBuffer f = new StringBuffer();
			
			
			
			String ldapf = equal("member",ldapUser.getDN()).toString();
			/*if (ldapf.contains("\\,")) { 
			                       ldapf = ldapf.replaceAll("[\\\\][,]","\\\\5C,");               
			} */
			
			//ldapf = this.adEscape(ldapf);
			
			res = con.search(searchBase, 2, ldapf, new String[] {"cn"}, false);
			while (res.hasMore()) {
				LDAPEntry group = null;
				
				try {
					group = res.next();
				} catch (LDAPReferralException e) {
					continue;
				}
				
				user.getGroups().add(group.getAttribute("cn").getStringValue());
			}
		}
		
		return user;
	}

	private LDAPEntry getMyVDUser(StringBuffer filter) throws LDAPException {
		LDAPSearchResults res;
		LDAPEntry ldapUser;
		ArrayList<String> attrs = new ArrayList<String>();
		attrs.add("1.1");
		res = this.cfgMgr.getMyVD().search("o=Tremolo", 2, filter.toString(), attrs);
		
		if (! res.hasMore()) {
			return null;
		}
		
		ldapUser = res.next();
		
		while (res.hasMore()) res.next();
		return ldapUser;
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
			
			this.supportExternalUsers = cfg.get("supportExternalUsers") != null && cfg.get("supportExternalUsers").getValues().get(0).equalsIgnoreCase("true");
			
			if (this.supportExternalUsers) {
				this.externalGroupAttr = cfg.get("externalGroupAttr").getValues().get(0);
				
			}
			
			this.userIDAttribute = cfg.get("userIDAttribute").getValues().get(0);
			
			this.objectClass = "user";
			
			if (cfg.get("useSSL") != null) {
				this.isSSL = Boolean.parseBoolean(cfg.get("useSSL").getValues().get(0));
			} else {
				this.isSSL = false;
			}
			
			if (cfg.get("createShadowAccount") != null) {
				this.createShadowAccounts = Boolean.parseBoolean(cfg.get("createShadowAccount").getValues().get(0));
			} else {
				this.createShadowAccounts = false;
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
			
			
			
			
			
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not initialize",e);
		}
	}
	
	private String getDN(User user) throws ProvisioningException {
		StringBuffer dn = new StringBuffer();
		int last = 0;
		int index = dnPattern.indexOf('$');
		while (index != -1) {
			int begin = index + 1;
			int end = dnPattern.indexOf('}',begin + 1);

			dn.append(dnPattern.substring(last,index));
			
			String attr = dnPattern.substring(begin + 1,end);
			Attribute attrib = user.getAttribs().get(attr);
			
			if (attrib == null) {
				StringBuffer b = new StringBuffer();
				b.append("User ").append(user.getUserID()).append(" does not have attribute ").append(attr);
				throw new ProvisioningException(b.toString());
			}
			
			String val = attrib.getValues().get(0);
			val = val.replace(",", "\\,");
			
			dn.append(val);
			
			
			
			last = end + 1;
			index = dnPattern.indexOf('$',last);
		}
		
		dn.append(dnPattern.substring(last));
		
		
		
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
		try {
			
			LdapConnection con;
			try {
				con = this.ldapPool.getConnection();
			} catch (Exception e) {
				StringBuffer b = new StringBuffer();
				b.append("Could not get LDAP connection ").append(user.getUserID());
				throw new ProvisioningException(b.toString(),e);
			}
			
			try {
				doSetPassword(user, filter, con.getConnection(),request);
			} finally {
				con.returnCon();
			}
				
			
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not set user's password",e);
		}
		
	}

	private void doSetPassword(User user, StringBuffer filter,
			LDAPConnection con, Map<String, Object> request) throws LDAPException, ProvisioningException {
		
		
		int approvalID = 0;
		
		
		
		
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		LDAPSearchResults res = con.search(this.searchBase, 2, filter.toString(), new String[] {"1.1"}, false);
		if (! res.hasMore()) {
			throw new ProvisioningException("Could not find user");
		}
		
		LDAPEntry entry = res.next();
		String dn = entry.getDN();
		
		StringBuffer password = new StringBuffer();
		password.append('"').append(user.getPassword()).append('"');
		byte[] unicodePwd;
		try {
			unicodePwd = password.toString().getBytes("UTF-16LE");
		} catch (UnsupportedEncodingException e) {
			throw new ProvisioningException("Could not generate password",e);
		}
		
		LDAPModification mod = new LDAPModification(LDAPModification.REPLACE,new LDAPAttribute("unicodePwd",unicodePwd));
		try {
			con.modify(dn, mod);
			this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Replace, approvalID, workflow, "unicodePwd", "*******");
		} catch (LDAPException e) {
			throw new ProvisioningException("Could not set password",e);
		}
		
		
		res = con.search(dn, 0, "(objectClass=*)", new String[] {"userAccountControl"}, false);
		res.hasMore();
		entry = res.next();
		LDAPAttribute attr = entry.getAttribute("userAccountControl");
		
		int val = Integer.parseInt(attr.getStringValue());
		
		if ((val & 2) == 2) {
			val -= 2;
		}
		
		if ((val & 65536) != 65536) {
			val += 65536;
		}
		
		mod = new LDAPModification(LDAPModification.REPLACE,new LDAPAttribute("userAccountControl",Integer.toString(val)));
		this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Replace, approvalID, workflow, "userAccountControl",Integer.toString(val));
		con.modify(dn, mod);
	}
	
	public LdapConnection checkoutConnection() throws ProvisioningException {
		return this.ldapPool.getConnection();
	}
	
	private String adEscape(String dn) {
		StringBuffer sb = new StringBuffer();
		
		for (int i=0;i<dn.length();i++) {
			if (dn.charAt(i) == '\\') {
				if ((i + 1) < dn.length()) {
					if (dn.charAt(i + 1) == ',') {
						sb.append("\\5C,");
						i++;
					} else if (i + 3< dn.length()) {
						if ((dn.charAt(i + 2) == '\\') && (dn.charAt(i + 3) == ',') ) {
							sb.append("\\5C,");
							i+=3;
						} else {
							sb.append(dn.charAt(i));
						}
					} else {
						sb.append(dn.charAt(i));
					}
				} else {
					sb.append(dn.charAt(i));
				}
			} else {
				sb.append(dn.charAt(i));
			}
		}
		
		return sb.toString();
	}
}


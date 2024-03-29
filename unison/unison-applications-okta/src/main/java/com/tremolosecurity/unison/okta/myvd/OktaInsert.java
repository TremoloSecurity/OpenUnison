/*******************************************************************************
 * Copyright 2019 Tremolo Security, Inc.
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
package com.tremolosecurity.unison.okta.myvd;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.logging.log4j.Logger;

import org.json.simple.JSONObject;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;
import com.okta.sdk.resource.api.GroupApi;
import com.okta.sdk.resource.client.ApiClient;
import com.okta.sdk.resource.client.ApiException;
import com.okta.sdk.resource.model.Group;
import com.okta.sdk.resource.model.User;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.okta.provisioning.OktaTarget;
import com.tremolosecurity.util.ObjUtils;

import net.sourceforge.myvd.chain.AddInterceptorChain;
import net.sourceforge.myvd.chain.BindInterceptorChain;
import net.sourceforge.myvd.chain.CompareInterceptorChain;
import net.sourceforge.myvd.chain.DeleteInterceptorChain;
import net.sourceforge.myvd.chain.ExetendedOperationInterceptorChain;
import net.sourceforge.myvd.chain.ModifyInterceptorChain;
import net.sourceforge.myvd.chain.PostSearchCompleteInterceptorChain;
import net.sourceforge.myvd.chain.PostSearchEntryInterceptorChain;
import net.sourceforge.myvd.chain.RenameInterceptorChain;
import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.ExtendedOperation;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.FilterNode;
import net.sourceforge.myvd.types.FilterType;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;
import net.sourceforge.myvd.util.EntryUtil;
import net.sourceforge.myvd.util.IteratorEntrySet;

public class OktaInsert implements Insert {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(OktaInsert.class.getName());

	String name;
	String target;
	NameSpace nameSpace;
	
	String objectClass;
	

	DN baseDN;
	boolean users;
	
	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public void configure(String name, Properties props, NameSpace ns) throws LDAPException {
		this.name = name;
		this.nameSpace = ns;
		this.target = props.getProperty("target");
		
		this.objectClass = props.getProperty("objectClass");
		
		String isusers = props.getProperty("users");
		this.users = isusers == null || isusers.equalsIgnoreCase("true");

		this.baseDN = new DN(ns.getBase().getDN().toString());

	}

	@Override
	public void add(AddInterceptorChain chain, Entry entry, LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Unsupported", LDAPException.UNWILLING_TO_PERFORM, LDAPException.resultCodeToString(LDAPException.UNWILLING_TO_PERFORM));

	}

	@Override
	public void bind(BindInterceptorChain chain, DistinguishedName dn, Password pwd, LDAPConstraints constraints)
			throws LDAPException {
		
		if (! this.users) {
			throw new LDAPException("Unsupported", LDAPException.UNWILLING_TO_PERFORM, LDAPException.resultCodeToString(LDAPException.UNWILLING_TO_PERFORM));
		}
		
		RDN rdn =(RDN)  dn.getDN().getRDNs().get(0);
		if (! rdn.getType().equalsIgnoreCase("login")) {
			throw new LDAPException("Unsupported", LDAPException.UNWILLING_TO_PERFORM, LDAPException.resultCodeToString(LDAPException.UNWILLING_TO_PERFORM));
		}
		
		String userid = rdn.getValue();
		
		userid = userid.replace("\\+", "+");
		
		OktaTarget os = null;
		try {
			os = (OktaTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.target).getProvider();
		} catch (ProvisioningException e1) {
			logger.error("Could not retrieve kubernetes target",e1);
			throw new LDAPException("Could not connect to kubernetes",LDAPException.OPERATIONS_ERROR,LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR));
		}
		
		
		
		
		
		
		
		
		
		
		String pwdStr = new String(pwd.getValue());
		LDAPException ldapRes;
		
		JSONObject authPayload = new JSONObject();
		authPayload.put("username", userid);
		authPayload.put("password", pwdStr);
		JSONObject options = new JSONObject();
		authPayload.put("options", options);
		options.put("multiOptionalFactorEnroll", false);
		options.put("warnBeforePasswordExpired", false);
		
		
		try {
			StringBuilder sb = new StringBuilder();
			sb.append(os.getDomain()).append("/api/v1/authn");
			HttpRequest request = HttpRequest.newBuilder(new URI(sb.toString()))
						.header("Accept","application/json")
						.header("Content-Type", "application/json")
						.POST(HttpRequest.BodyPublishers.ofString(authPayload.toString()))
						.build();
			
			HttpClient http = HttpClient.newBuilder().build();
			HttpResponse<String> resp = http.send(request, BodyHandlers.ofString());
			
			if (resp.statusCode() != 200) {
				if (resp.statusCode() == 401) {
					throw new LDAPException("Could not authenticate",LDAPException.INVALID_CREDENTIALS,LDAPException.resultCodeToString(LDAPException.INVALID_CREDENTIALS));
				} else {
					logger.error(String.format("Unexpected authenticaiton error %s/%s",resp.statusCode(),resp.body()));
					throw new LDAPException("Unexpected authentication error",LDAPException.OPERATIONS_ERROR,LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR));
				}
			}
		} catch (IOException | InterruptedException | URISyntaxException e) {
			logger.error("Unexpected authenticaiton error",e);
			throw new LDAPException("Unexpected authentication error",LDAPException.OPERATIONS_ERROR,LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR));
		}
		
		
		
		

	}

	@Override
	public void compare(CompareInterceptorChain chain, DistinguishedName dn, Attribute attrib,
			LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Unsupported", LDAPException.UNWILLING_TO_PERFORM, LDAPException.resultCodeToString(LDAPException.UNWILLING_TO_PERFORM));

	}

	@Override
	public void delete(DeleteInterceptorChain chain, DistinguishedName dn, LDAPConstraints constraints)
			throws LDAPException {
		throw new LDAPException("Unsupported", LDAPException.UNWILLING_TO_PERFORM, LDAPException.resultCodeToString(LDAPException.UNWILLING_TO_PERFORM));

	}

	@Override
	public void extendedOperation(ExetendedOperationInterceptorChain chain, ExtendedOperation op,
			LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Unsupported", LDAPException.UNWILLING_TO_PERFORM, LDAPException.resultCodeToString(LDAPException.UNWILLING_TO_PERFORM));

	}

	@Override
	public void modify(ModifyInterceptorChain chain, DistinguishedName dn, ArrayList<LDAPModification> mods,
			LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Unsupported", LDAPException.UNWILLING_TO_PERFORM, LDAPException.resultCodeToString(LDAPException.UNWILLING_TO_PERFORM));

	}

	@Override
	public void search(SearchInterceptorChain chain, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		
		OktaTarget os = null;
		try {
			os = (OktaTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.target).getProvider();
		} catch (ProvisioningException e1) {
			logger.error("Could not retrieve kubernetes target",e1);
			throw new LDAPException("Could not connect to kubernetes",LDAPException.OPERATIONS_ERROR,LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR));
		}

        //base search
        if (scope.getValue() == 0) {
            //  dir root
        	if (base.getDN().equals(this.baseDN)) {
        		ArrayList<Entry> ret = new ArrayList<Entry>();
        		ret.add(new Entry(EntryUtil.createBaseEntry(this.baseDN)));
        		chain.addResult(results, new IteratorEntrySet(ret.iterator()), base, scope, filter, attributes, typesOnly, constraints);
        		return;
        	} else {
        		if (this.users) {
        			String name = ((RDN)base.getDN().getRDNs().get(0)).getValue();
        			try {
        				loadUserFromOkta(chain, base, scope, filter, attributes, typesOnly, results, constraints, os, name,base.getDN().toString(),true);
        			} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
						throw new LDAPException("Could not load okta user",LDAPException.OPERATIONS_ERROR,LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),e);
					}
        		} else {
        			String name = ((RDN)base.getDN().getRDNs().get(0)).getValue();
        			
        			
        			
        			
        			ApiClient okta = os.getOkta();
        			
        			List<Group> groupList = null;
        			Group fromOkta = null;
        			
        			
        			try {
        				ArrayList<Entry> ret = new ArrayList<Entry>();
        				
        				
        				if (! loadGroupFromOkta(base, filter, name, okta, os.getGroupApi(),ret)) {
        					throw new LDAPException("group not found",LDAPException.NO_SUCH_OBJECT,LDAPException.resultCodeToString(LDAPException.NO_SUCH_OBJECT));
        				}
        				
        				
        				
        				
        				chain.addResult(results, new IteratorEntrySet(ret.iterator()), base, scope, filter, attributes, typesOnly, constraints);
        				
        				
        			} catch (ApiException e) {
        				if (e.getCode() == 404) {
        					throw new LDAPException("group not found",LDAPException.NO_SUCH_OBJECT,LDAPException.resultCodeToString(LDAPException.NO_SUCH_OBJECT));
        				} else {
        					throw new LDAPException("Could not load group",LDAPException.OPERATIONS_ERROR,LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),e);
        				}
        			} catch (UnsupportedEncodingException e) {
        				throw new LDAPException("Could not load group",LDAPException.OPERATIONS_ERROR,LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),e);
					} catch (IllegalStateException e) {
						throw new LDAPException("group not found",LDAPException.NO_SUCH_OBJECT,LDAPException.resultCodeToString(LDAPException.NO_SUCH_OBJECT));
					}
        		}
				return;
        		
        	}

            
        } /*else if (scope.getValue() == 1) {
        	if (base.getDN().equals(this.baseDN)) {
        		
        		if (this.users) {
	        		String name = userFromFilter(filter.getRoot());
	        		
	        		loadUserFromOkta(chain, base, scope, filter, attributes, typesOnly, results, constraints, os, name,new StringBuilder().append("login=").append(name).append(",").append(base.getDN().toString()).toString(),false);
        		}
        		
				return;
        	}
        }*/ else {
        	//only subtree left
        	//String name = userFromFilter(filter.getRoot());
    		
        	//loadUserFromOkta(chain, base, scope, filter, attributes, typesOnly, results, constraints, os, name,new StringBuilder().append("uid=").append(name).append(",").append(this.baseDN.toString()).toString(),false);
        	
        	ApiClient okta = os.getOkta();
        	
        	Filter newFilter = new Filter(filter.getRoot().toString());
        	String finalOktaFilter = null;
        	if (this.cleanFilter(newFilter.getRoot())) {
        		StringBuffer filterForOkta = new StringBuffer();
        		this.stringFilter(newFilter.getRoot(), filterForOkta);
        		finalOktaFilter = filterForOkta.toString();
        	}
        	
        	if (logger.isDebugEnabled()) {
        		logger.debug(newFilter.getRoot().toString());
        	}
        	
        	
        	
        	if (this.users) {
        	
	        	List<User> usersFromOkta = os.getUserApi().listUsers(null, null, null, finalOktaFilter,null, null, null); 
	        			
	        			
	        			//okta.listUsers(null, finalOktaFilter , null, null, null);
	        	StringBuilder sb = new StringBuilder();
	        	
	        	ArrayList<Entry> ret = new ArrayList<Entry>();
	    		
	        	
	        	for (User user : usersFromOkta) {
	        		if (logger.isDebugEnabled()) {
	        			logger.debug(user);
	        		}
	        		sb.setLength(0);
	        		
	        		
	        		
	        		sb.append("login=").append(user.getProfile().getLogin().replace("+","\\+")).append(",").append(this.baseDN.toString());
	        		LDAPEntry ldapUser;
					try {
						ldapUser = createLdapUser(sb.toString(), user,os);
						if (filter.getRoot().checkEntry(ldapUser)) {
		        			ret.add(new Entry(ldapUser));
		        		}
					} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
						throw new LDAPException("Could not load okta user",LDAPException.OPERATIONS_ERROR,LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),e);
					}
	        		
	        	}
	        	
	        	chain.addResult(results, new IteratorEntrySet(ret.iterator()), base, scope, filter, attributes, typesOnly, constraints);
        	} else {
        		
        		HashSet<String> groupsToLookup = new HashSet<String>();
        		HashSet<String> usersToLookup = new HashSet<String>();
        		loadGroups(filter.getRoot(),groupsToLookup,usersToLookup);
        		StringBuilder sb = new StringBuilder();
        		
        		HashSet<String> processedGroups = new HashSet<String>();
        		ArrayList<Entry> ret = new ArrayList<Entry>();
        		
        		if (usersToLookup.size() > 0) {
        			sb.setLength(0);
        			for (String username : usersToLookup) {
        				sb.append("profile.login eq \"").append(username).append("\" or ");
        			}
        			
        			String searchFilter = sb.toString();
        			searchFilter = searchFilter.substring(0, searchFilter.length() - 3);
        			
        			List<User> users = os.getUserApi().listUsers(null, null,null, searchFilter, null, null, null); 
        					
        					
        			for (User fromOkta : users) {
        				
        				List<Group> memberships = os.getUserApi().listUserGroups(fromOkta.getId());
        				
        				for (Group groupFromOkta : memberships) {
        					if (! processedGroups.contains(groupFromOkta.getProfile().getName())) {
        						try {
        		        			processedGroups.add(groupFromOkta.getProfile().getName());
        		    				sb.setLength(0);
        			        		
        			        		
        			        		
        			        		sb.append("name=").append(groupFromOkta.getProfile().getName().replace("+","\\+")).append(",").append(this.baseDN.toString());
        			        		LDAPEntry entry = new LDAPEntry(sb.toString());
        			        		try {
        								this.oktaGroup2Ldap(filter, ret, groupFromOkta, os.getGroupApi(), entry);
        							} catch (UnsupportedEncodingException e) {
        								throw new LDAPException("Could not load group",LDAPException.OPERATIONS_ERROR,LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),e);
        							}
        	        			} catch (IllegalStateException e) {
        	        				//no nothing
        	        			}
        					}
        				}
        			}
        		}
        		
        		
        		
        		if (groupsToLookup.size() > 0) {
        			
        			for (String group : groupsToLookup) {
        				
        				if (! processedGroups.contains(group)) {
        			
		        			List<Group> groups = os.getGroupApi().listGroups(group, null, null, null, null, null, null, null);
		        			
		        			processedGroups.add(group);
		        			try {
			        			if (groups.size() > 0) {
			        				Group groupFromOkta = groups.get(0);
				    				sb.setLength(0);
					        		
					        		
					        		
					        		sb.append("name=").append(groupFromOkta.getProfile().getName().replace("+","\\+")).append(",").append(this.baseDN.toString());
					        		LDAPEntry entry = new LDAPEntry(sb.toString());
					        		try {
										this.oktaGroup2Ldap(filter, ret, groupFromOkta,os.getGroupApi(), entry);
									} catch (UnsupportedEncodingException e) {
										throw new LDAPException("Could not load group",LDAPException.OPERATIONS_ERROR,LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),e);
									}
			        			}
		        			} catch (IllegalStateException e) {
		        				//no nothing
		        			}
        				}
        			}
        			
        			
        			
        		}
        		
        		if (usersToLookup.size() == 0 && groupsToLookup.size() == 0) {
        			List<Group> groups = os.getGroupApi().listGroups(null, null, null, null, null, null, null, null);
        			try {
	        			for (Group groupFromOkta : groups) {
		    				sb.setLength(0);
			        		
			        		
			        		
			        		sb.append("name=").append(groupFromOkta.getProfile().getName().replace("+","\\+")).append(",").append(this.baseDN.toString());
			        		LDAPEntry entry = new LDAPEntry(sb.toString());
			        		try {
								this.oktaGroup2Ldap(filter, ret, groupFromOkta,os.getGroupApi(), entry);
							} catch (UnsupportedEncodingException e) {
								throw new LDAPException("Could not load group",LDAPException.OPERATIONS_ERROR,LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),e);
							}
	        			}
        			} catch (IllegalStateException e) {
        				//no nothing
        			}
        		}
        		
        		chain.addResult(results, new IteratorEntrySet(ret.iterator()), base, scope, filter, attributes, typesOnly, constraints);
        		
        	}
			return;
        }

	}

	private void loadGroups(FilterNode root, HashSet<String> groupsToLookup,HashSet<String> usersToLookup) {
		switch (root.getType()) {
			case AND: 
			case OR: 
				for (FilterNode child : root.getChildren()) {
					loadGroups(child,groupsToLookup,usersToLookup);
				}
				break;
			case NOT:
				loadGroups(root.getNot(),groupsToLookup,usersToLookup); break;
			default:
				if (root.getName().equalsIgnoreCase("member")) {
					if (! usersToLookup.contains(root.getValue())) {
						usersToLookup.add(root.getValue());
					}
					
				} else if (root.getName().equalsIgnoreCase("name")) {
					if (! groupsToLookup.contains(root.getValue())) {
						groupsToLookup.add(root.getValue());
					}
				}
		}
		
	}

	private boolean loadGroupFromOkta(DistinguishedName base, Filter filter, String name, ApiClient okta,GroupApi groupApi,
			ArrayList<Entry> ret) throws UnsupportedEncodingException {
		List<Group> groupList;
		Group fromOkta;
		groupList = groupApi.listGroups(name, null, null, null, null, null, null, null);
		
		if (groupList.size() > 0) {
			fromOkta = groupList.get(0);
			
			LDAPEntry entry = new LDAPEntry(base.getDN().toString());
			oktaGroup2Ldap(filter, ret, fromOkta, groupApi, entry);
			return true;
		} else {
			return false;
		}
	}

	private void oktaGroup2Ldap(Filter filter, ArrayList<Entry> ret, Group fromOkta, GroupApi groupApi, LDAPEntry entry)
			throws UnsupportedEncodingException {
		entry.getAttributeSet().add(new LDAPAttribute("name",fromOkta.getProfile().getName()));
		String description = fromOkta.getProfile().getDescription();
		if (description != null) { 
			entry.getAttributeSet().add(new LDAPAttribute("description",description));
		}
		entry.getAttributeSet().add(new LDAPAttribute("objectClass",this.objectClass));
		
		LDAPAttribute members = new LDAPAttribute("member");
		
		
		
		List<User> users = groupApi.listGroupUsers(fromOkta.getId(),null, 100000);
		for (User user : users) {
			members.addValue(user.getProfile().getLogin().getBytes("UTF-8"));
		}
		
		if (members.size() > 0) {
			entry.getAttributeSet().add(members);
		}
		
		
		if (filter.getRoot().checkEntry(entry)) {
			ret.add(new Entry(entry));
		}
	}

	private void loadUserFromOkta(SearchInterceptorChain chain, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly, Results results, LDAPSearchConstraints constraints,
			OktaTarget os, String name, String entryDN, boolean b) throws LDAPException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		
		ApiClient okta = os.getOkta();
		
		User fromOkta = null;
		
		
		try {
			fromOkta = os.getUserApi().getUser(name);
			
		} catch (ApiException e) {
			if (e.getCode() == 404) {
				throw new LDAPException("user not found",LDAPException.NO_SUCH_OBJECT,LDAPException.resultCodeToString(LDAPException.NO_SUCH_OBJECT));
			} else {
				throw new LDAPException("Could not load user",LDAPException.OPERATIONS_ERROR,LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),e);
			}
		}
		
		LDAPEntry ldapUser = createLdapUser(entryDN, fromOkta, os);
		
		ArrayList<Entry> ret = new ArrayList<Entry>();
		ret.add(new Entry(ldapUser));
		chain.addResult(results, new IteratorEntrySet(ret.iterator()), base, scope, filter, attributes, typesOnly, constraints);
	}

	private LDAPEntry createLdapUser(String entryDN, User fromOkta,OktaTarget okta) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		LDAPEntry ldapUser = new LDAPEntry(entryDN);
		
		ldapUser.getAttributeSet().add(new LDAPAttribute("objectClass",this.objectClass));
		ldapUser.getAttributeSet().add(new LDAPAttribute("login",fromOkta.getProfile().getLogin()));
		ldapUser.getAttributeSet().add(new LDAPAttribute("id",fromOkta.getId()));
		
		
		Map<String,String> attrs = ObjUtils.props2map(fromOkta.getProfile());
		
		for (String attrName : attrs.keySet()) {
			if (attrs.get(attrName) != null) {
				ldapUser.getAttributeSet().add(new LDAPAttribute(attrName,attrs.get(attrName).toString()));
			}
		}
		
		LDAPAttribute groups = new LDAPAttribute("groups");
		
		List<Group> oktaGroups = okta.getUserApi().listUserGroups(fromOkta.getId());
		
		for (Group group : oktaGroups) {
			groups.addValue(group.getProfile().getName());
		}
		
		ldapUser.getAttributeSet().add(groups);
		return ldapUser;
	}

	@Override
	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Unsupported", LDAPException.UNWILLING_TO_PERFORM, LDAPException.resultCodeToString(LDAPException.UNWILLING_TO_PERFORM));

	}

	@Override
	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn,
			DistinguishedName newParentDN, Bool deleteOldRdn, LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Unsupported", LDAPException.UNWILLING_TO_PERFORM, LDAPException.resultCodeToString(LDAPException.UNWILLING_TO_PERFORM));

	}

	@Override
	public void postSearchEntry(PostSearchEntryInterceptorChain chain, Entry entry, DistinguishedName base, Int scope,
			Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	@Override
	public void postSearchComplete(PostSearchCompleteInterceptorChain chain, DistinguishedName base, Int scope,
			Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	@Override
	public void shutdown() {


	}
	
	private String userFromFilter(FilterNode node) {
		switch (node.getType()) {
			case EQUALS:
				if (node.getName().equalsIgnoreCase("login")) {
					return node.getValue();
				} 
				break;
			case AND:
			case OR:
				for (FilterNode kid : node.getChildren()) {
					String ret = userFromFilter(kid);
					if (ret != null) {
						return ret;
					}
				}
				break;
			case NOT:
				return userFromFilter(node.getNot());
			default:
				return null;
		}
		return null;
	}
	
	
	private String stringFilter(FilterNode root, StringBuffer filter) {
        FilterType op;
        //filter.append('(');
        String comp = null;
        ArrayList<FilterNode> children;
        Iterator<FilterNode> filterIt;
        String attribName = null;
        
        boolean isFirst = true;
        
        
                op = root.getType();
                switch (op){
                    case AND:
                    		
                    		HashMap<String,ArrayList<FilterNode>> attribs = new HashMap<String,ArrayList<FilterNode>>();
                    		//first sort the nodes into "buckets"
                    		children = root.getChildren();
                        filterIt = children.iterator();
                        while (filterIt.hasNext()) {
                        		FilterNode node = filterIt.next();
                        		if (node.getType() == FilterType.AND) {
                        			ArrayList<FilterNode> ands = attribs.get("&");
                        			if (ands == null) {
                        				ands = new ArrayList<FilterNode>();
                        				attribs.put("&",ands);
                        			}
                        			ands.add(node);
                        		} else if (node.getType() == FilterType.OR) {
                        			ArrayList<FilterNode> ors = attribs.get("|");
                        			if (ors == null) {
                        				ors = new ArrayList<FilterNode>();
                        				attribs.put("|",ors);
                        			}
                        			ors.add(node);
                        		} else if (node.getType() == FilterType.NOT) {
                        			ArrayList<FilterNode> nots = attribs.get("!");
                        			if (nots == null) {
                        				nots = new ArrayList<FilterNode>();
                        				attribs.put("!",nots);
                        			}
                        			nots.add(node);
                        		} else {
                        			
                        			ArrayList<FilterNode> attribNodes = attribs.get(node.getName());
                        			if (attribNodes == null) {
                        				attribNodes = new ArrayList<FilterNode>();
                        				attribs.put(node.getName(),attribNodes);
                        			}
                        			attribNodes.add(node);
                        		}
                        }
                        
                        filter.append(" ( ");
                    		
                        Iterator<String> itBuckets = attribs.keySet().iterator();
                        while (itBuckets.hasNext()) {
                        		String attrib = itBuckets.next();
                        		ArrayList<FilterNode> nodes = attribs.get(attrib);
                        		if (attrib.equals("&")) {
                        			Iterator<FilterNode> itNodes = nodes.iterator();
                        			filter.append(" ( ");
                        			while (itNodes.hasNext()) {
                        				stringFilter(itNodes.next(),filter);
                        				if (itNodes.hasNext()) {
                        					filter.append(" and ");
                        				}
                        			}
                        			
                        			
                        			filter.append(" ) ");
                        			
                        			if (itBuckets.hasNext()) {
                        				filter.append(" and ");
                        			}
                        		} else if (attrib.equals("|")) {
                        			Iterator<FilterNode> itNodes = nodes.iterator();
                        			filter.append(" ( ");
                        			while (itNodes.hasNext()) {
                        				stringFilter(itNodes.next(),filter);
                        				if (itNodes.hasNext()) {
                        					filter.append(" and ");
                        				}
                        			}
                        			filter.append(" ) ");
                        			
                        			if (itBuckets.hasNext()) {
                        				filter.append(" and ");
                        			}
                        		} else if (attrib.equals("!")) {
                        			Iterator<FilterNode> itNodes = nodes.iterator();
                        			filter.append(" ( ");
                        			while (itNodes.hasNext()) {
                        				stringFilter(itNodes.next(),filter);
                        				if (itNodes.hasNext()) {
                        					filter.append(" and ");
                        				}
                        			}
                        			filter.append(" ) ");
                        			
                        			if (itBuckets.hasNext()) {
                        				filter.append(" and ");
                        			}
                        		} else {
                        			Iterator<FilterNode> itNodes = nodes.iterator();
                        			filter.append(" ( ");
                        			while (itNodes.hasNext()) {
                        				stringFilter(itNodes.next(),filter);
                        				if (itNodes.hasNext()) {
                        					filter.append(" or ");
                        				}
                        			}
                        			filter.append(" ) ");
                        			
                        			if (itBuckets.hasNext()) {
                        				filter.append(" and ");
                        			}
                        		}
                        }
                        
                        filter.append(" ) ");
                    		
                        
                        
                        break;
                    case OR:
                    		filter.append(" ( ");
                        
                        children = root.getChildren();
                        filterIt = children.iterator();
                        while (filterIt.hasNext()) {
                        		stringFilter(filterIt.next(),filter);
                        		if (filterIt.hasNext()) {
                        			filter.append(" or ");
                        		}
                        }
                        filter.append(" ) ");
                        break;
                        
                    case NOT:
                        filter.append(" NOT ( ");
                        stringFilter(root.getNot(),filter);
                        filter.append(" ) ");
                        
                        break;
                    case EQUALS:{
                    		if (root.getName().equalsIgnoreCase("objectclass")) {
                    			filter.append(" profile.displayName pr ");
                    		} else {
		                        attribName = root.getName();
		                        
		                        if (attribName == null) {
		                        	filter.append(" 1 = 0 ");
		                        } else {
		                        
		                    		filter.append("profile.")
		                    		      .append(attribName)
		                    			  .append(" eq \"")
		                    			  .append(root.getValue())
		                    			  .append("\" ");
		                        
		                    		
		                        }
                    		}
                        
                        
                        
                        break;
                    }
                    case GREATER_THEN:{
                    		attribName = root.getName();
                    		filter.append("profile.")
              		      		  .append(attribName)
		              			  .append(" gt \"")
		              			  .append(root.getValue())
		              			  .append("\" ");
                        break;
                    }
                    case LESS_THEN:{
                    		attribName = root.getName();
                    		filter.append("profile.")
        		      		  	  .append(attribName)
		              			  .append(" lt \"")
		              			  .append(root.getValue())
		              			  .append("\" ");
                        break;
                        
                        
                    }
                    case PRESENCE:
                    		if (root.getName().equalsIgnoreCase("objectclass")) {
                    			filter.append(" 1=1 ");
                    		} else {
                    			filter.append("profile.")
            		      		      .append(attribName)
		                  			  .append(" pr ");
                    		}
                        break;
                    /*case APPROX_MATCH:
                        filter.append((String)itr.next());
                        filter.append("~=");
                        byte[] value = (byte[])itr.next();
                        filter.append(byteString(value));
                        
                        if (comp != null && itr.hasNext()) {
                        	filter.append(comp);
                        }
                        
                        break;
                    case LDAPSearchRequest.EXTENSIBLE_MATCH:
                        String oid = (String)itr.next();

                        filter.append((String)itr.next());
                        filter.append(':');
                        filter.append(oid);
                        filter.append(":=");
                        filter.append((String)itr.next());
                        
                        if (comp != null && itr.hasNext()) {
                        	filter.append(comp);
                        }
                        
                        break;*/
                    case SUBSTR:{
                    		attribName = root.getName();
                    		filter.append(attribName);
                        filter.append(" LIKE '");
                        boolean noStarLast = false;
                        
                        filter.append(root.getValue().replace('*','%')).append('\'');
                        
                        break;
                    }
                }
            
        
        
        
        
        if (comp != null) {
        	filter.append(')');
        }
        
        return attribName;
    }
	
	
	private boolean cleanFilter(FilterNode root) {
        FilterType op;
        //filter.append('(');
        String comp = null;
        ArrayList<FilterNode> children;
        Iterator<FilterNode> filterIt;
        String attribName = null;
        
        boolean isFirst = true;
        
        
                op = root.getType();
                switch (op){
                    case AND:
                    case OR:
                    		ArrayList<FilterNode> toRemove = new ArrayList<FilterNode>();
                    	
                    		children = root.getChildren();
                    		for (FilterNode node : children) {
                    			if (! cleanFilter(node)) {
                    				toRemove.add(node);
                    			}
                    		}
                    		
                    		if (! toRemove.isEmpty()) {
                    			children.removeAll(toRemove);
                    		}
                    		
                    		return ! children.isEmpty();
                        
                        
                    		
                        
                        
                        
                    
                    		
                                                
                       
                        
                    case NOT:
                        
                    	return cleanFilter(root.getNot());
                        
                        
                        
                    case EQUALS:{
                    		if (root.getName().equalsIgnoreCase("objectclass")) {
                    			return false;
                    		} 
                        
                        
                        
                        break;
                    }
                    
                    case PRESENCE:
                    	//presence search seems broken in okta,skip it
                    	return false;
                        
                    
                }
            
        
        
        return true;
        
        
    }
	
	

}

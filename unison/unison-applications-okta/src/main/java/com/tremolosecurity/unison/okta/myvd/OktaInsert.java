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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;

import org.apache.logging.log4j.Logger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;
import com.okta.sdk.client.Client;
import com.okta.sdk.resource.ResourceException;
import com.okta.sdk.resource.group.Group;
import com.okta.sdk.resource.user.User;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.okta.provisioning.OktaTarget;


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
	

	DN baseDN;
	
	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public void configure(String name, Properties props, NameSpace ns) throws LDAPException {
		this.name = name;
		this.nameSpace = ns;
		this.target = props.getProperty("target");
		

		this.baseDN = new DN(ns.getBase().getDN().toString());

	}

	@Override
	public void add(AddInterceptorChain chain, Entry entry, LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Unsupported", LDAPException.UNWILLING_TO_PERFORM, LDAPException.resultCodeToString(LDAPException.UNWILLING_TO_PERFORM));

	}

	@Override
	public void bind(BindInterceptorChain chain, DistinguishedName dn, Password pwd, LDAPConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	@Override
	public void compare(CompareInterceptorChain chain, DistinguishedName dn, Attribute attrib,
			LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

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
        		String name = ((RDN)base.getDN().getRDNs().get(0)).getValue();
        		loadUserFromOkta(chain, base, scope, filter, attributes, typesOnly, results, constraints, os, name,base.getDN().toString(),true);
				return;
        		
        	}

            
        } else if (scope.getValue() == 1) {
        	if (base.getDN().equals(this.baseDN)) {
        		String name = userFromFilter(filter.getRoot());
        		
        		loadUserFromOkta(chain, base, scope, filter, attributes, typesOnly, results, constraints, os, name,new StringBuilder().append("uid=").append(name).append(",").append(base.getDN().toString()).toString(),false);
				return;
        	}
        } else {
        	//only subtree left
        	String name = userFromFilter(filter.getRoot());
    		
        	loadUserFromOkta(chain, base, scope, filter, attributes, typesOnly, results, constraints, os, name,new StringBuilder().append("uid=").append(name).append(",").append(this.baseDN.toString()).toString(),false);
			return;
        }

	}

	private void loadUserFromOkta(SearchInterceptorChain chain, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly, Results results, LDAPSearchConstraints constraints,
			OktaTarget os, String name, String entryDN, boolean b) throws LDAPException {
		
		Client okta = os.getOkta();
		
		User fromOkta = null;
		
		
		try {
			fromOkta = okta.getUser(name);
		} catch (ResourceException e) {
			if (e.getStatus() == 404) {
				throw new LDAPException("user not found",LDAPException.NO_SUCH_OBJECT,LDAPException.resultCodeToString(LDAPException.NO_SUCH_OBJECT));
			} else {
				throw new LDAPException("Could not load user",LDAPException.OPERATIONS_ERROR,LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),e);
			}
		}
		
		LDAPEntry ldapUser = new LDAPEntry(entryDN);
		
		ldapUser.getAttributeSet().add(new LDAPAttribute("objectClass",GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getUserObjectClass()));
		ldapUser.getAttributeSet().add(new LDAPAttribute("uid",fromOkta.getProfile().getLogin()));
		
		for (String attrName : fromOkta.getProfile().keySet()) {
			if (fromOkta.getProfile().get(attrName) != null) {
				ldapUser.getAttributeSet().add(new LDAPAttribute(attrName,fromOkta.getProfile().get(attrName).toString()));
			}
		}
		
		LDAPAttribute groups = new LDAPAttribute("groups");
		
		for (Group group : fromOkta.listGroups()) {
			groups.addValue(group.getProfile().getName());
		}
		
		ldapUser.getAttributeSet().add(groups);
		
		ArrayList<Entry> ret = new ArrayList<Entry>();
		ret.add(new Entry(ldapUser));
		chain.addResult(results, new IteratorEntrySet(ret.iterator()), base, scope, filter, attributes, typesOnly, constraints);
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
				if (node.getName().equalsIgnoreCase("uid")) {
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

}

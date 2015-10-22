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


package com.tremolosecurity.proxy.myvd.inserts.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;

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
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;

public class CreateUPN implements Insert {

	String name;
	String prefixAttrName;
	String suffix;
	
	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		this.name = name;
		this.prefixAttrName = props.getProperty("prefixAttributeName");
		this.suffix = props.getProperty("suffix");

	}

	@Override
	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextAdd(entry, constraints);

	}

	@Override
	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		chain.nextBind(dn, pwd, constraints);

	}

	@Override
	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		chain.nextCompare(dn, attrib, constraints);

	}

	@Override
	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextDelete(dn, constraints);

	}

	@Override
	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextExtendedOperations(op, constraints);

	}

	@Override
	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextModify(dn, mods, constraints);

	}

	@Override
	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		
		boolean upnNeeded = false;
		boolean requestPrefixAttr = false;
		
		if (attributes.size() == 0) {
			upnNeeded = true;
			
		} else {
			for (Attribute attr : attributes) {
				if (attr.getAttribute().getName().equalsIgnoreCase("*")) {
					upnNeeded = true;
					
					break;
				} else if (attr.getAttribute().getName().equalsIgnoreCase("userprincipalname")) {
					upnNeeded = true;
					requestPrefixAttr = true;
					break;
				}
			}
		}
		
		ArrayList<Attribute> nattrs = new ArrayList<Attribute>(attributes);
		
		if (requestPrefixAttr) {
			nattrs.add(new Attribute(this.prefixAttrName));
		}
		
		chain.getRequest().put("CREATEUPN_NEEDUPN", upnNeeded);
		
		Filter nfilter = null;
		
		try {
			FilterNode nroot = (FilterNode) filter.getRoot().clone();
			nfilter = new Filter(nroot);
		} catch (CloneNotSupportedException e) {
			throw new LDAPException("Could not clone filter",LDAPException.OPERATIONS_ERROR,"Could not clone filter",e);
		}
		
		this.toUID(nfilter.getRoot());
		
		chain.nextSearch(base, scope, nfilter, nattrs, typesOnly, results, constraints);

	}

	@Override
	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn, newRdn, deleteOldRdn, constraints);

	}

	@Override
	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextRename(dn, newRdn, newParentDN, deleteOldRdn, constraints);

	}

	@Override
	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		
		chain.nextPostSearchEntry(entry, base, scope, filter, attributes, typesOnly, constraints);
		
		boolean needUPN = (Boolean) chain.getRequest().get("CREATEUPN_NEEDUPN");
		
		
		
		if (needUPN) {
			LDAPAttribute upn = entry.getEntry().getAttribute("userprincipalname");
			if (upn == null) {
				LDAPAttribute prefixAttr = entry.getEntry().getAttribute(this.prefixAttrName);
				if (prefixAttr != null) {
					StringBuffer sb = new StringBuffer();
					sb.append(prefixAttr.getStringValue()).append('@').append(this.suffix);
					entry.getEntry().getAttributeSet().add(new LDAPAttribute("userPrincipalName",sb.toString()));
				}
			}
		}

	}

	@Override
	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		
		chain.nextPostSearchComplete(base, scope, filter, attributes, typesOnly, constraints);

	}

	@Override
	public void shutdown() {
		// TODO Auto-generated method stub

	}
	
	private void toUID(FilterNode node) {
		String name;
		String newVal;
		HashMap<String,String> map;
		switch (node.getType()) {
			 
			case EQUALS 	  :  name = node.getName().toLowerCase();
			if (name.equalsIgnoreCase("userprincipalname")) {
				String val = node.getValue();
				if (val.indexOf('@') > 0) {
					String upnSuffix = val.substring(val.indexOf('@') + 1);
					if (upnSuffix.equalsIgnoreCase(this.suffix)) {
						node.setValue(val.substring(0,val.indexOf('@')));
						node.setName("uid");
					}
				}
			}
			break;
			case SUBSTR	:
			case GREATER_THEN :
			case LESS_THEN:
			case PRESENCE : break;
			case AND:
			case OR:
							Iterator<FilterNode> it = node.getChildren().iterator();
							while (it.hasNext()) {
								toUID(it.next());
							}
							break;
			case NOT :		toUID(node.getNot());
		}
		
		
	}

}

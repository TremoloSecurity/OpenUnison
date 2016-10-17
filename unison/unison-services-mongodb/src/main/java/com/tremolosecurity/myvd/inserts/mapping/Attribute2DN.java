/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
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
package com.tremolosecurity.myvd.inserts.mapping;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Properties;

import org.apache.logging.log4j.Logger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;


import net.sourceforge.myvd.chain.AddInterceptorChain;
import net.sourceforge.myvd.chain.BindInterceptorChain;
import net.sourceforge.myvd.chain.CompareInterceptorChain;
import net.sourceforge.myvd.chain.DeleteInterceptorChain;
import net.sourceforge.myvd.chain.ExetendedOperationInterceptorChain;
import net.sourceforge.myvd.chain.InterceptorChain;
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

public class Attribute2DN implements Insert {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(Attribute2DN.class.getName());
	
	String attributeName;
	
	
	HashMap<String,String> dn2attr;
	HashMap<String,String> attr2dn;
	String searchBase;
	String name;
	NameSpace nameSpace;
	String searchAttribute;
	
	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public void configure(String name, Properties props, NameSpace nameSpace) throws LDAPException {
		this.dn2attr = new HashMap<String,String>();
		this.attr2dn =  new HashMap<String,String>();
		
		this.name = name;
		this.searchBase = props.getProperty("searchBase");
		this.attributeName = props.getProperty("attributeName");
		this.searchAttribute = props.getProperty("searchAttribute");
		this.nameSpace = nameSpace;
		
	}

	@Override
	public void add(AddInterceptorChain chain, Entry entry, LDAPConstraints constraints) throws LDAPException {
		//TODO we should support add
		chain.nextAdd(entry, constraints);

	}

	@Override
	public void bind(BindInterceptorChain chain, DistinguishedName dn, Password pwd, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextBind(dn, pwd, constraints);

	}

	@Override
	public void compare(CompareInterceptorChain chain, DistinguishedName dn, Attribute attrib,
			LDAPConstraints constraints) throws LDAPException {
		//TODO should support
		chain.nextCompare(dn, attrib, constraints);

	}

	@Override
	public void delete(DeleteInterceptorChain chain, DistinguishedName dn, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextDelete(dn, constraints);

	}

	@Override
	public void extendedOperation(ExetendedOperationInterceptorChain chain, ExtendedOperation op,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextExtendedOperations(op, constraints);

	}

	@Override
	public void modify(ModifyInterceptorChain chain, DistinguishedName dn, ArrayList<LDAPModification> mods,
			LDAPConstraints constraints) throws LDAPException {
		//TODO support
		chain.nextModify(dn, mods, constraints);

	}

	@Override
	public void search(SearchInterceptorChain chain, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly, Results results, LDAPSearchConstraints constraints)
					throws LDAPException {
		
		
		Filter newfilter = new Filter(filter.getRoot().toString());
		this.mapFilter(newfilter.getRoot(), chain);
		chain.nextSearch(base, scope, newfilter, attributes, typesOnly, results, constraints);

	}

	@Override
	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn, newRdn, deleteOldRdn, constraints);

	}

	@Override
	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn,
			DistinguishedName newParentDN, Bool deleteOldRdn, LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn, newRdn, newParentDN, deleteOldRdn, constraints);

	}

	@Override
	public void postSearchEntry(PostSearchEntryInterceptorChain chain, Entry entry, DistinguishedName base, Int scope,
			Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints)
					throws LDAPException {
		
		chain.nextPostSearchEntry(entry, base, scope, filter, attributes, typesOnly, constraints);
		
		LDAPAttribute attr = entry.getEntry().getAttribute(this.attributeName);
		if (attr != null) {
			LDAPAttribute nattr = new LDAPAttribute(this.attributeName);
			String[] vals = attr.getStringValueArray();
			for (String val : vals) {
				nattr.addValue(this.attr2dn(val,chain));
			}
			entry.getEntry().getAttributeSet().remove(this.attributeName);
			entry.getEntry().getAttributeSet().add(nattr);
		}

	}

	@Override
	public void postSearchComplete(PostSearchCompleteInterceptorChain chain, DistinguishedName base, Int scope,
			Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints)
					throws LDAPException {
		chain.nextPostSearchComplete(base, scope, filter, attributes, typesOnly, constraints);

	}

	@Override
	public void shutdown() {
		

	}
	
	private void mapFilter(FilterNode node,InterceptorChain chain) throws LDAPException {
		switch (node.getType()) {
			case EQUALS :
			case GREATER_THEN:
			case LESS_THEN:
				if (node.getName().equalsIgnoreCase(this.attributeName)) {
					String val = this.dn2attr(node.getValue(),chain);
					if (val != null) {
						node.setValue(val);
					}
				}
				break;
			case PRESENCE:
			case SUBSTR:
				//do nothing
				break;
			case AND:
			case OR:
				for (FilterNode child : node.getChildren()) {
					mapFilter(child,chain);
				}
				break;
			case NOT: mapFilter(node.getNot(),chain);
			
		}
	}
	
	private String dn2attr(String dn,InterceptorChain chain) throws LDAPException {
		String dnlcase = dn.toLowerCase();
		String attr = this.dn2attr.get(dnlcase);
		
		if (attr != null) {
			return attr;
		} else {
			Filter filter = new Filter("(objectClass=*)");
		
			
			
			Results results = new Results(this.nameSpace.getRouter().getGlobalChain(),0);
			SearchInterceptorChain schain = new SearchInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,this.nameSpace.getRouter().getGlobalChain(),chain.getSession(),chain.getRequest(),this.nameSpace.getRouter());
			
			
			ArrayList<Attribute> attributes = new ArrayList<Attribute>();
			attributes.add(new Attribute(this.searchAttribute));
			
			
			schain.nextSearch(new DistinguishedName(dn), new Int(0), filter, attributes, new Bool(false), results, new LDAPSearchConstraints());
			
			results.start();
			
			if (! results.hasMore()) {
				logger.warn("DN does not exist : " + dn);
				results.finish();
				return null;
			} else {
				Entry entry = results.next();
				LDAPAttribute valAttr = entry.getEntry().getAttribute(this.searchAttribute);
				
				if (valAttr == null) {
					logger.warn("Attribute " + this.searchAttribute + " does not exist");
					results.finish();
					return null;
				} else {
					this.dn2attr.put(dnlcase, valAttr.getStringValue());
					results.finish();
					return valAttr.getStringValue();
				}
			}
			
		}
	}
	
	private String attr2dn(String attr,InterceptorChain chain) throws LDAPException {
		String attrlcase = attr.toLowerCase();
		String dn = this.attr2dn.get(attrlcase);
		
		if (dn != null) {
			return dn;
		} else {
			Filter filter = new Filter(equal(this.searchAttribute,attr).toString());
			
			
			Results results = new Results(this.nameSpace.getRouter().getGlobalChain(),0);
			SearchInterceptorChain schain = new SearchInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,this.nameSpace.getRouter().getGlobalChain(),chain.getSession(),chain.getRequest(),this.nameSpace.getRouter());
			
			ArrayList<Attribute> attributes = new ArrayList<Attribute>();
			attributes.add(new Attribute(this.searchAttribute));
			
			
			schain.nextSearch(new DistinguishedName(this.searchBase), new Int(2), filter, attributes, new Bool(false), results, new LDAPSearchConstraints());
			
			results.start();
			
			if (! results.hasMore()) {
				logger.warn("Entry does not exist for : " + attr);
				results.finish();
				return null;
			} else {
				Entry entry = results.next();
				
				this.attr2dn.put(attrlcase, entry.getEntry().getDN());
				results.finish();
				return entry.getEntry().getDN();
				
			}
			
		}
	}

}

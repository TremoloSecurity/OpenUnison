/*******************************************************************************
 * Copyright 2016, 2017 Tremolo Security, Inc.
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
package com.tremolosecurity.proxy.myvd.inserts;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import org.apache.log4j.Logger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.server.GlobalEntries;

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
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;

public class AddAttributesFromProvisioningTarget implements Insert {

	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(AddAttributesFromProvisioningTarget.class.getName());
	
	String name;
	
	String targetName;
	String uidAttribute;
	Set<String> attributes;
	
	public String getName() {
		return this.name;
	}

	public void configure(String name, Properties props, NameSpace nameSpace) throws LDAPException {
		this.name = name;
		String attributeNames = props.getProperty("attributeNames");
		
		attributes = new HashSet<String>();
		
		String attrs[] = attributeNames.split("[,]");
		for (String attrName : attrs) {
			this.attributes.add(attrName);
		}
		
		
		logger.info("For '" + name + "' - attributeNames='" + attributeNames + "'");

		this.targetName = props.getProperty("targetName");
		logger.info("For '" + name + "' - targetName='" + targetName + "'");
		
		this.uidAttribute = props.getProperty("uidAttribute");
		logger.info("For '" + name + "' - uidAttribute='" + uidAttribute + "'");
		
		

	}

	public void add(AddInterceptorChain chain, Entry entry, LDAPConstraints constraints) throws LDAPException {
		chain.nextAdd(entry, constraints);

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn, Password pwd, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextBind(dn, pwd, constraints);

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn, Attribute attrib,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextCompare(dn, attrib, constraints);

	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextDelete(dn, constraints);

	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain, ExtendedOperation op,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextExtendedOperations(op, constraints);

	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn, ArrayList<LDAPModification> mods,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextModify(dn, mods, constraints);

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly, Results results, LDAPSearchConstraints constraints)
					throws LDAPException {
		
		boolean hasAttribute = attributes.size() == 0 || (attributes.size() == 1 && attributes.get(0).getAttribute().getName().equalsIgnoreCase("*"));
		if (! hasAttribute) {
			for (Attribute attr : attributes) {
				if (attr.getAttribute().getName().equalsIgnoreCase(this.uidAttribute)) {
					hasAttribute = true;
				}
			}
		}
		
		if (! hasAttribute) {
			Attribute attr = new Attribute(this.uidAttribute);
			ArrayList<Attribute> nattrs = new ArrayList<Attribute>();
			nattrs.add(attr);
			nattrs.addAll(attributes);
			attributes = nattrs;
		}
		
		chain.nextSearch(base, scope, filter, attributes, typesOnly, results, constraints);

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn, newRdn, deleteOldRdn, constraints);

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn,
			DistinguishedName newParentDN, Bool deleteOldRdn, LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn, newRdn, newParentDN, deleteOldRdn, constraints);

	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain, Entry entry, DistinguishedName base, Int scope,
			Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints)
					throws LDAPException {
		chain.nextPostSearchEntry(entry, base, scope, filter, attributes, typesOnly, constraints);
		
		if (logger.isDebugEnabled()) {
				logger.debug("in post search entry");
		}

	
		
		
		
		
		//LDAPAttribute attr = new LDAPAttribute(this.attributeName);
		try {
			
			StringBuffer b = new StringBuffer();
			LDAPAttribute userID = entry.getEntry().getAttribute(this.uidAttribute);
			if (logger.isDebugEnabled()) {
				logger.debug("Looking up user : '" + userID + "'");
			}
			
			if (userID != null) {
			
				User user = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(targetName).findUser(userID.getStringValue(),new HashMap<String,Object>());
				if (logger.isDebugEnabled()) {
					logger.debug("User returned : '" + user + "'");
				}
				
				if (user != null) {
					for (String attributeName : this.attributes) {
						
						LDAPAttribute attr = entry.getEntry().getAttributeSet().getAttribute(attributeName);
						if (attr == null) {
							attr = new LDAPAttribute(attributeName);
							entry.getEntry().getAttributeSet().add(attr);
						}
						
						
						com.tremolosecurity.saml.Attribute targetAttr = user.getAttribs().get(attributeName);
						if (targetAttr != null) {
							for (String val : targetAttr.getValues()) {		
								attr.addValue(val);
							}
						}
						
					}
					
				}
			}
			
			
			
		} catch (Throwable t) {
			logger.warn("Could not load user : '" + t.getMessage() + "'");
			if (logger.isDebugEnabled()) {
				logger.debug(t);
			}
			
		}
		

	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain, DistinguishedName base, Int scope,
			Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints)
					throws LDAPException {
		chain.nextPostSearchComplete(base, scope, filter, attributes, typesOnly, constraints);

	}

	public void shutdown() {
		//nothing to stop

	}

}

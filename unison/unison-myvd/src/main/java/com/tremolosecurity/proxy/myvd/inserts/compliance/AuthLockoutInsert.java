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
package com.tremolosecurity.proxy.myvd.inserts.compliance;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Properties;

import jakarta.servlet.ServletException;

import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningParams;
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

public class AuthLockoutInsert implements Insert {

	static transient Logger logger = org.apache.logging.log4j.LogManager.getLogger(AuthLockoutInsert.class.getName());
	
	String name;
	
	int maxFailedAttempts;
	long maxLockoutTime;
	String numFailedAttribute;
	String lastFailedAttribute;
	String lastSucceedAttribute;
	String updateAttributesWorkflow;
	String uidAttributeName;
	
	
	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public void configure(String name, Properties props, NameSpace nameSpace) throws LDAPException {
		this.name = name;
		this.maxFailedAttempts = Integer.parseInt(props.getProperty("maxFailedAttempts","0"));
		this.maxLockoutTime = Long.parseLong(props.getProperty("maxLockoutTime", "0"));
		this.lastFailedAttribute = props.getProperty("lastFailedAttribute");
		this.lastSucceedAttribute = props.getProperty("lastSucceedAttribute");
		this.updateAttributesWorkflow = props.getProperty("updateAttributesWorkflow");
		this.uidAttributeName = props.getProperty("uidAttributeName");
		this.numFailedAttribute = props.getProperty("numFailedAttribute");
	}

	@Override
	public void add(AddInterceptorChain chain, Entry entry, LDAPConstraints constraints) throws LDAPException {
		chain.nextAdd(entry, constraints);

	}

	
	private void updateFailedAttrs(LDAPEntry entry) throws LDAPException {
		LDAPAttribute numFails = entry.getAttribute(this.numFailedAttribute);
		
		int fails = 0;
		if (numFails != null) {
			fails = Integer.parseInt(numFails.getStringValue());
		}
		fails++;
		String uid = entry.getAttribute(this.uidAttributeName).getStringValue();
		User updateAttrs = new User(uid);
		updateAttrs.getAttribs().put(this.lastFailedAttribute, new com.tremolosecurity.saml.Attribute(this.lastFailedAttribute,Long.toString(new DateTime(DateTimeZone.UTC).getMillis())));
		updateAttrs.getAttribs().put(this.numFailedAttribute, new com.tremolosecurity.saml.Attribute(this.numFailedAttribute,Integer.toString(fails)));
		updateAttrs.getAttribs().put(this.uidAttributeName, new com.tremolosecurity.saml.Attribute(this.uidAttributeName,uid));
		
		HashMap<String,Object> wfReq = new HashMap<String,Object>();
		wfReq.put(ProvisioningParams.UNISON_EXEC_TYPE, ProvisioningParams.UNISON_EXEC_SYNC);
		
		
		try {
			GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getWorkFlow(this.updateAttributesWorkflow).executeWorkflow(updateAttrs, wfReq);
		} catch (ProvisioningException e) {
			throw new LDAPException("Could not update compliance attribute",LDAPException.OPERATIONS_ERROR,"Operations Error",e);
		}
	}
	
	private void updateSuccessAttrs(LDAPEntry entry) throws LDAPException {
		int fails = 0;
		
		String uid = entry.getAttribute(this.uidAttributeName).getStringValue();
		User updateAttrs = new User(uid);
		updateAttrs.getAttribs().put(this.lastSucceedAttribute, new com.tremolosecurity.saml.Attribute(this.lastSucceedAttribute,Long.toString(new DateTime(DateTimeZone.UTC).getMillis())));
		updateAttrs.getAttribs().put(this.numFailedAttribute, new com.tremolosecurity.saml.Attribute(this.numFailedAttribute,Integer.toString(fails)));
		updateAttrs.getAttribs().put(this.uidAttributeName, new com.tremolosecurity.saml.Attribute(this.uidAttributeName,uid));
		
		HashMap<String,Object> wfReq = new HashMap<String,Object>();
		wfReq.put(ProvisioningParams.UNISON_EXEC_TYPE, ProvisioningParams.UNISON_EXEC_SYNC);
		
		
		try {
			GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getWorkFlow(this.updateAttributesWorkflow).executeWorkflow(updateAttrs, wfReq);
		} catch (ProvisioningException e) {
			throw new LDAPException("Could not update compliance attribute",LDAPException.OPERATIONS_ERROR,"Operations Error",e);
		}
	}
	
	@Override
	public void bind(BindInterceptorChain chain, DistinguishedName dn, Password pwd, LDAPConstraints constraints)
			throws LDAPException {
		
		Results results = new Results(null,chain.getPositionInChain(this) + 1);
		SearchInterceptorChain schain = chain.createSearchChain(chain.getPositionInChain(this) + 1);
		schain.nextSearch(new DistinguishedName(dn.getDN()), new Int(0), new Filter("(objectClass=*)"), new ArrayList<Attribute>(), new Bool(false), results, new LDAPSearchConstraints());
		results.start();
		
		if (! results.hasMore()) {
			throw new LDAPException("No such object",LDAPException.NO_SUCH_OBJECT,"Could not find dn");
		}
		
		Entry entry = results.next();
		
		while (results.hasMore()) {
			results.next();
		}
		
		try {
			chain.nextBind(dn, pwd, constraints);
			LDAPAttribute lastFailed = entry.getEntry().getAttributeSet().getAttribute(this.lastFailedAttribute);
			
			
			
			LDAPAttribute numFailures = entry.getEntry().getAttributeSet().getAttribute(this.numFailedAttribute);
			
			if (lastFailed != null && numFailures != null) {
				long lastFailedTS = Long.parseLong(lastFailed.getStringValue());
				int numPrevFailures = Integer.parseInt(numFailures.getStringValue());
				long now = new DateTime(DateTimeZone.UTC).getMillis();
				long lockedUntil = lastFailedTS + this.maxLockoutTime;
				
				if (logger.isDebugEnabled()) {
					logger.debug("Num Failed : " + numPrevFailures);
					logger.debug("Last Failed : '" + lastFailedTS + "'");
					logger.info("Now : '" + now + "'");
					logger.info("Locked Until : '" + lockedUntil + "'");
					logger.info("locked >= now? : '" + (lockedUntil >= now) + "'");
					logger.info("max fails? : '" + this.maxFailedAttempts + "'");
					logger.info("too many fails : '" + (numPrevFailures >= this.maxFailedAttempts) + "'");
				}
				
				
				
				if (lockedUntil >= now && numPrevFailures >= this.maxFailedAttempts) {
					this.updateFailedAttrs(entry.getEntry());
					throw new LDAPException("Invalid credentials",LDAPException.INVALID_CREDENTIALS,"User locked out");
				}
			}
			
			this.updateSuccessAttrs(entry.getEntry());
			
		} catch (LDAPException e) {
			if (e.getResultCode() == LDAPException.INVALID_CREDENTIALS) {
				this.updateFailedAttrs(entry.getEntry());
				
			} 
			throw e;
			
		}

	}

	@Override
	public void compare(CompareInterceptorChain chain, DistinguishedName dn, Attribute attrib,
			LDAPConstraints constraints) throws LDAPException {
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
		chain.nextModify(dn, mods, constraints);
		

	}

	@Override
	public void search(SearchInterceptorChain chain, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly, Results results, LDAPSearchConstraints constraints)
					throws LDAPException {
		chain.nextSearch(base, scope, filter, attributes, typesOnly, results, constraints);

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

}

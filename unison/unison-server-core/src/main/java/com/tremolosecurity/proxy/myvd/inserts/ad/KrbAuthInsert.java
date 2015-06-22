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


package com.tremolosecurity.proxy.myvd.inserts.ad;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Properties;

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

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
import net.sourceforge.myvd.chain.ModifyInterceptorChain;
import net.sourceforge.myvd.chain.PostSearchCompleteInterceptorChain;
import net.sourceforge.myvd.chain.PostSearchEntryInterceptorChain;
import net.sourceforge.myvd.chain.RenameInterceptorChain;
import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.inserts.kerberos.KerbHandler;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.ExtendedOperation;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;

public class KrbAuthInsert implements Insert {

	String name;
	
	HashMap<String,String> principalCache;
	
	@Override
	public String getName() {
		return name;
	}

	@Override
	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		this.name = name;
		this.principalCache = new HashMap<String,String>();
		
	}

	@Override
	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextAdd(entry, constraints);

	}

	@Override
	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		
		String userPrincipalName = getUserPrincipal(chain, dn);
		
		//check to see if this is an anonymous bind
		if (userPrincipalName.length() == 0) {
			return;
		}
		
		LoginContext lc = null;
		try {
			lc = new LoginContext("myvd-client", new UpnPwdCallbackHandler(userPrincipalName,pwd.getValue()));
		} catch (LoginException le) {
			
			throw new LDAPException(le.toString(),LDAPException.INVALID_CREDENTIALS,le.toString());
		} catch (SecurityException se) {
			
			throw new LDAPException(se.toString(),LDAPException.INVALID_CREDENTIALS,se.toString());
		}

		try {
			// attempt authentication
			lc.login();
		} catch (LoginException le) {
			
			throw new LDAPException(le.toString(),LDAPException.INVALID_CREDENTIALS,le.toString());
		}

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
		chain.nextSearch(base, scope, filter, attributes, typesOnly, results, constraints);

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
		

	}
	
	private String getUserPrincipal(BindInterceptorChain chain,
			DistinguishedName dn) throws LDAPException {
		
		
		
		if (dn.getDN().toString().length() == 0) {
			return "";
		}
		
		String userPrincipalName = this.principalCache.get(dn.getDN().toString().toLowerCase());
		
		if (userPrincipalName != null) {
			return userPrincipalName;
		}
		
		
		SearchInterceptorChain schain = chain.createSearchChain();
		Results res = new Results(null,chain.getPos());
		ArrayList<Attribute> attribs = new ArrayList<Attribute>();
		attribs.add(new Attribute("userPrincipalName"));
		schain.nextSearch(new DistinguishedName(dn.getDN().toString()), new Int(0), new Filter("(objectClass=*)"), attribs, new Bool(false), res, new LDAPSearchConstraints());
		res.start();
		
		
		if (res.hasMore()) {
			LDAPEntry entry = res.next().getEntry();
			userPrincipalName = entry.getAttribute("userPrincipalName").getStringValue().toUpperCase();
			
			
			
			
			while (res.hasMore()) {
				res.next();
			}
			
			res.finish();
			
			
		} else {
			res.finish();
			throw new LDAPException(dn.getDN().toString(),LDAPException.NO_SUCH_OBJECT,"No Such Object");
			
		}
		
		
		this.principalCache.put(dn.getDN().toString(), userPrincipalName);
		return userPrincipalName;
	}

}

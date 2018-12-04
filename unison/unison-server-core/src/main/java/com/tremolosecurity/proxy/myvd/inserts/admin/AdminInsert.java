/*
Copyright 2015, 2017 Tremolo Security, Inc.

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


package com.tremolosecurity.proxy.myvd.inserts.admin;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Properties;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
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
import net.sourceforge.myvd.util.EntryUtil;
import net.sourceforge.myvd.util.IteratorEntrySet;
import net.sourceforge.myvd.util.PBKDF2;

public class AdminInsert implements Insert {

	LDAPEntry userEntry;
	LDAPEntry rootEntry;
	String nameSpace;
	String name;
	String password;
	
	boolean hashed;
	
	
	@Override
	public void add(AddInterceptorChain arg0, Entry arg1, LDAPConstraints arg2)
			throws LDAPException {
		throw new LDAPException("Operation Not Supported",LDAPException.UNAVAILABLE,"");

	}

	@Override
	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password password, LDAPConstraints constraints) throws LDAPException {
		String pwd = new String(password.getValue());
		
		if (! (dn.getDN().toString().toLowerCase().equals(this.userEntry.getDN().toLowerCase()))) {
			throw new LDAPException("Invalid Credentials",LDAPException.INVALID_CREDENTIALS,dn.getDN().toString());
		}
		
		
		if (this.hashed) {
			try {
				if (! PBKDF2.checkPassword(pwd, this.password)) {
					throw new LDAPException("Invalid Credentials",LDAPException.INVALID_CREDENTIALS,dn.getDN().toString());
				}
			} catch (InvalidKeyException | UnsupportedEncodingException
					| NoSuchAlgorithmException e) {
				throw new LDAPException("Could not verify credentials",LDAPException.OPERATIONS_ERROR,dn.getDN().toString());
			}
			
			
			
		} else {
			if (! pwd.equals(this.password)) {
				throw new LDAPException("Invalid Credentials",LDAPException.INVALID_CREDENTIALS,dn.getDN().toString());
			}
		}
		

	}

	@Override
	public void compare(CompareInterceptorChain arg0, DistinguishedName arg1,
			Attribute arg2, LDAPConstraints arg3) throws LDAPException {
		throw new LDAPException("Operation Not Supported",LDAPException.UNAVAILABLE,"");

	}

	@Override
	public void configure(String name, Properties props, NameSpace ns)
			throws LDAPException {
		this.name = name;
		
		this.rootEntry = EntryUtil.createBaseEntry(ns.getBase().getDN());

		String uid = props.getProperty("uid");
		String password = props.getProperty("password");
		
		String uidDN = "uid=" + uid + "," + ns.getBase().getDN().toString();
		LDAPAttributeSet attrs = new LDAPAttributeSet();
		attrs.add(new LDAPAttribute("uid",uid));
		attrs.add(new LDAPAttribute("cn",uid));
		attrs.add(new LDAPAttribute("sn",uid));
		attrs.add(new LDAPAttribute("objectClass",GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getUserObjectClass()));
		
		this.userEntry = new LDAPEntry(uidDN,attrs);
		
		this.password = password;
		if (this.password.startsWith("{myvd}")) {
			this.hashed = true;
		}
	}

	@Override
	public void delete(DeleteInterceptorChain arg0, DistinguishedName arg1,
			LDAPConstraints arg2) throws LDAPException {
		throw new LDAPException("Operation Not Supported",LDAPException.UNAVAILABLE,"");

	}

	@Override
	public void extendedOperation(ExetendedOperationInterceptorChain arg0,
			ExtendedOperation arg1, LDAPConstraints arg2) throws LDAPException {
		throw new LDAPException("Operation Not Supported",LDAPException.UNAVAILABLE,"");

	}

	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public void modify(ModifyInterceptorChain arg0, DistinguishedName arg1,
			ArrayList<LDAPModification> arg2, LDAPConstraints arg3)
			throws LDAPException {
		throw new LDAPException("Operation Not Supported",LDAPException.UNAVAILABLE,"");

	}

	@Override
	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	@Override
	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	@Override
	public void rename(RenameInterceptorChain arg0, DistinguishedName arg1,
			DistinguishedName arg2, Bool arg3, LDAPConstraints arg4)
			throws LDAPException {
		throw new LDAPException("Operation Not Supported",LDAPException.UNAVAILABLE,"");

	}

	@Override
	public void rename(RenameInterceptorChain arg0, DistinguishedName arg1,
			DistinguishedName arg2, DistinguishedName arg3, Bool arg4,
			LDAPConstraints arg5) throws LDAPException {
		throw new LDAPException("Operation Not Supported",LDAPException.UNAVAILABLE,"");

	}

	@Override
	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes, Bool typesOnly,
			Results results, LDAPSearchConstraints constraints) throws LDAPException {
		
		Entry luserEntry = new Entry(new LDAPEntry(userEntry.getDN(),(LDAPAttributeSet) userEntry.getAttributeSet().clone()));
		Entry lrootEntry = new Entry(new LDAPEntry(userEntry.getDN(),(LDAPAttributeSet) userEntry.getAttributeSet().clone())); 
		
		ArrayList<Entry> res = new ArrayList<Entry>();
		
		if (scope.getValue() == 0) {
			if (base.getDN().toString().equalsIgnoreCase(rootEntry.getDN()) && filter.getRoot().checkEntry(rootEntry)) {
				res.add(lrootEntry);
			}
			
			if (base.getDN().toString().equalsIgnoreCase(userEntry.getDN()) && filter.getRoot().checkEntry(userEntry)) {
				res.add(luserEntry);
			}
		} else if (scope.getValue() == 1) {
			if (base.getDN().toString().equalsIgnoreCase(rootEntry.getDN()) && filter.getRoot().checkEntry(userEntry)) {
				res.add(luserEntry);
			}
		} else if (scope.getValue() == 2) {
			if (base.getDN().toString().equalsIgnoreCase(rootEntry.getDN()) && filter.getRoot().checkEntry(rootEntry)) {
				res.add(lrootEntry);
			}
			
			if (userEntry.getDN().toLowerCase().endsWith(base.getDN().toString().toLowerCase()) && filter.getRoot().checkEntry(userEntry)) {
				res.add(luserEntry);
			}
		}
		
		chain.addResult(results, new IteratorEntrySet(res.iterator()), base, scope, filter, attributes, typesOnly, constraints);

	}

	@Override
	public void shutdown() {
		

	}

}

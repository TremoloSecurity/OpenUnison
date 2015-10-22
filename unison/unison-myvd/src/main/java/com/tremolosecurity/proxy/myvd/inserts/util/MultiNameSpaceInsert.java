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
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.StringTokenizer;

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
import net.sourceforge.myvd.core.InsertChain;
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

public abstract class MultiNameSpaceInsert implements Insert {

	String name;
	
	List<NameSpace> nameSpaces;
	
	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		
		this.name = name;
		this.nameSpaces = new ArrayList<NameSpace>();
		
		ArrayList<String> nameSpaceNames = new ArrayList<String>();
		Properties nsProps = new Properties();
		
		this.configureNameSpaces(name,props,nameSpace,nameSpaceNames,nsProps);

		for (String nsName : nameSpaceNames) {
			String prefix = "server." + nsName + ".";
			int weight = Integer.parseInt(nsProps.getProperty(prefix + "weight","0"));
			String nsBase = nsProps.getProperty(prefix + "nameSpace");
			
			String nsChain = nsProps.getProperty(prefix + "chain");
			StringTokenizer chainToker = new StringTokenizer(nsChain,",");
			
			ArrayList<String> chainList = new ArrayList<String>();
			
			while (chainToker.hasMoreTokens()) {
				chainList.add(chainToker.nextToken());
			}
			
			Insert[] tchain = new Insert[chainList.size()];
			InsertChain chain = new InsertChain(tchain);
			chain.setProps(nsProps);
			
			NameSpace ns = new NameSpace(nsName,new DistinguishedName(nsBase),weight,chain,false);
			chain.setNameSpace(ns);
			
			this.nameSpaces.add(ns);
			
			try {
				this.configureChain(prefix,chainList,chain,ns);
			} catch (Exception e) {
				throw new LDAPException("Error initializing namespace",LDAPException.OPERATIONS_ERROR,"Could not initialize namespace",e);
			} 
		}
		
	}

	private void configureChain(String prefix,ArrayList<String> links,InsertChain chain,NameSpace ns) throws InstantiationException, IllegalAccessException, ClassNotFoundException, LDAPException {
		Iterator<String> it = links.iterator();
		int i=0;
		
		while (it.hasNext()) {
			String name = it.next();
			chain.setInsert(i, chain.getInsertConfig(name,prefix +  name + ".",chain,i));
			
			i++;
		}
		
		chain.configureChain();
	}
	
	public abstract void configureNameSpaces(String name, Properties props,
			NameSpace nameSpace, ArrayList<String> nameSpaceNames,
			Properties nsProps);

	@Override
	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Not provided",LDAPException.UNAVAILABLE,"Not provided");

	}

	@Override
	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		int numExceptions = 0;
		LDAPException last = null;
		for (NameSpace ns : this.nameSpaces) {
			try {
				BindInterceptorChain localChain = new BindInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,ns.getChain(),chain.getSession(),chain.getRequest());
				localChain.nextBind(dn,pwd,constraints);
			} catch (LDAPException e) {
				numExceptions++;
				last = e;
			}
		}
		
		if (numExceptions == this.nameSpaces.size()) {
			throw last;
		}


	}

	@Override
	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Not provided",LDAPException.UNAVAILABLE,"Not provided");

	}

	@Override
	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Not provided",LDAPException.UNAVAILABLE,"Not provided");

	}

	@Override
	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		throw new LDAPException("Not provided",LDAPException.UNAVAILABLE,"Not provided");

	}

	@Override
	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		throw new LDAPException("Not provided",LDAPException.UNAVAILABLE,"Not provided");

	}

	@Override
	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		for (NameSpace ns : this.nameSpaces) {
			SearchInterceptorChain localChain = new SearchInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,ns.getChain(),chain.getSession(),chain.getRequest());
			localChain.nextSearch(base,scope,filter,attributes,typesOnly,results,constraints);
		}
		


	}

	@Override
	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Not provided",LDAPException.UNAVAILABLE,"Not provided");

	}

	@Override
	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		throw new LDAPException("Not provided",LDAPException.UNAVAILABLE,"Not provided");

	}

	@Override
	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		

		
		for (NameSpace ns : this.nameSpaces) {
			PostSearchEntryInterceptorChain localChain = new PostSearchEntryInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,ns.getChain(),null, chain.getSession(),chain.getRequest());
			localChain.nextPostSearchEntry(entry, base, scope, filter, attributes, typesOnly, constraints);
		}

	}

	@Override
	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		

		
		for (NameSpace ns : this.nameSpaces) {
			PostSearchCompleteInterceptorChain localChain = new PostSearchCompleteInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,ns.getChain(),null, chain.getSession(),chain.getRequest());
			localChain.nextPostSearchComplete(base, scope, filter, attributes, typesOnly, constraints);
		}

	}

	@Override
	public void shutdown() {
		

	}

	public List<NameSpace> getChildNameSpaces() {
		return this.nameSpaces;
	}
}

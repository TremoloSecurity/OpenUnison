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


package com.tremolosecurity.proxy.myvd.inserts.amazon;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Properties;

import org.apache.logging.log4j.Logger;

import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClient;
import com.amazonaws.services.simpledb.AmazonSimpleDBClient;
import com.amazonaws.services.simpledb.model.Item;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;

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

public class AmazonDynamoDB implements Insert {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AmazonDynamoDB.class.getName());
	
	String accessKey;
	String secretKey;
	String userTable;
	String groupTable;
	
	DN userDN;
	DN groupDN;
	DN baseDN;

	String name;
	private AmazonDynamoDBClient db;
	
	@Override
	public void add(AddInterceptorChain arg0, Entry arg1, LDAPConstraints arg2)
			throws LDAPException {
		throw new LDAPException("Not provided",LDAPException.UNAVAILABLE,"Not provided");

	}

	@Override
	public void bind(BindInterceptorChain arg0, DistinguishedName arg1,
			Password arg2, LDAPConstraints arg3) throws LDAPException {
		throw new LDAPException("Not provided",LDAPException.UNAVAILABLE,"Not provided");

	}

	@Override
	public void compare(CompareInterceptorChain arg0, DistinguishedName arg1,
			Attribute arg2, LDAPConstraints arg3) throws LDAPException {
		throw new LDAPException("Not provided",LDAPException.UNAVAILABLE,"Not provided");

	}

	@Override
	public void configure(String name, Properties props, NameSpace ns)
			throws LDAPException {
		this.name = name;
		this.accessKey = props.getProperty("accessKey");
		this.secretKey = props.getProperty("secretKey");
		this.userTable = props.getProperty("userTable");
		this.groupTable = props.getProperty("groupTable");
		
		this.userDN = new DN("ou=users," + ns.getBase().getDN().toString());
		this.groupDN = new DN("ou=groups," + ns.getBase().getDN().toString());
		this.baseDN = new DN(ns.getBase().getDN().toString());
		
		this.db = new AmazonDynamoDBClient(new BasicAWSCredentials(accessKey,secretKey));

	}

	@Override
	public void delete(DeleteInterceptorChain arg0, DistinguishedName arg1,
			LDAPConstraints arg2) throws LDAPException {
		throw new LDAPException("Not provided",LDAPException.UNAVAILABLE,"Not provided");

	}

	@Override
	public void extendedOperation(ExetendedOperationInterceptorChain arg0,
			ExtendedOperation arg1, LDAPConstraints arg2) throws LDAPException {
		throw new LDAPException("Not provided",LDAPException.UNAVAILABLE,"Not provided");

	}

	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public void modify(ModifyInterceptorChain arg0, DistinguishedName arg1,
			ArrayList<LDAPModification> arg2, LDAPConstraints arg3)
			throws LDAPException {
		throw new LDAPException("Not provided",LDAPException.UNAVAILABLE,"Not provided");

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
		throw new LDAPException("Not provided",LDAPException.UNAVAILABLE,"Not provided");

	}

	@Override
	public void rename(RenameInterceptorChain arg0, DistinguishedName arg1,
			DistinguishedName arg2, DistinguishedName arg3, Bool arg4,
			LDAPConstraints arg5) throws LDAPException {
		throw new LDAPException("Not provided",LDAPException.UNAVAILABLE,"Not provided");

	}

	@Override
	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes, Bool typesOnly,
			Results results, LDAPSearchConstraints constraints) throws LDAPException {
		boolean addBase = false;
		boolean addUser = false;
		boolean addGroups = false;
		
		boolean searchUsers = false;
		boolean searchGroups = false;
		
		Filter filterToUser = null;
		
		Iterator<Item> userResults = null;
		Iterator<Item> groupResults = null;
		
		
		try {
			filterToUser = new Filter((FilterNode) filter.getRoot().clone());
		} catch (CloneNotSupportedException e) {
			
		}
		
		if (scope.getValue() == 0) {
			//base search
			
			
			
			if (base.getDN().equals(this.baseDN)) {
				addBase = true;
			} else if (base.getDN().equals(this.userDN)) {
				addUser = true;
			} else if (base.getDN().equals(this.groupDN)) {
				addGroups = true;
			} else if (base.getDN().toString().endsWith(this.userDN.toString())) {
				searchUsers = true;
				filterToUser = this.addBaseToFilter(base, filterToUser);
			} else if (base.getDN().toString().endsWith(this.groupDN.toString())) {
				searchGroups = true;
				filterToUser = this.addBaseToFilter(base, filterToUser);
			} else {
				throw new LDAPException("Object not found",LDAPException.NO_SUCH_OBJECT,base.getDN().toString());
			}
			
			
		} else if (scope.getValue() == 1) {
			//One Level
			
			if (base.getDN().equals(this.baseDN)) {
				addUser = true;
				addGroups = true;
			} else if (base.getDN().equals(userDN)) {
				searchUsers = true;
				//filterToUser = this.addBaseToFilter(base, filterToUser);
			} else if (base.getDN().equals(groupDN)) {
				searchGroups = true;
				//filterToUser = this.addBaseToFilter(base, filterToUser);
			} 
		} else if (scope.getValue() == 2) {
			if (base.getDN().equals(this.baseDN)) {
				addBase = true;
				addUser = true;
				addGroups = true;
				searchUsers = true;
				searchGroups = true;
				
				
				//filterToUser = this.addBaseToFilter(base, filterToUser);
			} else if (base.getDN().equals(userDN) || base.getDN().toString().endsWith(this.userDN.toString())) {
				searchUsers = true;
				//filterToUser = this.addBaseToFilter(base, filterToUser);
			} else if (base.getDN().equals(groupDN) ||  base.getDN().toString().endsWith(this.groupDN.toString())) {
				searchGroups = true;
				//filterToUser = this.addBaseToFilter(base, filterToUser);
			} 
		}
		
		
		ArrayList<Entry> baseEntries = new ArrayList<Entry>();
		
		if (addBase) {
			baseEntries.add(new Entry(EntryUtil.createBaseEntry(this.baseDN)));
		}
		
		if (addUser) {
			baseEntries.add(new Entry(EntryUtil.createBaseEntry(this.userDN)));
		}
		
		if (addGroups) {
			baseEntries.add(new Entry(EntryUtil.createBaseEntry(this.groupDN)));
		}

	}
	
	private Filter addBaseToFilter(DistinguishedName base, Filter filter) {
		String rdnName,rdnVal;
		
		RDN rdn = (RDN) base.getDN().getRDNs().get(0); 
		rdnName = rdn.getType();
		rdnVal = rdn.getValue();
		
		ArrayList<FilterNode> ands = new ArrayList<FilterNode>();
		ands.add(new FilterNode(FilterType.EQUALS,rdnName, rdnVal));
		try {
			ands.add((FilterNode) filter.getRoot().clone());
		} catch (CloneNotSupportedException e) {
			
		}
		FilterNode newroot = new FilterNode(FilterType.AND,ands);
		filter = new Filter(newroot);
		
		return filter;
	}

	@Override
	public void shutdown() {
		db.shutdown();

	}

}

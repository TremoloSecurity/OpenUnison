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

import com.amazonaws.services.simpledb.model.Attribute;
import com.amazonaws.services.simpledb.model.Item;
import com.amazonaws.services.simpledb.model.SelectResult;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.util.DN;

import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.EntrySet;
import net.sourceforge.myvd.types.Filter;

public class AmazonSimpleDBEntrySet implements EntrySet {

	
	String dnBase;
	
	Iterator<Item> userRes;
	Iterator<Item> groupRes;
	Iterator<Entry> baseEntries;
	
	Entry currEntry;
	
	boolean done;
	boolean entryFetched;
	boolean isFirst;
	
	Filter filter;
	
	
	public AmazonSimpleDBEntrySet(String dnBase,Iterator<Entry> baseEntries, Iterator<Item> userRes, Iterator<Item> groupRes,Filter filter) {
		this.done = false;
		this.isFirst = true;
		this.dnBase = dnBase;
		this.baseEntries = baseEntries;
		this.userRes = userRes;
		this.groupRes =  groupRes;
		this.filter = filter;
	}
	
	@Override
	public void abandon() throws LDAPException {
		
		
	}

	
	
	
	@Override
	public Entry getNext() throws LDAPException {
		if (! done) {
			if (! entryFetched) {
				entryFetched = true;
				return this.currEntry;
			} else {
				this.hasMore();
				return this.getNext();
			}
		} else {
			return null;
		}
		
	}

	@Override
	public boolean hasMore() throws LDAPException {
		if (! done) {
			if (entryFetched || isFirst) {
				isFirst = false;
				return getNextEntry();
			} else {
				return true;
			}
		} else {
			return false;
		}
	}




	private boolean getNextEntry() {
		if (this.baseEntries != null && this.baseEntries.hasNext()) {
			
			Entry tmpEntry = this.baseEntries.next();
			if (filter.getRoot().checkEntry(tmpEntry.getEntry())) {
				this.currEntry = tmpEntry;
				this.entryFetched = false;
				return true;
			} else {
				return getNextEntry();
			}
			
			
			 
			 
			
			
			
		} else if (this.userRes != null && this.userRes.hasNext()) {
			Entry tmpEntry = createEntry(this.userRes.next(),true);
			
			//if (filter.getRoot().checkEntry(tmpEntry.getEntry())) {
				this.currEntry = tmpEntry;
				this.entryFetched = false;
				return true;
			//} else {
			//	return getNextEntry();
			//}
			
			
		} else if (this.groupRes != null && this.groupRes.hasNext()) {
			
			Entry tmpEntry = createEntry(this.groupRes.next(),false);
			
			//if (filter.getRoot().checkEntry(tmpEntry.getEntry())) {
				this.currEntry = tmpEntry;
				this.entryFetched = false;
				return true;
			//} else {
			//	return getNextEntry();
			//}
			
			
			
			
		} else { 
			this.done = true;
			return false;
		}
	}




	private Entry createEntry(Item item,boolean user) {
		StringBuffer dnBuff = new StringBuffer();
		LDAPAttribute objClass = null;
		
		if (user) {
			dnBuff.append("uid=").append(item.getName()).append(",ou=users,").append(this.dnBase);
			objClass = new LDAPAttribute("objectClass","inetOrgPerson");
		} else {
			dnBuff.append("cn=").append(item.getName()).append(",ou=groups,").append(this.dnBase);
			objClass = new LDAPAttribute("objectClass","groupOfUniqueNames");
		}
		
		LDAPAttributeSet attrs = new LDAPAttributeSet();
		
		for (Attribute fromAmz : item.getAttributes()) {
			LDAPAttribute attr = attrs.getAttribute(fromAmz.getName());
			if (attr == null) {
				attr =  new LDAPAttribute(fromAmz.getName());
				attrs.add(attr);
			}
			
			attr.addValue(fromAmz.getValue());
		}
		
		attrs.add(objClass);
		
		
		return new Entry(new LDAPEntry(dnBuff.toString(),attrs));
	}

}

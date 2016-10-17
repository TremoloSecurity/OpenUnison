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
package com.tremolosecurity.mongodb.myvd;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.bson.Document;
import org.bson.conversions.Bson;

import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.mongodb.client.FindIterable;
import com.mongodb.client.model.Filters;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;

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

import static com.mongodb.client.model.Filters.*;

public class MongoInsert implements Insert {

	private static final String UNISON_RDN_ATTRIBUTE_NAME = "unisonRdnAttributeName";
	String name;
	private NameSpace nameSpace;
	String lcaseBase;
	String database;
	
	MongoClient mongo;
	
	public String getName() {
		return this.name;
	}
	
	

	public void configure(String name, Properties props, NameSpace nameSpace) throws LDAPException {
		this.name = name;
		this.nameSpace = nameSpace;
		this.mongo = new MongoClient(new MongoClientURI(props.getProperty("url")));
		this.lcaseBase = nameSpace.getBase().getDN().toString().toLowerCase();
		this.database = props.getProperty("database");
		
	}
	
	String getLocalBase(String dn) {
		if (dn.length() < this.lcaseBase.length()) {
			return "";
		} else {
			String v = dn.substring(0,dn.length() - this.lcaseBase.length());
			if (! v.isEmpty()) {
				//remove the comma
				v = v.substring(0, v.length() - 1);
			}
			return v;
		}
	}
	
	//the collection will be the ou= of the base after rmoving the namespace
	String getCollection(String dn) {
		int start = dn.lastIndexOf(',');
		
		if (start == -1) {
			if (dn.startsWith("ou=")) {
				return dn.substring(3);
			} else {
				return null;
			}
			
		} else {
			start += ",ou=".length();
			return dn.substring(start);
		}
		
		
	}
	
	Attribute getRDN(String dn) {
		if (dn.toLowerCase().startsWith("ou=")) {
			return null;
		} else {
			int start = dn.indexOf('=');
			String attr = dn.substring(0,start);
			String val = dn.substring(start + 1,dn.indexOf(',',start + 1));
			Attribute rdn = new Attribute(attr,val);
			return rdn;
		}
		
		
	}
	
	

	public void add(AddInterceptorChain chain, Entry entry, LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn, Password pwd, LDAPConstraints constraints)
			throws LDAPException {
		throw new LDAPException(LDAPException.resultCodeToString(LDAPException.LDAP_NOT_SUPPORTED),LDAPException.LDAP_NOT_SUPPORTED,"Bind not supported");

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn, Attribute attrib,
			LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn, LDAPConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain, ExtendedOperation op,
			LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException(LDAPException.resultCodeToString(LDAPException.LDAP_NOT_SUPPORTED),LDAPException.LDAP_NOT_SUPPORTED,"Bind not supported");

	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn, ArrayList<LDAPModification> mods,
			LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		
		boolean addBase = false;
		boolean addCollection = false;
		boolean oneEntry = false;
		boolean listCollections = false;
		boolean searchUsers = false;
		Bson mongoFilter = null;
		Filter filterToUser = null;
		
		try {
			filterToUser = new Filter((FilterNode) filter.getRoot().clone());
		} catch (CloneNotSupportedException e) {
		}
		
		
		String localBase = this.getLocalBase(base.getDN().toString());
		String collectionName = this.getCollection(localBase);
		
		Attribute rdn = null;
		
		if (! localBase.isEmpty()) {
			rdn = this.getRDN(localBase);
		}
		
		if (scope.getValue() == 0) {
			
			if (localBase.isEmpty()) {
				addBase = true;
			} else if (rdn == null) {
				addCollection = true;
			} else {
				oneEntry = true;
			}
		} else if (scope.getValue() == 1) {
			addBase = false;
			
			if (localBase.isEmpty()) {
				listCollections = true;
			} else {
				searchUsers = true;
			}
			
		} else {
			//scope == 2
			addBase = true;
			if (localBase.isEmpty()) {
				listCollections = true;
			}
			
			searchUsers = true;
		}
		
		
		
		//create results
		ArrayList<Entry> res = new ArrayList<Entry>();
		StringBuffer b = new StringBuffer();
		if (addBase) {
			this.addToEntry(new Entry(EntryUtil.createBaseEntry(new DN(this.nameSpace.getBase().getDN().toString()))),filter,res);
		}
		
		if (listCollections) {
			
			for (String ou : mongo.getDatabase(this.database).listCollectionNames()) {
				b.setLength(0);
				b.append("ou=").append(ou).append(",").append(this.nameSpace.getBase().getDN().toString());
				
				this.addToEntry(new Entry(EntryUtil.createBaseEntry(new DN(b.toString()))),filter,res);
			}
		}
		
		if (addCollection) {
			boolean found = false;
			for (String ou : mongo.getDatabase(this.database).listCollectionNames()) {
				if (ou.equalsIgnoreCase(collectionName)) {
					b.setLength(0);
					b.append("ou=").append(ou).append(",").append(this.nameSpace.getBase().getDN().toString());
					
					this.addToEntry(new Entry(EntryUtil.createBaseEntry(new DN(b.toString()))),filter,res);
					found = true;
				}
			}
			
			if (! found) {
				throw new LDAPException("Could not find object",LDAPException.NO_SUCH_OBJECT,LDAPException.resultCodeToString(LDAPException.NO_SUCH_OBJECT));
			}
			
		}
		
		if (oneEntry) {
			
			boolean found = false;
			for (String ou : mongo.getDatabase(this.database).listCollectionNames()) {
				if (ou.equalsIgnoreCase(collectionName)) {
					found = true;
				}
			}
			
			if (! found) {
				throw new LDAPException("Could not find object",LDAPException.NO_SUCH_OBJECT,LDAPException.resultCodeToString(LDAPException.NO_SUCH_OBJECT));
			}
			
			//first see if we get results with the filter
			ArrayList<FilterNode> children = new ArrayList<FilterNode>();
			children.add(new FilterNode(FilterType.EQUALS,rdn.getAttribute().getName(),rdn.getAttribute().getStringValue()));
			children.add(filterToUser.getRoot());
			FilterNode and = new FilterNode(FilterType.AND,children);
			mongoFilter = this.convertFilterToMongo(and);
			
			
			FindIterable<Document> searchRes = mongo.getDatabase(this.database).getCollection(collectionName).find(mongoFilter);
			if (searchRes == null) {
				//nothing, need to know if the object exists or if its just the filter that didn't match
				searchRes = mongo.getDatabase(this.database).getCollection(collectionName).find(eq(rdn.getAttribute().getName(),rdn.getAttribute().getStringValue()));
				
				if (searchRes == null) {
					throw new LDAPException("Could not find object",LDAPException.NO_SUCH_OBJECT,LDAPException.resultCodeToString(LDAPException.NO_SUCH_OBJECT));
				}
			} else {
				Document doc = searchRes.first();
				if (doc == null) {
					
					//nothing, need to know if the object exists or if its just the filter that didn't match
					searchRes = mongo.getDatabase(this.database).getCollection(collectionName).find(eq(rdn.getAttribute().getName(),rdn.getAttribute().getStringValue()));
					if (searchRes.first() == null) {
						throw new LDAPException("Could not find object",LDAPException.NO_SUCH_OBJECT,LDAPException.resultCodeToString(LDAPException.NO_SUCH_OBJECT));
					}
				} else {
					res.add(createEntry(doc,collectionName));
				}
			}
			
			
		}
		
		if (searchUsers) {
			mongoFilter = this.convertFilterToMongo(filter.getRoot());
			
			if (collectionName != null) {
				boolean found = false;
				for (String ou : mongo.getDatabase(this.database).listCollectionNames()) {
					if (ou.equalsIgnoreCase(collectionName)) {
						found = true;
					}
				}
				
				if (! found) {
					throw new LDAPException("Could not find object",LDAPException.NO_SUCH_OBJECT,LDAPException.resultCodeToString(LDAPException.NO_SUCH_OBJECT));
				}
				
				FindIterable<Document> searchRes = mongo.getDatabase(this.database).getCollection(collectionName).find(mongoFilter);
				for (Document doc : searchRes) {
					res.add(createEntry(doc,collectionName));
				}
			} else {
				for (String ou : mongo.getDatabase(this.database).listCollectionNames()) {
					FindIterable<Document> searchRes = mongo.getDatabase(this.database).getCollection(ou).find(mongoFilter);
					for (Document doc : searchRes) {
						res.add(createEntry(doc,ou));
					}
				}
				
			}
		}
		
		chain.addResult(results, new IteratorEntrySet(res.iterator()), base, scope, filterToUser, attributes, typesOnly, constraints);
		
		
	}
	
	private void addToEntry(Entry entry,Filter filter,List<Entry> res) {
		if (filter.getRoot().checkEntry(entry.getEntry())) {
			res.add(entry);
		}
	}

	private Entry createEntry(Document doc, String collectionName) {
		LDAPAttributeSet attrs = new LDAPAttributeSet();
		for (String key : doc.keySet()) {
			if (! key.equalsIgnoreCase(UNISON_RDN_ATTRIBUTE_NAME)) {
				Object o = doc.get(key);
				if (o instanceof List) {
					List l = (List) o;
					LDAPAttribute attr = new LDAPAttribute(key);
					for (Object ox : l) {
						attr.addValue(ox.toString());
					}
					attrs.add(attr);
				} else {
					attrs.add(new LDAPAttribute(key,o.toString()));
				}
			}
		}
		
		StringBuffer b = new StringBuffer();
		b.append(doc.getString(UNISON_RDN_ATTRIBUTE_NAME)).append('=').append(doc.getString(doc.getString(UNISON_RDN_ATTRIBUTE_NAME))).append(",ou=").append(collectionName).append(',').append(this.nameSpace.getBase().getDN().toString());
		
		return new Entry(new LDAPEntry(b.toString(),attrs));
		
		
	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn,
			DistinguishedName newParentDN, Bool deleteOldRdn, LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain, Entry entry, DistinguishedName base, Int scope,
			Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain, DistinguishedName base, Int scope,
			Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void shutdown() {
		this.mongo.close();

	}
	
	private Bson convertFilterToMongo(FilterNode root) {
		FilterType op = root.getType();
        switch (op){
            case AND:
            case OR:
            	List<Bson> children = new ArrayList<Bson>();
            	for (FilterNode node : root.getChildren()) {
            		children.add(convertFilterToMongo(node));
            	}
            	
            	if (op == FilterType.OR) {
            		return or(children);
            	} else {
            		return and(children);
            	}
            	
            case NOT:
            	return not(convertFilterToMongo(root.getNot()));
            	
            case EQUALS: 
            	return eq(root.getName(),root.getValue());
            	
            case GREATER_THEN:
            	return gt(root.getName(),root.getValue());
            	
            case LESS_THEN:
            	return lt(root.getName(),root.getValue());
            	
            case PRESENCE:
            	return exists(root.getName());
            	
            case SUBSTR:
            	StringBuffer s = new StringBuffer();
            	return eq(root.getName(),java.util.regex.Pattern.compile(root.getValue().replace("*", ".*")));
            	
        }
        
        return null;
	}
}

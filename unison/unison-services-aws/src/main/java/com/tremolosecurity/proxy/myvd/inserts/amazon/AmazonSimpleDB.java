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
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;

import org.apache.logging.log4j.Logger;

import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.simpledb.AmazonSimpleDBClient;
import com.amazonaws.services.simpledb.model.Item;
import com.amazonaws.services.simpledb.model.SelectRequest;
import com.amazonaws.services.simpledb.model.SelectResult;
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

public class AmazonSimpleDB implements Insert {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AmazonSimpleDB.class.getName());
	
	String accessKey;
	String secretKey;
	String userDomain;
	String groupDomain;
	
	DN userDN;
	DN groupDN;
	DN baseDN;
	
	String name;
	private AmazonSimpleDBClient sdb;
	
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
		this.userDomain = props.getProperty("userDomain");
		this.groupDomain = props.getProperty("groupDomain");
		
		this.userDN = new DN("ou=users," + ns.getBase().getDN().toString());
		this.groupDN = new DN("ou=groups," + ns.getBase().getDN().toString());
		this.baseDN = new DN(ns.getBase().getDN().toString());
		
		this.sdb = new AmazonSimpleDBClient(new BasicAWSCredentials(accessKey,secretKey));

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
		
		if (searchUsers) {
			userResults = this.searchAmazonSimpleDB(true, filterToUser, attributes);
		}
		
		if (searchGroups) {
			groupResults = this.searchAmazonSimpleDB(false, filterToUser, attributes);
		}
		
		chain.addResult(results, new AmazonSimpleDBEntrySet(this.baseDN.toString(),baseEntries.iterator(),userResults,groupResults,filterToUser), base, scope, filterToUser, attributes, typesOnly, constraints);
	}
	
	private Iterator<Item> searchAmazonSimpleDB(boolean users,Filter filter,ArrayList<Attribute> attributes) {
		StringBuffer sqlWhere = new StringBuffer();
		ArrayList<Object> vals = new ArrayList<Object>();
		this.stringFilter(filter.getRoot(),sqlWhere, vals);
		
		StringBuffer SQL = new StringBuffer();
		SQL.append("SELECT ");
		
		if (attributes.size() == 0) {
			SQL.append("* ");
		} else if (attributes.size() == 1 && attributes.get(0).equals("*")) {
			SQL.append("* ");
		} else if (attributes.size() == 1 && attributes.get(0).getAttribute().getName().equals("1.1")) {
			SQL.append("uid ");
		} else {
			for(Attribute attr : attributes) {
				SQL.append(attr.getAttribute().getName()).append(',');
			}
			
			SQL.setLength(SQL.length() - 1);
		}
		
		SQL.append(" FROM ").append('`');
		
		if (users) {
			SQL.append(this.userDomain);
		} else  {
			SQL.append(this.groupDomain);
		}
		
		SQL.append("` WHERE ").append(sqlWhere);
		
		if (logger.isDebugEnabled()) {
			logger.debug("SQL : " + SQL.toString());
		}
		
		SelectResult res = this.sdb.select(new SelectRequest(SQL.toString()));
		return res.getItems().iterator();
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
	
	private String stringFilter(FilterNode root, StringBuffer filter,ArrayList<Object> vals) {
        FilterType op;
        //filter.append('(');
        String comp = null;
        ArrayList<FilterNode> children;
        Iterator<FilterNode> filterIt;
        String attribName = null;
        
        boolean isFirst = true;
        
        
                op = root.getType();
                switch (op){
                    case AND:
                    		
                    		HashMap<String,ArrayList<FilterNode>> attribs = new HashMap<String,ArrayList<FilterNode>>();
                    		//first sort the nodes into "buckets"
                    		children = root.getChildren();
                        filterIt = children.iterator();
                        while (filterIt.hasNext()) {
                        		FilterNode node = filterIt.next();
                        		if (node.getType() == FilterType.AND) {
                        			ArrayList<FilterNode> ands = attribs.get("&");
                        			if (ands == null) {
                        				ands = new ArrayList<FilterNode>();
                        				attribs.put("&",ands);
                        			}
                        			ands.add(node);
                        		} else if (node.getType() == FilterType.OR) {
                        			ArrayList<FilterNode> ors = attribs.get("|");
                        			if (ors == null) {
                        				ors = new ArrayList<FilterNode>();
                        				attribs.put("|",ors);
                        			}
                        			ors.add(node);
                        		} else if (node.getType() == FilterType.NOT) {
                        			ArrayList<FilterNode> nots = attribs.get("!");
                        			if (nots == null) {
                        				nots = new ArrayList<FilterNode>();
                        				attribs.put("!",nots);
                        			}
                        			nots.add(node);
                        		} else {
                        			
                        			ArrayList<FilterNode> attribNodes = attribs.get(node.getName().toLowerCase());
                        			if (attribNodes == null) {
                        				attribNodes = new ArrayList<FilterNode>();
                        				attribs.put(node.getName(),attribNodes);
                        			}
                        			attribNodes.add(node);
                        		}
                        }
                        
                        filter.append(" ( ");
                    		
                        Iterator<String> itBuckets = attribs.keySet().iterator();
                        while (itBuckets.hasNext()) {
                        		String attrib = itBuckets.next();
                        		ArrayList<FilterNode> nodes = attribs.get(attrib);
                        		if (attrib.equals("&")) {
                        			Iterator<FilterNode> itNodes = nodes.iterator();
                        			filter.append(" ( ");
                        			while (itNodes.hasNext()) {
                        				stringFilter(itNodes.next(),filter,vals);
                        				if (itNodes.hasNext()) {
                        					filter.append(" AND ");
                        				}
                        			}
                        			
                        			
                        			filter.append(" ) ");
                        			
                        			if (itBuckets.hasNext()) {
                        				filter.append(" AND ");
                        			}
                        		} else if (attrib.equals("|")) {
                        			Iterator<FilterNode> itNodes = nodes.iterator();
                        			filter.append(" ( ");
                        			while (itNodes.hasNext()) {
                        				stringFilter(itNodes.next(),filter,vals);
                        				if (itNodes.hasNext()) {
                        					filter.append(" AND ");
                        				}
                        			}
                        			filter.append(" ) ");
                        			
                        			if (itBuckets.hasNext()) {
                        				filter.append(" AND ");
                        			}
                        		} else if (attrib.equals("!")) {
                        			Iterator<FilterNode> itNodes = nodes.iterator();
                        			filter.append(" ( ");
                        			while (itNodes.hasNext()) {
                        				stringFilter(itNodes.next(),filter,vals);
                        				if (itNodes.hasNext()) {
                        					filter.append(" AND ");
                        				}
                        			}
                        			filter.append(" ) ");
                        			
                        			if (itBuckets.hasNext()) {
                        				filter.append(" AND ");
                        			}
                        		} else {
                        			Iterator<FilterNode> itNodes = nodes.iterator();
                        			filter.append(" ( ");
                        			while (itNodes.hasNext()) {
                        				stringFilter(itNodes.next(),filter,vals);
                        				if (itNodes.hasNext()) {
                        					filter.append(" OR ");
                        				}
                        			}
                        			filter.append(" ) ");
                        			
                        			if (itBuckets.hasNext()) {
                        				filter.append(" AND ");
                        			}
                        		}
                        }
                        
                        filter.append(" ) ");
                    		
                        
                        
                        break;
                    case OR:
                    		filter.append(" ( ");
                        
                        children = root.getChildren();
                        filterIt = children.iterator();
                        while (filterIt.hasNext()) {
                        		stringFilter(filterIt.next(),filter,vals);
                        		if (filterIt.hasNext()) {
                        			filter.append(" OR ");
                        		}
                        }
                        filter.append(" ) ");
                        break;
                        
                    case NOT:
                        filter.append(" NOT ( ");
                        stringFilter(root.getNot(),filter,vals);
                        filter.append(" ) ");
                        
                        break;
                    case EQUALS:{
                    		if (root.getName().equalsIgnoreCase("objectclass")) {
                    			filter.append(" (uid IS NOT NULL OR cn IS NOT NULL) ");
                    		} else {
		                        attribName = root.getName().toLowerCase();
		                        
		                        if (attribName == null) {
		                        	filter.append(" (uid IS NULL AND cn IS NULL) ");
		                        } else {
		                        
		                    		filter.append(attribName);
		                    		filter.append("='");
		                    		filter.append(root.getValue());
		                    		filter.append('\'');
		                        
		                    		vals.add(root.getValue());
		                        }
                    		}
                        
                        
                        
                        break;
                    }
                    case GREATER_THEN:{
                    		attribName = root.getName().toLowerCase();
                    		filter.append(attribName);
                        filter.append(">=");
                        filter.append("=");
                		filter.append(root.getValue());
                		
                        vals.add(root.getValue());
                        break;
                    }
                    case LESS_THEN:{
                    		attribName = root.getName().toLowerCase();
                    		filter.append(attribName);
                        filter.append("<=");
                        filter.append("=");
                		filter.append(root.getValue());
                		
                        vals.add(root.getValue());
                        break;
                        
                        
                    }
                    case PRESENCE:
                    		if (root.getName().equalsIgnoreCase("objectclass")) {
                    			filter.append(" (uid IS NOT NULL OR cn IS NOT NULL) ");
                    		} else {
	                    		filter.append(root.getName().toLowerCase());
	                        filter.append(" IS NOT NULL ");
                    		}
                        break;
                    /*case APPROX_MATCH:
                        filter.append((String)itr.next());
                        filter.append("~=");
                        byte[] value = (byte[])itr.next();
                        filter.append(byteString(value));
                        
                        if (comp != null && itr.hasNext()) {
                        	filter.append(comp);
                        }
                        
                        break;
                    case LDAPSearchRequest.EXTENSIBLE_MATCH:
                        String oid = (String)itr.next();

                        filter.append((String)itr.next());
                        filter.append(':');
                        filter.append(oid);
                        filter.append(":=");
                        filter.append((String)itr.next());
                        
                        if (comp != null && itr.hasNext()) {
                        	filter.append(comp);
                        }
                        
                        break;*/
                    case SUBSTR:{
                    		attribName = root.getName().toLowerCase();
                    		filter.append(attribName);
                        filter.append(" LIKE '");
                        boolean noStarLast = false;
                        
                        filter.append(root.getValue().replace('*','%')).append('\'');
                        
                        break;
                    }
                }
            
        
        
        
        
        if (comp != null) {
        	filter.append(')');
        }
        
        return attribName;
    }

	@Override
	public void shutdown() {
		this.sdb.shutdown();

	}

}

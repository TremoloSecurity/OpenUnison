/*******************************************************************************
 * Copyright 2023 Tremolo Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/

package com.tremolosecurity.proxy.myvd.inserts;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import org.apache.http.client.ClientProtocolException;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningTarget;
import com.tremolosecurity.provisioning.core.providers.AzureADProvider;
import com.tremolosecurity.provisioning.util.HttpCon;
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
import net.sourceforge.myvd.types.FilterNode;
import net.sourceforge.myvd.types.FilterType;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;
import net.sourceforge.myvd.util.EntryUtil;
import net.sourceforge.myvd.util.IteratorEntrySet;

public class AzureADInsert implements Insert {

	String name;
	String target;

	NameSpace nameSpace;

	String objectClass;

	DN base;
	boolean users;
	String uriPoint;
	String rdnAttribute;

	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public void configure(String name, Properties props, NameSpace nameSpace) throws LDAPException {
		this.name = name;
		this.nameSpace = nameSpace;

		this.target = props.getProperty("target");
		this.objectClass = props.getProperty("objectClass");

		this.base = new DN(nameSpace.getBase().getDN().toString());

		String isusers = props.getProperty("users");
		this.users = isusers == null || isusers.equalsIgnoreCase("true");
		
		if (this.users) {
			this.uriPoint = "users";
			this.rdnAttribute = "userPrincipalName";
		} else {
			this.uriPoint = "groups";
			this.rdnAttribute = props.getProperty("rdnAttribute");
		}
	}

	@Override
	public void add(AddInterceptorChain chain, Entry entry, LDAPConstraints constraints) throws LDAPException {
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
		AzureADProvider azuread = null;
		try {
			ProvisioningTarget target = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine()
					.getTarget(this.target);
			if (target == null) {
				throw new ProvisioningException("Target not found '" + this.target + "'");
			}

			if (target.getProvider() instanceof AzureADProvider) {
				azuread = (AzureADProvider) target.getProvider();
			} else {
				throw new ProvisioningException("Target '" + this.target + "' is not AzureADProvider");
			}
		} catch (ProvisioningException e) {
			throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),
					LDAPException.OPERATIONS_ERROR, "Could not load target '" + this.target + "'", e);
		}
		
		FilterNode newFilter = this.clearOutPresence(new Filter(filter.getValue()).getRoot());

		if (scope.getValue() == 0) {

			if (base.getDN().equals(this.base)) {
				ArrayList<Entry> entries = new ArrayList<Entry>();

				entries.add(new Entry(EntryUtil.createBaseEntry(new DN(this.base.toString()))));

				chain.addResult(results, new IteratorEntrySet(entries.iterator()), base, scope, filter, attributes,
						typesOnly, constraints);
				return;
			} else {
				RDN rdn = (RDN) base.getDN().getRDNs().get(0);
				String upn = null;
				if (this.users) {
					if (!rdn.getType().equalsIgnoreCase("userPrincipalName")) {
						throw new LDAPException("Unsupported", LDAPException.UNWILLING_TO_PERFORM,
								LDAPException.resultCodeToString(LDAPException.UNWILLING_TO_PERFORM));
					}
					
					upn = rdn.getValue();
				} else {
					if (rdn.getType().equalsIgnoreCase(this.rdnAttribute)) {
						FilterNode searchByDisplayName = new FilterNode(FilterType.EQUALS,this.rdnAttribute,rdn.getValue());
						if (newFilter == null) {
							newFilter = searchByDisplayName;
							
						} else {
							FilterNode andFilter = new FilterNode(FilterType.AND,new ArrayList<FilterNode>());
							andFilter.getChildren().add(searchByDisplayName);
							andFilter.getChildren().add(newFilter);
							newFilter = andFilter;
						}
					} else {
						throw new LDAPException("Unsupported", LDAPException.UNWILLING_TO_PERFORM,
								LDAPException.resultCodeToString(LDAPException.UNWILLING_TO_PERFORM));
					}
				}

				

			

				

				chain.addResult(results, new IteratorEntrySet(this.lookupUser(upn, azuread, attributes,newFilter).iterator()), base, scope, filter, attributes,
						typesOnly, constraints);
				return;

			}

		} else {
			chain.addResult(results, new IteratorEntrySet(this.lookupUser(null, azuread, attributes,newFilter).iterator()), base, scope, filter, attributes,
					typesOnly, constraints);
			
		}

	}

	private List<Entry> lookupUser(String userPrincipalName, AzureADProvider azureAD, List<Attribute> toreturn,FilterNode filter)
			throws LDAPException {
		HttpCon con = null;
		
		List<Entry> entries = new ArrayList<Entry>();

		try {
			con = azureAD.createClient();
			StringBuilder uri = new StringBuilder();
			
			
			if (userPrincipalName != null) {
				uri.append("/").append(this.uriPoint).append("/")
				.append(URLEncoder.encode(userPrincipalName, "UTf-8"));
			} else {
				uri.append("/").append(this.uriPoint);
			}
			
			boolean hasParam = false;

			boolean returnAll = false;
			boolean addOC = false;
			boolean foundUserPrincipalName = false;
			boolean foundId = false;
			if (toreturn.size() == 0) {
				returnAll = true;
				addOC = true;
			} else {
				for (Attribute attr : toreturn) {
					if (attr.getAttribute().getName().equalsIgnoreCase("*")) {
						returnAll = true;
					} else if (attr.getAttribute().getName().equalsIgnoreCase("objectclass")) {
						addOC = true;
					} else if (attr.getAttribute().getName().equalsIgnoreCase(this.rdnAttribute)) {
						foundUserPrincipalName = true;
					} else if (attr.getAttribute().getName().equalsIgnoreCase("id")) {
						foundId = true;
					}
				}
			}

			if (!returnAll) {
				StringBuilder select = new StringBuilder();
				for (Attribute attr : toreturn) {
					select.append(attr.getAttribute().getName()).append(',');
				}

				
				if (! foundUserPrincipalName ) {
					select.append("userPrincipalName,");
				}
				
				if (! foundId) {
					select.append("id");
				}
				
				String selectAttrs = select.toString();
				
				
				
				selectAttrs.substring(0, selectAttrs.lastIndexOf(','));
				uri.append("?$select=").append(URLEncoder.encode(selectAttrs, "UTF-8"));
				hasParam = true;
				
				
			}
			
			if (filter != null) {
				if (hasParam) {
					uri.append("&$count=true&$filter=");
				} else {
					uri.append("?$count=true&$filter=");
				}
				
				hasParam = true;
				StringBuffer entraFilter = new StringBuffer();
				this.stringFilter(filter, entraFilter);
				uri.append(URLEncoder.encode(entraFilter.toString(),"UTF-8"));
			}

			String json = azureAD.callWS(con, uri.toString());
			
			JSONObject root = (JSONObject) new JSONParser().parse(json);

			if (root.containsKey("error")) {
				JSONObject error = (JSONObject) root.get("error");
				String code = (String) error.get("code");
				if (code.equalsIgnoreCase("Request_ResourceNotFound")) {
					throw new LDAPException(LDAPException.resultCodeToString(LDAPException.NO_SUCH_OBJECT),
							LDAPException.NO_SUCH_OBJECT,
							"Could not find user '" + userPrincipalName + "' in target '" + this.target + "'");
				} else {
					throw new ProvisioningException("Could not lookup user " + json);
				}
			} else {
				
				if (userPrincipalName != null) {
					LDAPEntry entry = generateLDAPEntry(userPrincipalName, addOC, root,azureAD,con);
					entries.add(new Entry(entry));
				} else {
					JSONArray res = (JSONArray) root.get("value");
					
					for (Object o : res) {
						JSONObject obj = (JSONObject) o;
						userPrincipalName = (String) obj.get(this.rdnAttribute);
						entries.add(new Entry(generateLDAPEntry(userPrincipalName,addOC,obj,azureAD,con)));
					}
				}
			}

		} catch (Exception e) {
			throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),
					LDAPException.OPERATIONS_ERROR,
					"Could not find user '" + userPrincipalName + "' in target '" + this.target + "'", e);
		} finally {
			if (con != null) {
				try {
					con.getHttp().close();
				} catch (IOException e) {

				}

				con.getBcm().close();
			}
		}
		
		return entries;
	}

	private LDAPEntry generateLDAPEntry(String userPrincipalName, boolean addOC, JSONObject root,AzureADProvider azureAD,HttpCon con) throws LDAPException, ProvisioningException, ClientProtocolException, IOException, ParseException {
		LDAPAttributeSet attrs = new LDAPAttributeSet();
		for (Object key : root.keySet()) {
			Object val = root.get(key);
			if (val != null) {
				LDAPAttribute attr = new LDAPAttribute(key.toString(), val.toString());
				attrs.add(attr);
			}
		}

		if (addOC) {
			attrs.add(new LDAPAttribute("objectClass", this.objectClass));
		}
		
		if (! this.users) {
			String uri = "/groups/" + (String) root.get("id") + "/members/microsoft.graph.user?$count=true&$select=userPrincipalName";
			String json = azureAD.callWS(con, uri.toString());
			
			JSONObject resp = (JSONObject) new JSONParser().parse(json);

			if (resp.containsKey("error")) {
				JSONObject error = (JSONObject) root.get("error");
				String code = (String) error.get("code");
				if (code.equalsIgnoreCase("Request_ResourceNotFound")) {
					throw new LDAPException(LDAPException.resultCodeToString(LDAPException.NO_SUCH_OBJECT),
							LDAPException.NO_SUCH_OBJECT,
							"Could not find user '" + userPrincipalName + "' in target '" + this.target + "'");
				} else {
					throw new ProvisioningException("Could not lookup user " + json);
				}
			} else {
				JSONArray res = (JSONArray) resp.get("value");
				LDAPAttribute members = new LDAPAttribute("members");
				for (Object o : res) {
					JSONObject obj = (JSONObject) o;
					String luserPrincipalName = (String) obj.get("userPrincipalName");
					members.addValue(luserPrincipalName.getBytes("UTF-8"));
				}
				
				if (members.size() > 0) {
					attrs.add(members);
				}
			}
			
		}
		
		LDAPEntry entry = new LDAPEntry(this.rdnAttribute + "=" + userPrincipalName + "," + this.base.toString(),
				attrs);
		return entry;
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

	
	private FilterNode clearOutPresence(FilterNode root) {
		
		switch (root.getType()) {
			case OR:
			case NOT:
			case AND:
				FilterNode newRoot = new FilterNode(root.getType(), new ArrayList<FilterNode>());
				for (FilterNode sub : root.getChildren()) {
					FilterNode newChild = clearOutPresence(sub);
					if (newChild != null) {
						newRoot.getChildren().add(newChild);
					}
				}
				
				if (newRoot.getChildren().size() > 0) {
					return newRoot;
				} else {
					return null;
				}
			case PRESENCE:
				return null;
			default:
				return new FilterNode(root.getType(),root.getName(),root.getValue());
				
		}
	}
	
	private String stringFilter(FilterNode root, StringBuffer filter) throws LDAPException {
		FilterType op;
		// filter.append('(');
		String comp = null;
		ArrayList<FilterNode> children;
		Iterator<FilterNode> filterIt;
		String attribName = null;

		boolean isFirst = true;

		op = root.getType();
		switch (op) {
		case AND:

			HashMap<String, ArrayList<FilterNode>> attribs = new HashMap<String, ArrayList<FilterNode>>();
			// first sort the nodes into "buckets"
			children = root.getChildren();
			
			for (FilterNode node : children) {
				
				if (node.getType() == FilterType.AND) {
					ArrayList<FilterNode> ands = attribs.get("&");
					if (ands == null) {
						ands = new ArrayList<FilterNode>();
						attribs.put("&", ands);
					}
					ands.add(node);
				} else if (node.getType() == FilterType.OR) {
					ArrayList<FilterNode> ors = attribs.get("|");
					if (ors == null) {
						ors = new ArrayList<FilterNode>();
						attribs.put("|", ors);
					}
					ors.add(node);
				} else if (node.getType() == FilterType.NOT) {
					ArrayList<FilterNode> nots = attribs.get("!");
					if (nots == null) {
						nots = new ArrayList<FilterNode>();
						attribs.put("!", nots);
					}
					nots.add(node);
				} else {

					ArrayList<FilterNode> attribNodes = attribs.get(node.getName().toLowerCase());
					if (attribNodes == null) {
						attribNodes = new ArrayList<FilterNode>();
						attribs.put(node.getName(), attribNodes);
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
						stringFilter(itNodes.next(), filter);
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
						stringFilter(itNodes.next(), filter);
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
						stringFilter(itNodes.next(), filter);
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
						stringFilter(itNodes.next(), filter);
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
				stringFilter(filterIt.next(), filter);
				if (filterIt.hasNext()) {
					filter.append(" OR ");
				}
			}
			filter.append(" ) ");
			break;

		case NOT:
			filter.append(" NOT ( ");
			stringFilter(root.getNot(), filter);
			filter.append(" ) ");

			break;
		case EQUALS: {
			if (root.getName().equalsIgnoreCase("objectclass")) {
				filter.append(" 1=1 ");
			} else {
				attribName = root.getName();

				if (attribName == null) {
					filter.append(" 1 eq 0 ");
				} else {

					filter.append(attribName);
					filter.append(" eq '");
					filter.append(root.getValue());
					filter.append("'");
					
				}
			}

			break;
		}
		case GREATER_THEN: {
			filter.append(attribName);
			filter.append(" gt '");
			filter.append(root.getValue());
			filter.append("'");
			break;
		}
		case LESS_THEN: {
			filter.append(attribName);
			filter.append(" lt '");
			filter.append(root.getValue());
			filter.append("'");
			break;

		}
		case PRESENCE:
			throw new LDAPException(LDAPException.resultCodeToString(LDAPException.FILTER_ERROR),LDAPException.FILTER_ERROR,"presence not supported by Entra");
		case SUBSTR: {
			
			boolean startsWith = root.getValue().endsWith("*");
			boolean endsWith = root.getValue().startsWith("*");
			
			
			if (startsWith && endsWith) {
				filter.append("contains(").append(root.getName()).append(",'").append(root.getValue().substring(1, root.getValue().length() - 1)).append("')");
			} else if (startsWith) {
				filter.append("startsWith(").append(root.getName()).append(",'").append(root.getValue().substring(0, root.getValue().length() - 1)).append("')");;
				
			} else if (endsWith) {
				filter.append("endsWith(").append(root.getName()).append(",'").append(root.getValue().substring(1)).append("')");;
				
			} else {
				throw new LDAPException(LDAPException.resultCodeToString(LDAPException.FILTER_ERROR),LDAPException.FILTER_ERROR,"'*' inside of substring search not supported by Entra, only beginning and end");
			}
			
			
			

			break;
		}
		}

		if (comp != null) {
			filter.append(')');
		}

		return attribName;
	}

}

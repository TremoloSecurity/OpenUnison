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
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.http.client.ClientProtocolException;
import org.apache.log4j.Logger;
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

public class KeyCloakInsert implements Insert {
	static Logger logger = Logger.getLogger(KeyCloakInsert.class);

	String name;
	

	NameSpace nameSpace;

	String objectClass;

	DN base;
	boolean users;
	
	String rdnAttribute;
	
	String authRealm;
	String user;
	String password;
	String userRealm;
	String clientId;
	String grantType;
	
	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public void configure(String name, Properties props, NameSpace nameSpace) throws LDAPException {
		this.name = name;
		this.nameSpace = nameSpace;

		
		this.objectClass = props.getProperty("objectClass");

		this.base = new DN(nameSpace.getBase().getDN().toString());

		String isusers = props.getProperty("users");
		this.users = isusers == null || isusers.equalsIgnoreCase("true");
		
		if (this.users) {
			
			this.rdnAttribute = "id";
		} else {
			
			this.rdnAttribute = props.getProperty("rdnAttribute");
		}
		
		this.authRealm = props.getProperty("authRealm");
		this.user = props.getProperty("user");
		this.password = props.getProperty("password");
		this.userRealm = props.getProperty("userRealm");
		this.clientId = props.getProperty("clientId");
		this.grantType = props.getProperty("grantType");
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

	
	private String getAccessToken() throws IOException, InterruptedException, ParseException {
		HttpClient http = HttpClient.newBuilder().build();
		try {
        HttpRequest authTokenRequest = HttpRequest.newBuilder()
                                      .uri(URI.create(String.format("%s/protocol/openid-connect/token", this.authRealm)))
                                      .header("Content-Type", "application/x-www-form-urlencoded")
                                      .POST(BodyPublishers.ofString(String.format("client_id=%s&username=%s&password=%s&grant_type=%s",
                                    		  URLEncoder.encode(this.clientId, "UTF-8"),
                                    		  URLEncoder.encode(this.user, "UTF-8"),
                                    		  URLEncoder.encode(this.password, "UTF-8"),
                                    		  URLEncoder.encode(this.grantType, "UTF-8"), "UTF-8" ) ))
                                      .build();
        
        HttpResponse<String> response = http.send(authTokenRequest, BodyHandlers.ofString());
        
        if (response.statusCode() != 200) {
        	logger.warn(String.format("Could not get token from %s: %s/%s", this.authRealm, response.statusCode(), response.body()));
        	return null;
        } else {
        	JSONObject root =  (JSONObject) new JSONParser().parse(response.body());
        	return (String) root.get("access_token");
        }
        
        
		} finally {
			
		}
        
	}
	
	@Override
	public void search(SearchInterceptorChain chain, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		
		
		List<FilterNode> searches = new ArrayList<FilterNode>(); 
		this.filter2params(filter.getRoot(), searches);

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
					if (!rdn.getType().equalsIgnoreCase("id")) {
						throw new LDAPException("Unsupported", LDAPException.UNWILLING_TO_PERFORM,
								LDAPException.resultCodeToString(LDAPException.UNWILLING_TO_PERFORM));
					}
					
					upn = rdn.getValue();
				} /*else {
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
				}*/

				

			

				

				chain.addResult(results, new IteratorEntrySet(this.lookupUser(upn, filter,null).iterator()), base, scope, filter, attributes,
						typesOnly, constraints);
				return;

			}

		} else {
			
			List<Entry> searchResults = new ArrayList<Entry>();
			
			for (FilterNode search : searches) {
				searchResults.addAll(this.lookupUser(null, filter, search));
			}
			
			chain.addResult(results, new IteratorEntrySet(searchResults.iterator()), base, scope, filter, attributes,
					typesOnly, constraints);
			
		}

	}

	private List<Entry> lookupUser(String userPrincipalName, Filter filter,FilterNode search) throws LDAPException {
		HttpCon con = null;
		
		List<Entry> entries = new ArrayList<Entry>();
		String uri;
		if (userPrincipalName != null) {
			// base search by id
			uri = String.format("%s/users/%s", this.userRealm,userPrincipalName);
		} else {
			if (search != null) {
				try {
					uri = String.format("%s/users?%s=%s", this.userRealm,search.getName(),URLEncoder.encode(search.getValue(), "UTF-8"));
				} catch (UnsupportedEncodingException e) {
					throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),LDAPException.OPERATIONS_ERROR,"sould not search keycloak",e);
				}
			} else {
				uri = String.format("%s/users", this.userRealm);
			}
		}
		
		HttpClient http = HttpClient.newBuilder().build();
		HttpResponse<String> response = null;
		try {
			HttpRequest kcRequest = HttpRequest.newBuilder()
                .uri(URI.create(uri))
                .header("Content-Type", "application/json")
                .header("Authorization", String.format("Bearer %s", this.getAccessToken()))
                .GET()
                .build();

		
			response = http.send(kcRequest, BodyHandlers.ofString());
		} catch (IOException | InterruptedException | ParseException e) {
			throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),LDAPException.OPERATIONS_ERROR,"sould not search keycloak",e);
		}
		
		if (response.statusCode() != 200) {
			if (response.statusCode() == 404) {
				throw new LDAPException(LDAPException.resultCodeToString(LDAPException.NO_SUCH_OBJECT),LDAPException.NO_SUCH_OBJECT,String.format("unable to find %s", userPrincipalName));
			} else {
				throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),LDAPException.OPERATIONS_ERROR,String.format("%s/%s",response.statusCode(),response.body()));
			}
		} else {
			try {
				JSONParser parser = new JSONParser();
				if (userPrincipalName != null) {
					JSONObject root =  (JSONObject) parser.parse(response.body());
					Entry entry = new Entry(this.generateLDAPEntry(userPrincipalName, root));
					if (filter.getRoot().checkEntry(entry.getEntry())) {
						entries.add(entry);
					}
					
				} else {
					JSONArray ret = (JSONArray) parser.parse(response.body());
					for (Object o : ret) {
						JSONObject root =  (JSONObject) o;
						Entry entry = new Entry(this.generateLDAPEntry(userPrincipalName, root));
						if (filter.getRoot().checkEntry(entry.getEntry())) {
							entries.add(entry);
						}
					}
				}
				
				
				
			} catch (ParseException | ProvisioningException | IOException e) {
				throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),LDAPException.OPERATIONS_ERROR,"sould not search keycloak",e);
			}
			
		}
		
		
		return entries;
	}

	private LDAPEntry generateLDAPEntry(String userPrincipalName, JSONObject root) throws LDAPException, ProvisioningException, ClientProtocolException, IOException, ParseException {
		LDAPAttributeSet attrs = new LDAPAttributeSet();
		for (Object key : root.keySet()) {
			Object val = root.get(key);
			if (val != null) {
				LDAPAttribute attr = new LDAPAttribute(key.toString(), val.toString());
				attrs.add(attr);
			}
		}

		
		attrs.add(new LDAPAttribute("objectClass", this.objectClass));
		
		if (userPrincipalName == null) {
			userPrincipalName = (String) root.get("id");
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

	
	
	private void filter2params(FilterNode root,List<FilterNode> params ) {
		switch (root.getType()) {
			case OR:
			case AND:
			case NOT:
				for (FilterNode child : root.getChildren()) {
					filter2params(child,params);
				}
				break;
			default:
				if (root.getName().equalsIgnoreCase("firstname") || root.getName().equalsIgnoreCase("lastname") || root.getName().equalsIgnoreCase("email") || root.getName().equalsIgnoreCase("username") ) {
					params.add(root);
				}
		}
	}
	
	

}

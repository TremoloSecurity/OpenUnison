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

package com.tremolosecurity.myvd;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.google.gson.Gson;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningTarget;
import com.tremolosecurity.provisioning.targets.RbacBindingsTarget;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;
import com.tremolosecurity.unison.openshiftv3.model.users.User;
import com.tremolosecurity.k8s.model.Binding;

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

public class AddClusterBindingsAsAttribute implements Insert {
	
	static Logger logger = Logger.getLogger(AddClusterBindingsAsAttribute.class);
	
	String name;
	String lookupByAttribute;
	String attributeToAdd;
	String labelAnnotation;
	String target;
	String namespace;
	
	boolean json;
	
	Gson gson;
	
	@Override
	public String getName() {
		return name;
	}

	@Override
	public void configure(String name, Properties props, NameSpace nameSpace) throws LDAPException {
		this.name = name;
		
		this.lookupByAttribute = props.getProperty("lookupByAttribute");
		this.attributeToAdd = props.getProperty("attributeToAdd");
		this.labelAnnotation = props.getProperty("labelAnnotation");
		this.target = props.getProperty("target");
		this.namespace = props.getProperty("namespace");
		
		if (props.get("json") != null) {
			this.json = props.get("json").equals("true");
		} else {
			this.json = false;
		}
		
		this.gson = new Gson();

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
		HttpCon con = null;
		
		JSONArray jsonRes = new JSONArray();
		
		try {
			
			if (entry.getEntry().getAttribute(this.lookupByAttribute) == null) {
				logger.warn(String.format("Could not find attribute %s for %s",this.lookupByAttribute,entry.getEntry().getDN()));
				return;
			}
			
			LDAPAttribute attrToAdd = new LDAPAttribute(this.attributeToAdd);
			
			String searchByAttrValue = entry.getEntry().getAttribute(this.lookupByAttribute).getStringValue();
			
			ProvisioningTarget t = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(target);
			if (t == null) {
				logger.warn(String.format("Can not load target %s",this.target));
				return;
			}
			
			OpenShiftTarget k8s = (OpenShiftTarget) t.getProvider();
			
			String uri = String.format("/apis/openunison.tremolo.io/v1/namespaces/%s/targets",this.namespace);
			
			logger.info("Searching uri " + uri);
			
			con = k8s.createClient();
			
			JSONObject targets = (JSONObject) new JSONParser().parse(k8s.callWS(k8s.getAuthToken(), con, uri));
			
			JSONArray items = (JSONArray) targets.get("items");
			if (items == null) {
				logger.warn(String.format("Not able to load %s, %s", uri,targets.toString()));
				return;
			}
			
			Map<String,Map<String,Binding>> bindings = new HashMap<String,Map<String,Binding>>();
			
			for (Object o : items) {
				logger.info("Target: " + o.toString());
				JSONObject target = (JSONObject) o;
				JSONObject metadata = (JSONObject) target.get("metadata");
				JSONObject spec = (JSONObject) target.get("spec");
				
				String className = (String) spec.get("className");
				if (className.equals("com.tremolosecurity.provisioning.targets.RbacBindingsTarget")) {
					logger.info("found rbac target");
					String label = (String) metadata.get("name");
					JSONObject annotations = (JSONObject) metadata.get("annotations");
					if (annotations != null) {
						logger.info("found annotations");
						String localLabel = (String) annotations.get(this.labelAnnotation);
						if (localLabel != null) {
							logger.info("found " + this.labelAnnotation + " / " + localLabel);
							label = localLabel;
						}
					}
					
					RbacBindingsTarget cluster = (RbacBindingsTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget((String)metadata.get("name")).getProvider();
					Map<String,Object> request = new HashMap<String,Object>();
					com.tremolosecurity.provisioning.core.User fromTarget = cluster.findUser(searchByAttrValue, new HashSet<String>(), request);
					if (fromTarget != null) {
						for (String group : fromTarget.getGroups()) {
							if (this.json) {
								JSONObject obj = new JSONObject();
								obj.put("Cluster", label);
								if (group.startsWith("rb")) {
									int begin = group.indexOf(':');
									int end = group.indexOf(':',begin + 1);
									obj.put("Namespace", group.substring(begin + 1,end));
									obj.put("Binding", group.substring(end + 1));
								} else {
									obj.put("Namespace", "N/A");
									obj.put("Binding", group.substring(group.indexOf(':') + 1));
									
								}
								
								jsonRes.add(obj);
							} else {
								attrToAdd.addValue(String.format("%s:%s", (String) metadata.get("name"),group));
							}
							
						}
						
						bindings.put((String)metadata.get("name"), (Map<String, Binding>) request.get(RbacBindingsTarget.USER_BINDINGS));
					}
				}
				
			}
			
			if (this.json) {
				if (jsonRes.size() > 0) {
					attrToAdd.addValue(jsonRes.toString().getBytes("UTF-8"));
				} else {
					attrToAdd.addValue("[]".getBytes("UTF-8"));
				}
			}
			
			if (attrToAdd.getAllValues().size() > 0) {
				
				
				entry.getEntry().getAttributeSet().add(attrToAdd);
				LDAPAttribute bindingsAttr = new LDAPAttribute(new StringBuilder().append(this.attributeToAdd).append("-bindings").toString());
				bindingsAttr.addValue(gson.toJson(bindings));
				entry.getEntry().getAttributeSet().add(bindingsAttr);
			}
			
		} catch (Exception e) {
			throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),LDAPException.OPERATIONS_ERROR,"Unable to add clsuter rbac",e);
		} finally {
			if (con != null) {
				try {
					con.getHttp().close();
				} catch (IOException e) {
					
				}
				
				con.getBcm().close();
			}
		}
		
		

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

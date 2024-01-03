/*******************************************************************************
 * Copyright (c) 2024 Tremolo Security, Inc.
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

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.StringTokenizer;

import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import com.google.common.collect.ComparisonChain;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.tremolosecurity.myvd.dataObj.RoleInfo;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningTarget;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

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

public class AddPortalRolesAsAttribute implements Insert {
	
	static Logger logger = Logger.getLogger(AddPortalRolesAsAttribute.class.getName());
	
	String name;
	
	NameSpace nameSpace;
	
	Map<String,RoleInfo> roles;
	String extSuffix;
	String intSuffix;
	
	String k8sTargetName;
	
	Map<String,String> role2label;
	
	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public void configure(String name, Properties props, NameSpace nameSpace) throws LDAPException {
		this.name = name;
		this.nameSpace = nameSpace;
		
		this.roles = new HashMap<String,RoleInfo>();
		
		this.extSuffix = props.getProperty("extSuffix");
		this.intSuffix = props.getProperty("intSuffix");
		
		this.k8sTargetName = props.getProperty("k8sTargetName");
		
		this.role2label = new HashMap<String,String>();
		String role2labelCfg = props.getProperty("role2label");
		
		StringTokenizer toker = new StringTokenizer(role2labelCfg,",",false);
		while (toker.hasMoreTokens()) {
			String token = toker.nextToken();
			int eq = token.indexOf('=');
			if (eq > 0) {
				String role = token.substring(0,eq);
				String label = token.substring(eq+1);
				this.role2label.put(role, label);
			}
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
	
	OpenShiftTarget findTarget(String name) throws ProvisioningException {
		if (logger.isDebugEnabled()) logger.debug(String.format("looking for target '%s'", name));
		ProvisioningTarget target = null;
		
		try {
			target = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(name);
		} catch (ProvisioningException e) {
			
		}
		
		int lastDash = name.lastIndexOf('-');
		
		while (target == null && lastDash > 0) {
			
			if (lastDash > 0) {
				name = name.substring(0,lastDash);
				if (logger.isDebugEnabled()) logger.debug(String.format("looking for target '%s'", name));
				try {
					target = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(name);
				} catch (ProvisioningException e) {
					lastDash = name.lastIndexOf('-');
				}
				
			} 
		}
		
		if (target != null) {
			if (logger.isDebugEnabled()) logger.debug("found target");
			return (OpenShiftTarget) target.getProvider();
		} else {
			if (logger.isDebugEnabled()) logger.debug("can't find target");
			return null;
		}
	}
	
	private RoleInfo loadRoleInfo(String roleName) throws ProvisioningException {
		if (logger.isDebugEnabled()) logger.debug(String.format("Looking for role '%s'", roleName));
		RoleInfo role = this.roles.get(roleName);
		if (role != null) {
			if (logger.isDebugEnabled()) logger.debug("found and returning");
			return role;
		} else {
			if (roleName.startsWith("k8s-")) {
				if (logger.isDebugEnabled()) logger.debug("roleName starts with k8s-");
				if (roleName.startsWith("k8s-cluster-")) {
					if (logger.isDebugEnabled()) logger.debug("roleName starts with k8s-cluster-");
					
					// lookup cluster
					String localName = roleName;
					if (localName.endsWith(extSuffix)) {
						localName = localName.substring(0,localName.lastIndexOf(extSuffix));
					} else if (localName.endsWith(this.intSuffix)) {
						localName = localName.substring(0,localName.lastIndexOf(this.intSuffix));
					}
					
					if (logger.isDebugEnabled()) logger.debug(String.format("localName without suffix '%s'", localName));
					
					
					localName = localName.substring("k8s-cluster-".length());
					
					if (logger.isDebugEnabled()) logger.debug(String.format("localName without prefix '%s'", localName));
					
					OpenShiftTarget target = this.findTarget(localName);
					if (target != null) {
						
						if (logger.isDebugEnabled()) logger.debug("Found target");
						
						String clusterLabel = target.getLabel();
						String roleLabel = localName.substring(target.getName().length() + 1);
						
						role = new RoleInfo(Character.toUpperCase(roleLabel.charAt(0)) + roleLabel.substring(1),clusterLabel,"N/A");
						this.roles.put(roleName, role);
						return role;
					} else {
						role = new RoleInfo(roleName,"N/A","N/A");
						return role;
					}
					
					
				} else if (roleName.startsWith("k8s-namespace-")) {
					String localName = roleName;
					if (localName.endsWith(extSuffix)) {
						localName = localName.substring(0,localName.lastIndexOf(extSuffix));
					} else if (localName.endsWith(this.intSuffix)) {
						localName = localName.substring(0,localName.lastIndexOf(this.intSuffix));
					}
					
					localName = localName.substring("k8s-namespace-".length());
					String roleCfgNameFound = null;
					for (String roleCfgName : this.role2label.keySet()) {
						if (localName.startsWith(roleCfgName)) {
							roleCfgNameFound = roleCfgName;
							break;
						}
					}
					
					if (roleCfgNameFound == null) {
						role = new RoleInfo(roleName,"N/A","N/A");
						return role;
					}
					
					localName = localName.substring(roleCfgNameFound.length() + 1);
					
					OpenShiftTarget target = null;
					
					try {
						target = this.findTarget(localName);
					} catch (ProvisioningException e) {
						target = null;
					}
					
					if (target != null) {
						String clusterLabel = target.getLabel();
						String namespace = localName.substring(target.getName().length() + 1);
						role = new RoleInfo(this.role2label.get(roleCfgNameFound),clusterLabel,namespace);
						this.roles.put(roleName, role);
						return role;
					} else {
						role = new RoleInfo(roleName,"N/A","N/A");
						return role;
					}
					
				}
			} else if (roleName.startsWith("approvers-k8s-")) {
				// approvers-k8s-cluster-ns
				String localName = roleName.substring("approvers-".length());
				if (localName.startsWith("k8s-k8s-")) {
					localName = localName.substring("k8s-".length());
				}
				OpenShiftTarget target = this.findTarget(localName);
				if (target != null) {
					String clusterLabel = target.getLabel();
					String namespace = localName.substring(target.getName().length() + 1);
					role = new RoleInfo("Approver",clusterLabel,namespace);
					this.roles.put(roleName, role);
					return role;
				} else {
					role = new RoleInfo(roleName,"N/A","N/A");
					return role;
				}
				
			} else {
				role = new RoleInfo(roleName,"N/A","N/A");
				this.roles.put(roleName, role);
				return role;
			}
		}
		
		// no cfg found
		role = new RoleInfo(roleName,"N/A","N/A");
		return role;
	}

	@Override
	public void postSearchEntry(PostSearchEntryInterceptorChain chain, Entry entry, DistinguishedName base, Int scope,
			Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints)
			throws LDAPException {
		chain.nextPostSearchEntry(entry, base, scope, filter, attributes, typesOnly, constraints);
		
		
		LDAPAttribute groups = entry.getEntry().getAttribute("groups");
		
		if (groups != null) {
			LDAPAttribute portalGroups = new LDAPAttribute("portalGroups");
			JSONArray portalGroupVals = new JSONArray();
			List<RoleInfo> sortedRoles = new ArrayList<RoleInfo>();
			String[] vals = groups.getStringValueArray();
			for (String group : vals) {
				RoleInfo ri = this.roles.get(group);
				if (ri == null) {
					try {
						ri = this.loadRoleInfo(group);
					} catch (ProvisioningException e) {
						throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),LDAPException.OPERATIONS_ERROR,"unable to load role " + group,e);
					}
				}
				
				
				sortedRoles.add(ri);
			}
			
			try {
				
				Collections.sort(sortedRoles, new Comparator<RoleInfo>() {
					@Override
					public int compare(RoleInfo o1, RoleInfo o2) {
						return ComparisonChain.start()
								.compare(o1.getCluster(), o2.getCluster())
								.compare(o1.getNamespace(), o2.getNamespace())
								.compare(o1.getName(), o2.getName())
								.result();
					}
				});
				
				for (RoleInfo ri : sortedRoles) {
					portalGroupVals.add(ri.toJSON());
				}
				
				portalGroups.addValue(portalGroupVals.toString().getBytes("UTF-8"));
			} catch (UnsupportedEncodingException e) {
				// can't happen
			}
			entry.getEntry().getAttributeSet().add(portalGroups);
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
		// TODO Auto-generated method stub

	}

}

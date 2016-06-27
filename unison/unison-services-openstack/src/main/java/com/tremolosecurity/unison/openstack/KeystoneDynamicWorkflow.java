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
package com.tremolosecurity.unison.openstack;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.WorkflowType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.util.DynamicWorkflow;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.openstack.model.KSDomain;
import com.tremolosecurity.unison.openstack.model.KSProject;
import com.tremolosecurity.unison.openstack.model.KSRole;
import com.tremolosecurity.unison.openstack.model.token.Project;

public class KeystoneDynamicWorkflow implements DynamicWorkflow {

	@Override
	public List<Map<String, String>> generateWorkflows(WorkflowType wf, ConfigManager cfg,
			HashMap<String, Attribute> params) throws ProvisioningException {
		String targetName = params.get("targetName").getValues().get(0);
		String targetScope = params.get("targetScope").getValues().get(0);
		boolean includeRoles = params.get("includeRoles").getValues().get(0).equalsIgnoreCase("true");
		
		String roleFilterMode = params.get("roleFilterMode").getValues().get(0);
		String targetFilterMode = params.get("targetFilterMode").getValues().get(0);
		
		HashSet<String> roleFilter = new HashSet<String>();
		HashSet<String> targetFilter = new HashSet<String>();
		
		if (params.get("filterRoles") != null) {
			roleFilter.addAll(params.get("filterRoles").getValues());
		}
		
		if (params.get("filterTargets") != null) {
			targetFilter.addAll(params.get("filterTargets").getValues());
		}
		
		
		boolean doFilterRoles = ! roleFilterMode.equalsIgnoreCase("none");
		boolean roleFilterExclude = roleFilterMode.equalsIgnoreCase("exclude");
		
		boolean doFilterTargets = ! targetFilterMode.equalsIgnoreCase("none");
		boolean targetFilterExclude = targetFilterMode.equalsIgnoreCase("exclude");
		
		
		ArrayList<Map<String,String>> workflows = new ArrayList<Map<String,String>>();
		
		List<Map<Object,Object>> domains = null;
		List<Map<Object,Object>> projects = null;
		List<Map<Object,Object>> roles = null;
		
		KeystoneProvisioningTarget target = (KeystoneProvisioningTarget) cfg.getProvisioningEngine().getTarget(targetName).getProvider();
		
		if (target == null) {
			throw new ProvisioningException("Target " + targetName + " not found");
		}
		
		if (targetScope != null && targetScope.equalsIgnoreCase("domains")) {
			domains = target.listDomains();
		} 
		
		if (targetScope != null && targetScope.equalsIgnoreCase("projects")) {
			projects = target.listProjects();
		} 
		
		if (includeRoles) {
			roles = target.listRoles();
		} 
		
		StringBuffer b = new StringBuffer();
		
		if (includeRoles) {
			for (Map<Object,Object> role : roles) {
				
				if (doFilterRoles) {
					String name = (String) role.get("name");
					if (roleFilterExclude && roleFilter.contains(name)) {
						continue;
					} else if (!roleFilterExclude && !roleFilter.contains(name))  {
						continue;
					}
				}
				
				HashMap<String,String> wfParams = new HashMap<String,String>();
				
				
				for (Object key : role.keySet()) {
					b.setLength(0);
					b.append("role_").append(key);
					String val = "";
					if (role.get(key) != null) {
						val = role.get(key).toString();
					}
					wfParams.put(b.toString().replace("-", "_").replace(".", "_"), val);
				}
				
				boolean addWF = true;
				
				
				if (!addDomainParams(workflows, domains, b, wfParams, addWF,doFilterTargets,targetFilterExclude,targetFilter)) {
					addWF = false;
				}
				
				if (!addProjectParams(workflows, projects, b, wfParams, addWF,doFilterTargets,targetFilterExclude,targetFilter,target)) {
					addWF = false;
				}
				
				if (addWF) {
					workflows.add(wfParams);
				}
				
				
			} 
			
			
		} else {
			addDomainParams(workflows, domains, b, null, false,doFilterTargets,targetFilterExclude,targetFilter);
			addProjectParams(workflows, projects, b, null, false,doFilterTargets,targetFilterExclude,targetFilter,target);
		}
		
		return workflows;
		
	}

	private boolean addDomainParams(ArrayList<Map<String, String>> workflows, List<Map<Object, Object>> domains,
			StringBuffer b, HashMap<String, String> wfParams, boolean addWF,boolean doFilterTargets,boolean targetFilterExclude,HashSet<String> targetFilter) {
		if (domains != null) {
			addWF = false;
			for (Map<Object,Object> domain : domains) {
				
				if (doFilterTargets) {
					String name = (String) domain.get("id");
					if (targetFilterExclude && targetFilter.contains(name)) {
						continue;
					} else if (!targetFilterExclude && !targetFilter.contains(name))  {
						continue;
					}
				}
				
				HashMap<String,String> wfParamsLocal = new HashMap<String,String>();
				
				if (wfParams != null) {
					wfParamsLocal.putAll(wfParams);
				}
				
				for (Object key : domain.keySet()) {
					b.setLength(0);
					b.append("domain_").append(key);
					String val = "";
					if (domain.get(key) != null) {
						val = domain.get(key).toString();
					}
					wfParamsLocal.put(b.toString().replace("-", "_").replace(".", "_"), val);
					
				}
				
				workflows.add(wfParamsLocal);
			}
		}
		return addWF;
	}

	private boolean addProjectParams(ArrayList<Map<String, String>> workflows, List<Map<Object, Object>> projects,
			StringBuffer b, HashMap<String, String> wfParams, boolean addWF,boolean doFilterTargets,boolean targetFilterExclude,HashSet<String> targetFilter, KeystoneProvisioningTarget target) throws ProvisioningException {
		
		HashMap<String,String> domainId2Name = new HashMap<String,String>();
		
		if (projects != null) {
			addWF = false;
			for (Map<Object,Object> project : projects) {
				
				if (doFilterTargets) {
					String name = (String) project.get("id");
					if (targetFilterExclude && targetFilter.contains(name)) {
						continue;
					} else if (!targetFilterExclude && !targetFilter.contains(name))  {
						continue;
					}
				}
				
				HashMap<String,String> wfParamsLocal = new HashMap<String,String>();
				if (wfParams != null) {
					wfParamsLocal.putAll(wfParams);
				}
				
				for (Object key : project.keySet()) {
					b.setLength(0);
					b.append("project_").append(key);
					String val = "";
					if (project.get(key) != null) {
						val = project.get(key).toString();
					}
					wfParamsLocal.put(b.toString().replace("-", "_").replace(".", "_"), val);
				}
				
				String domainID = wfParamsLocal.get("project_domain_id");
				String domainName = domainId2Name.get(domainID);
				if (domainName == null) {
					domainName = target.getDomainName(domainID);
					domainId2Name.put(domainID, domainName);
				}
				
				wfParamsLocal.put("project_domain_name", domainName);
				
				workflows.add(wfParamsLocal);
			}
		}
		return addWF;
	}

}

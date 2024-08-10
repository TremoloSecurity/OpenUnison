/*
Copyright 2015, 2018 Tremolo Security, Inc.

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


package com.tremolosecurity.proxy.az;

import java.io.ByteArrayOutputStream;
import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.apache.logging.log4j.Logger;


import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.util.JsonTools;



public class AzRule  {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AzRule.class.getName());
	private static HashSet<UUID> usedGUIDS = new HashSet<UUID>();
	
	
	private static Map<String,Set<AzRule>> customRules;  
	
	public enum ScopeType {
		Group,
		DynamicGroup,
		DN,
		Filter,
		Custom
	};
	
	private ScopeType scope;
	private String constraint;
	private UUID guid;
	private String className;
	private CustomAuthorization customAz;

	private String[] customParams;
	
	
	static {
		customRules = new HashMap<String,Set<AzRule>>();
	}
	
	public AzRule(String scopeType,String constraint, String className,ConfigManager cfgMgr,Workflow wf) throws ProvisioningException {
		if (scopeType.equalsIgnoreCase("group")) {
			scope = ScopeType.Group;
		} else if (scopeType.equalsIgnoreCase("dynamicGroup")) {
			scope = ScopeType.DynamicGroup;
		} else if (scopeType.equalsIgnoreCase("dn")) {
			scope = ScopeType.DN;
		} else if (scopeType.equalsIgnoreCase("custom")) {
			 scope = ScopeType.Custom;
			 
			 if (constraint.contains("!")) {
				String[] vals = constraint.split("[!]");
				this.customParams = new String[vals.length - 1];
				constraint = vals[0];

				for (int i=0;i<this.customParams.length;i++) {
					this.customParams[i] = vals[i+1];
 				}
			 } else {
				 this.customParams = new String[0];
			 }
		 	
			CustomAuthorization caz = cfgMgr.getCustomAuthorizations().get(constraint);
			
			if (caz == null) {
				logger.warn("Could not find custom authorization rule : '" + className + "'");
				caz = new AlwaysFail();
			}
			
			
			String json = JsonTools.writeObjectToJson(caz);
			
			this.customAz = (CustomAuthorization) JsonTools.readObjectFromJson(json);
			
			synchronized (customRules) {
				Set<AzRule> azRules = customRules.get(constraint);
				if (azRules == null) {
					azRules = new HashSet<AzRule>();
					customRules.put(constraint, azRules);
				}
				azRules.add(this);
			}
			
			try {
				this.customAz.setWorkflow(wf);
			} catch (AzException e) {
				throw new ProvisioningException("Can not set workflow",e);
			}
		} else if (scopeType.equalsIgnoreCase("filter")) {
			scope = ScopeType.Filter;
		}
		
		this.constraint = constraint;
		this.guid = UUID.randomUUID();
		this.className = className;
		
		while (usedGUIDS.contains(guid)) {
			this.guid = UUID.randomUUID();
		}
		
		
		

		
	}

	public ScopeType getScope() {
		return scope;
	}

	public String getConstraint() {
		return constraint;
	}

	public UUID getGuid() {
		return guid;
	}

	public String getClassName() {
		return className;
	}
	
	public CustomAuthorization getCustomAuthorization() {
		return this.customAz;
	}
	
	public void setCustomAuthorization(CustomAuthorization caz) {
		this.customAz = caz;
	}

	public String[] getCustomParameters() {
		return this.customParams;
	}
	
	public static void replaceCustomAuthorization(String name,CustomAuthorization caz) {
		Set<AzRule> azRules = customRules.get(name);
		
		if (azRules == null) {
			logger.warn("Custom rule '" + name + "' not referenced by any authorization rules");
			return;
		}
		
		
		
		for (AzRule rule : azRules) {
			synchronized (rule) {
				String json = JsonTools.writeObjectToJson(caz);
				CustomAuthorization newCazInstance = (CustomAuthorization) JsonTools.readObjectFromJson(json);
				try {
					newCazInstance.setWorkflow(rule.getCustomAuthorization().getWorkflow());
				} catch (AzException e) {
					logger.warn("Could not set workflow on '" + name +"' replacement",e);
				}
				rule.setCustomAuthorization(newCazInstance);
			}
			
			
		}
	}
	
	public static void deleteCustomAuthorization(String name) {
		Set<AzRule> azRules = customRules.get(name);
		
		if (azRules == null) {
			logger.warn("Custom rule '" + name + "' not referenced by any authorization rules");
			return;
		}
		
		
		
		for (AzRule rule : azRules) {
			synchronized (rule) {
				
				CustomAuthorization newCazInstance = new AlwaysFail();
				try {
					newCazInstance.setWorkflow(rule.getCustomAuthorization().getWorkflow());
				} catch (AzException e) {
					logger.warn("Could not set workflow on '" + name +"' replacement",e);
				}
				rule.setCustomAuthorization(newCazInstance);
			}
			
			
		}
	}
	
}

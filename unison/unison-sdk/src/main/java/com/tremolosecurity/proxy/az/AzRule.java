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


package com.tremolosecurity.proxy.az;

import java.io.Serializable;
import java.util.HashSet;
import java.util.UUID;

import org.apache.logging.log4j.Logger;

import com.cedarsoftware.util.io.JsonReader;
import com.cedarsoftware.util.io.JsonWriter;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.Workflow;



public class AzRule  {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AzRule.class.getName());
	private static HashSet<UUID> usedGUIDS = new HashSet<UUID>();
	
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
	
	public AzRule(String scopeType,String constraint, String className,ConfigManager cfgMgr,Workflow wf) throws ProvisioningException {
		if (scopeType.equalsIgnoreCase("group")) {
			scope = ScopeType.Group;
		} else if (scopeType.equalsIgnoreCase("dynamicGroup")) {
			scope = ScopeType.DynamicGroup;
		} else if (scopeType.equalsIgnoreCase("dn")) {
			scope = ScopeType.DN;
		} else if (scopeType.equalsIgnoreCase("custom")) {
		 	scope = ScopeType.Custom;
		 	
			CustomAuthorization caz = cfgMgr.getCustomAuthorizations().get(constraint);
			
			if (caz == null) {
				logger.warn("Could not find custom authorization rule : '" + className + "'");
			}
			
			String json = JsonWriter.objectToJson(caz);
			this.customAz = (CustomAuthorization) JsonReader.jsonToJava(json);
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
	
}

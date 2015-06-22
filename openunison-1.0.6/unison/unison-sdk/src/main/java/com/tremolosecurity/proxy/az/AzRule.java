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



public class AzRule implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = -6133851789320540298L;
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
	
	public AzRule(String scopeType,String constraint, String className) {
		if (scopeType.equalsIgnoreCase("group")) {
			scope = ScopeType.Group;
		} else if (scopeType.equalsIgnoreCase("dynamicGroup")) {
			scope = ScopeType.DynamicGroup;
		} else if (scopeType.equalsIgnoreCase("dn")) {
			scope = ScopeType.DN;
		} else if (scopeType.equalsIgnoreCase("custom")) {
		 	scope = ScopeType.Custom;
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
	
	
	
}

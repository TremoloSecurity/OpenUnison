/*
Copyright 2015, 2016 Tremolo Security, Inc.

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


package com.tremolosecurity.provisioning.service.util;

import java.util.HashMap;
import java.util.Map;

public class WFDescription {
	String name;
	String description;
	String label;
	String encryptedParams;
	String uuid;
	Map<String,String> filterAnnotations;
	
	public WFDescription() {
		this.filterAnnotations = new HashMap<String,String>();
		
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public String getLabel() {
		return label;
	}

	public void setLabel(String label) {
		this.label = label;
	}

	public String getEncryptedParams() {
		return encryptedParams;
	}

	public void setEncryptedParams(String encryptedParams) {
		this.encryptedParams = encryptedParams;
	}

	public String getUuid() {
		return uuid;
	}

	public void setUuid(String uuid) {
		this.uuid = uuid;
	}

	public Map<String, String> getFilterAnnotations() {
		return filterAnnotations;
	}

	public void setFilterAnnotations(Map<String, String> filterAnnotations) {
		this.filterAnnotations = filterAnnotations;
	}
	
	
	
	
}

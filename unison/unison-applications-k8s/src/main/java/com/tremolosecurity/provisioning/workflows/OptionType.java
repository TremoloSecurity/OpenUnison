/*******************************************************************************
 * Copyright 2020 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.workflows;

import java.util.Set;

public class OptionType {
	String name;
	
	public enum OptionValueType {
		STRING,
		INT,
		BOOLEAN
	}
	
	OptionValueType type;
	
	boolean required;
	
	Set<String> allowedValues;
	
	
	public OptionType(String name,boolean required,OptionValueType type) {
		this(name,required,type,null);
	}
	
	public OptionType(String name,boolean required,OptionValueType type,Set<String> allowedValues) {
		this.name = name;
		this.type = type;
		this.required = required;
		this.allowedValues = allowedValues;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public OptionValueType getType() {
		return type;
	}

	public void setType(OptionValueType type) {
		this.type = type;
	}

	public boolean isRequired() {
		return required;
	}

	public void setRequired(boolean required) {
		this.required = required;
	}

	public Set<String> getAllowedValues() {
		return allowedValues;
	}

	public void setAllowedValues(Set<String> allowedValues) {
		this.allowedValues = allowedValues;
	}
	
	
	
	
}

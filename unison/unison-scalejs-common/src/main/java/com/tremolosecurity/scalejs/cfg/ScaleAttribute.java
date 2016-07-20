/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
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
package com.tremolosecurity.scalejs.cfg;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.tremolosecurity.util.NVP;

public class ScaleAttribute {
	String name;
	String displayName;
	boolean readOnly;
	boolean required;
	String regEx;
	String regExFailedMsg;
	int minChars;
	int maxChars;
	boolean unique;
	String type;
	List<NVP> values;
	
	
	private transient Pattern pattern;
	
	public ScaleAttribute() {
		this.values = new ArrayList<NVP>();
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getDisplayName() {
		return displayName;
	}

	public void setDisplayName(String displayName) {
		this.displayName = displayName;
	}

	public boolean isReadOnly() {
		return readOnly;
	}

	public void setReadOnly(boolean readOnly) {
		this.readOnly = readOnly;
	}

	public boolean isRequired() {
		return required;
	}

	public void setRequired(boolean required) {
		this.required = required;
	}

	public String getRegEx() {
		return regEx;
	}

	public void setRegEx(String regEx) {
		this.regEx = regEx;
		if (regEx != null && ! regEx.isEmpty()) {
			this.pattern = Pattern.compile(regEx);
		}
	}

	public String getRegExFailedMsg() {
		return regExFailedMsg;
	}

	public void setRegExFailedMsg(String regExFailedMsg) {
		this.regExFailedMsg = regExFailedMsg;
	}

	public Pattern getPattern() {
		return pattern;
	}

	public int getMinChars() {
		return minChars;
	}

	public void setMinChars(int minChars) {
		this.minChars = minChars;
	}

	public int getMaxChars() {
		return maxChars;
	}

	public void setMaxChars(int maxChars) {
		this.maxChars = maxChars;
	}

	public boolean isUnique() {
		return unique;
	}

	public void setUnique(boolean unique) {
		this.unique = unique;
	}

	public List<NVP> getValues() {
		return values;
	}

	public void setValues(List<NVP> values) {
		this.values = values;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}
	
	
	
	
}

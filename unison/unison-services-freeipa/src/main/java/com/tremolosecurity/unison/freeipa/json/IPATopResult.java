/*******************************************************************************
 * Copyright 2015 Tremolo Security, Inc.
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
package com.tremolosecurity.unison.freeipa.json;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class IPATopResult {
	Object result;
	String summary;
	Object value;
	
	public IPATopResult() {
		this.result = new HashMap<String,Object>();
		this.value = new ArrayList<String>();
	}

	public Object getResult() {
		return result;
	}

	public void setResult(Object result) {
		this.result = result;
	}

	public String getSummary() {
		return summary;
	}

	public void setSummary(String summary) {
		this.summary = summary;
	}

	public Object getValue() {
		return value;
	}

	public void setValue(Object value) {
		this.value = value;
	}

	
	
	
}

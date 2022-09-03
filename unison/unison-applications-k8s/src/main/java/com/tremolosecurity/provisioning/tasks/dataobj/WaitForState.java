/*******************************************************************************
 * Copyright 2022 Tremolo Security, Inc.
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

package com.tremolosecurity.provisioning.tasks.dataobj;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class WaitForState implements Serializable {
	String uuid;
	String base64Workflow;
	String target;
	String uri;
	Map<String,String> conditions;
	
	public WaitForState() {
		this.conditions = new HashMap<String,String>();
	}

	public String getUuid() {
		return uuid;
	}

	public void setUuid(String uuid) {
		this.uuid = uuid;
	}

	public String getBase64Workflow() {
		return base64Workflow;
	}

	public void setBase64Workflow(String base64Workflow) {
		this.base64Workflow = base64Workflow;
	}

	public String getTarget() {
		return target;
	}

	public void setTarget(String target) {
		this.target = target;
	}

	public String getUri() {
		return uri;
	}

	public void setUri(String uri) {
		this.uri = uri;
	}

	public Map<String, String> getConditions() {
		return conditions;
	}

	public void setConditions(Map<String, String> conditions) {
		this.conditions = conditions;
	}
	
	
}

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

import com.tremolosecurity.config.xml.WorkflowTasksType;
import com.tremolosecurity.config.xml.WorkflowType;

public class ParsedWorkflow {
	String error;
	WorkflowType wft;
	String errorPath;
	
	public ParsedWorkflow() {
		this.error = null;
		this.wft = new WorkflowType();
		this.errorPath = null;
		
		this.wft.setTasks(new WorkflowTasksType());
	}

	public String getError() {
		return error;
	}

	public void setError(String error) {
		this.error = error;
	}

	public WorkflowType getWft() {
		return wft;
	}

	public String getErrorPath() {
		return errorPath;
	}

	public void setErrorPath(String errorPath) {
		this.errorPath = errorPath;
	}
	
	
	
}

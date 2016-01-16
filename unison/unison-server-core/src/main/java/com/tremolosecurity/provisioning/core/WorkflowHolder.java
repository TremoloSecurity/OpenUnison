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


package com.tremolosecurity.provisioning.core;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Stack;

import com.tremolosecurity.provisioning.util.TaskHolder;

public class WorkflowHolder implements Serializable {
	public static final String WF_HOLDER_REQUEST = "UNISON.PROV.WF_HOLDER_REQUEST";
	
	
	Stack<TaskHolder> wfStack;
	Workflow workflow;
	User user;
	HashMap<String,Object> request;
	
	public WorkflowHolder(Workflow workflow,User user,HashMap<String,Object> request) {
		this.wfStack = new Stack<TaskHolder>();
		this.workflow = workflow;
		this.user = user;
		this.request = request;
		this.request.put(WF_HOLDER_REQUEST, this);
	}

	public Stack<TaskHolder> getWfStack() {
		return wfStack;
	}

	public Workflow getWorkflow() {
		return workflow;
	}

	public User getUser() {
		return user;
	}

	public HashMap<String, Object> getRequest() {
		return request;
	}
	
	
}

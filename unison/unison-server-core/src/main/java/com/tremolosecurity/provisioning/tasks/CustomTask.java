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


package com.tremolosecurity.provisioning.tasks;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.CustomTaskType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.ParamWithValueType;
import com.tremolosecurity.config.xml.WorkflowTaskType;
import com.tremolosecurity.openunison.OpenUnisonConstants;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTaskImpl;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.util.NVP;

public class CustomTask extends WorkflowTaskImpl implements Serializable {

	String className;
	HashMap<String,Attribute> params;
	com.tremolosecurity.provisioning.util.CustomTask task;
	
	public CustomTask() {
		
	}
	
	public CustomTask(WorkflowTaskType taskConfig, ConfigManager cfg,
			Workflow wf) throws ProvisioningException {
		super(taskConfig, cfg, wf);
		
		
		
		
	}

	@Override
	public void init(WorkflowTaskType taskConfig) throws ProvisioningException {
		CustomTaskType taskCfg = (CustomTaskType) taskConfig;
		this.className = taskCfg.getClassName();
		
		
		params = new HashMap<String,Attribute>();
		for (ParamWithValueType pt : taskCfg.getParam()) {
			Attribute attr = params.get(pt.getName());
			if (attr == null) {
				attr = new Attribute(pt.getName());
				params.put(pt.getName(), attr);
			}
			if (pt.getValueAttribute() != null) {
				attr.getValues().add(pt.getValueAttribute());
			} else {
				attr.getValues().add(pt.getValue());
			}
			
		}
		

		
		try {
			this.task = (com.tremolosecurity.provisioning.util.CustomTask) Class.forName(this.className).newInstance();
			this.task.init(this, params);
		} catch (Exception e) {
			throw new ProvisioningException("Could not initialize custom task",e);
		} 

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request)
			throws ProvisioningException {
		
		
		return task.doTask(user, request);
	}

	@Override
	public void reInit() throws ProvisioningException {
		this.task.reInit(this);
	}

	@Override
	public String getLabel() {
		StringBuffer b = new StringBuffer();
		b.append("Custom Task : ").append(this.className);
		return b.toString();
	}

	public String getClassName() {
		return className;
	}

	public void setClassName(String className) {
		this.className = className;
	}

	public HashMap<String, Attribute> getParams() {
		return params;
	}

	public void setParams(HashMap<String, Attribute> params) {
		this.params = params;
	}

	public com.tremolosecurity.provisioning.util.CustomTask getTask() {
		return task;
	}

	public void setTask(com.tremolosecurity.provisioning.util.CustomTask task) {
		this.task = task;
	}

	
}

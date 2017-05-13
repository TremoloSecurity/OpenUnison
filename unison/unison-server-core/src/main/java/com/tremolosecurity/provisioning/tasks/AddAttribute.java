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

import java.util.HashMap;
import java.util.Map;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.AddAttributeType;
import com.tremolosecurity.config.xml.WorkflowTaskType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTaskImpl;
import com.tremolosecurity.saml.Attribute;

public class AddAttribute extends WorkflowTaskImpl {

	/**
	 * 
	 */
	private static final long serialVersionUID = -878014522800894726L;
	String name;
	String value;
	boolean remove;
	boolean addToRequest;
	
	public AddAttribute() {
		
	}
	
	public AddAttribute(WorkflowTaskType taskConfig, ConfigManager cfg,Workflow wf)
			throws ProvisioningException {
		super(taskConfig, cfg,wf);
		
	}

	@Override
	public void init(WorkflowTaskType taskConfig) throws ProvisioningException {
		AddAttributeType cfg = (AddAttributeType) taskConfig;
		name = cfg.getName();
		value = cfg.getValue();
		remove = cfg.isRemove();
		this.addToRequest = cfg.isAddToRequest();
	}

	@Override
	public boolean doTask(User user,Map<String,Object> request) throws ProvisioningException {
		String localName = this.renderTemplate(name, request);
		String localVal = this.renderTemplate(value, request);
		
		if (this.addToRequest) {
			if (this.remove) {
				request.remove(localName);
			} else {
				request.put(localName, localVal);
			}
		} else {
			if (this.remove) {
				Attribute attr = user.getAttribs().get(localName);
				if (attr != null) { 
					if (localVal.isEmpty()) {
						user.getAttribs().remove(localName);
					} else {
						attr.getValues().remove(localVal);
					}
				}
			} else {
				Attribute attr = user.getAttribs().get(localName);
				if (attr == null) {
					attr = new Attribute(localName);
					user.getAttribs().put(localName, attr);
				}
				attr.getValues().add(localVal);
				
			}
		}
		
		
		
		
		return true;
	}

	@Override
	public String getLabel() {
		StringBuffer b = new StringBuffer();
		b.append("Add attribute ").append(this.name).append(" = ").append(this.value);
		return b.toString();
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}

}

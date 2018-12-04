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


package com.tremolosecurity.provisioning.tasks;

import java.util.Map;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.MappingType;
import com.tremolosecurity.config.xml.WorkflowTaskType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTaskImpl;
import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.saml.Attribute;

public class Mapping extends WorkflowTaskImpl {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(Mapping.class.getName());
	/**
	 * 
	 */
	private static final long serialVersionUID = -3950236095138126621L;
	MapIdentity mapper;
	boolean strict;
	
	public Mapping() {
		
	}
	
	public Mapping(WorkflowTaskType taskConfig, ConfigManager cfg,Workflow wf)
			throws ProvisioningException {
		super(taskConfig, cfg,wf);
	
	}

	@Override
	public void init(WorkflowTaskType taskConfig) throws ProvisioningException {
		MappingType mapCfg = (MappingType) taskConfig;
		this.strict = mapCfg.isStrict();
		this.mapper = new MapIdentity(mapCfg.getMap());

	}

	@Override
	public boolean doTask(User user,Map<String,Object> request) throws ProvisioningException {
		
		
		User mappedUser = this.mapper.mapUser(user,strict,request,this);
		if (super.getOnSuccess() != null) {
			boolean doContinue = super.runSubTasks(super.getOnSuccess(),mappedUser,request);
			user.setResync(mappedUser.isResync());
			user.setKeepExternalAttrs(mappedUser.isKeepExternalAttrs());
			
			return doContinue;
		} else {
			logger.warn("No sub tasks");
			return true;
		}
	}
	
	public MapIdentity getMapping() {
		return this.mapper;
	}

	@Override
	public boolean restartChildren() throws ProvisioningException {
		return super.restartChildren(this.getWorkflow().getUser(),this.getWorkflow().getRequest());
	}

	@Override
	public String getLabel() {
		return "Map Attributes";
	}

	public MapIdentity getMapper() {
		return mapper;
	}

	public void setMapper(MapIdentity mapper) {
		this.mapper = mapper;
	}

	public boolean isStrict() {
		return strict;
	}

	public void setStrict(boolean strict) {
		this.strict = strict;
	}
	
	
}

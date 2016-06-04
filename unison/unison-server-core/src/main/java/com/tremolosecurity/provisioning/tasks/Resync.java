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

import java.util.Map;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.ResyncType;
import com.tremolosecurity.config.xml.WorkflowTaskType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningParams;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTaskImpl;

public class Resync extends WorkflowTaskImpl {

	boolean keepExternalAttrs;
	boolean changeRoot;
	String newRoot;
	
	
	public Resync() {
		
	}
	
	public Resync(WorkflowTaskType taskConfig, ConfigManager cfg,Workflow wf)
			throws ProvisioningException {
		super(taskConfig, cfg,wf);
		
	}

	@Override
	public void init(WorkflowTaskType taskConfig) throws ProvisioningException {
		ResyncType resync = (ResyncType) taskConfig;
		this.keepExternalAttrs = resync.isKeepExternalAttrs();
		this.changeRoot = resync.isChangeRoot();
		this.newRoot = resync.getNewRoot();
	}

	@Override
	public boolean doTask(User user,Map<String,Object> request) throws ProvisioningException {
		user.setResync(true);
		user.setKeepExternalAttrs(this.keepExternalAttrs);

		if (this.changeRoot) {
			request.put(ProvisioningParams.UNISON_RESYNC_ROOT, this.newRoot);
		}
		
		return true;
	}

	@Override
	public String getLabel() {
		return "Resync User from Directories";
	}

	public boolean isKeepExternalAttrs() {
		return keepExternalAttrs;
	}

	public void setKeepExternalAttrs(boolean keepExternalAttrs) {
		this.keepExternalAttrs = keepExternalAttrs;
	}

}

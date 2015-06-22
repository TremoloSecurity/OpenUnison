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


package com.tremolosecurity.provisioning.util;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.saml.Attribute;

public interface CustomTask extends Serializable {

	public void init(WorkflowTask task,Map<String,Attribute> params) throws ProvisioningException;
	
	public void reInit(WorkflowTask task) throws ProvisioningException;
	
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException;
}

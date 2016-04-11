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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.hibernate.HibernateException;
import org.hibernate.Session;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.objects.Workflows;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.proxy.auth.AuthInfo;

public interface Workflow extends Serializable {

	public abstract int getUserNum();

	public abstract void reInit(ConfigManager cfgMgr)
			throws ProvisioningException;

	public abstract void executeWorkflow(User user, Map<String, Object> params)
			throws ProvisioningException;

	public abstract void executeWorkflow(AuthInfo authInfo, String uidAttr)
			throws ProvisioningException;

	public abstract void executeWorkflow(WFCall call)
			throws ProvisioningException;

	public abstract void init() throws ProvisioningException;

	public abstract int getId();

	public abstract void setId(int id);

	public abstract void restart() throws ProvisioningException;

	public abstract User getUser();

	public abstract void completeWorkflow() throws ProvisioningException;

	public abstract WorkflowTask findCurrentApprovalTask();

	public abstract ArrayList<WorkflowTask> getTasks();

	public abstract Map<String, Object> getRequest();

	public abstract String getName();

	public abstract String toString();

	public abstract void printWF(StringBuffer b, String prefix,
			WorkflowTask task);
	
	public abstract Workflows getFromDB(Session session) throws HibernateException, ProvisioningException;

}
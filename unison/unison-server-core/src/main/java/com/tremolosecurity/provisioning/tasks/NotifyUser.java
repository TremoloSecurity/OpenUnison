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
import com.tremolosecurity.config.xml.NotifyUserType;
import com.tremolosecurity.config.xml.WorkflowTaskType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTaskImpl;

public class NotifyUser extends WorkflowTaskImpl {

	/**
	 * 
	 */
	private static final long serialVersionUID = 8258955520301960035L;
	String subject;
	String msg;
	String mailAttr;
	
	public NotifyUser() {
		
	}
	
	public NotifyUser(WorkflowTaskType taskConfig, ConfigManager cfg,
			Workflow wf) throws ProvisioningException {
		super(taskConfig, cfg, wf);
	}

	@Override
	public void init(WorkflowTaskType taskConfig) throws ProvisioningException {
		NotifyUserType nut = (NotifyUserType) taskConfig;
		this.subject = nut.getSubject();
		this.mailAttr = nut.getMailAttrib();
		this.msg = nut.getMsg();

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request)
			throws ProvisioningException {
		
		if (! user.getAttribs().containsKey(this.mailAttr)) {
			throw new ProvisioningException("No mail attribute");
		}
		
		
		
		if (this.getWorkflow().getRequesterNum() != this.getWorkflow().getUserNum()) {
			String mail = this.getWorkflow().getRequester().getAttribs().get(this.mailAttr).getValues().get(0);
			
			String localSubject = this.renderTemplate(subject, request);
			String localMsg = this.renderTemplate(msg, request);
			
			try {
				this.getConfigManager().getProvisioningEngine().sendNotification(mail, localMsg,localSubject,this.getWorkflow().getRequester());
			} catch (Exception e) {
				throw new ProvisioningException("Could not send user notification",e);
			}
		}
		
		
		
		String mail = user.getAttribs().get(this.mailAttr).getValues().get(0);
		
		String localSubject = this.renderTemplate(subject, request);
		String localMsg = this.renderTemplate(msg, request);
		
		try {
			this.getConfigManager().getProvisioningEngine().sendNotification(mail, localMsg,localSubject,user);
		} catch (Exception e) {
			throw new ProvisioningException("Could not send user notification",e);
		}
		
		return true;
	}

	@Override
	public String getLabel() {
		return "Notify User";
	}

	public String getSubject() {
		return subject;
	}

	public void setSubject(String subject) {
		this.subject = subject;
	}

	public String getMsg() {
		return msg;
	}

	public void setMsg(String msg) {
		this.msg = msg;
	}

	public String getMailAttr() {
		return mailAttr;
	}

	public void setMailAttr(String mailAttr) {
		this.mailAttr = mailAttr;
	}
	
	

}

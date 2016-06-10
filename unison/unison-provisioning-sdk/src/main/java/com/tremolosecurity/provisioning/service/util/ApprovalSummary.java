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


package com.tremolosecurity.provisioning.service.util;

import org.joda.time.DateTime;

public class ApprovalSummary {
	int workflow;
	int approval;
	String label;
	String user;
	long wfStart;
	long approvalStart;
	String wfName;
	String wfDescription;
	String wfLabel;
	String reason;
	String displayName;
	
	public ApprovalSummary() {
		
	}

	public int getWorkflow() {
		return workflow;
	}

	public void setWorkflow(int workflow) {
		this.workflow = workflow;
	}

	public int getApproval() {
		return approval;
	}

	public void setApproval(int approval) {
		this.approval = approval;
	}

	public String getLabel() {
		return label;
	}

	public void setLabel(String label) {
		this.label = label;
	}

	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}

	public long getWfStart() {
		return wfStart;
	}

	public void setWfStart(long wfStart) {
		this.wfStart = wfStart;
	}

	public long getApprovalStart() {
		return approvalStart;
	}

	public void setApprovalStart(long approvalStart) {
		this.approvalStart = approvalStart;
	}

	public String getWfName() {
		return wfName;
	}

	public void setWfName(String wfName) {
		this.wfName = wfName;
	}

	public String getWfDescription() {
		return wfDescription;
	}

	public void setWfDescription(String wfDescription) {
		this.wfDescription = wfDescription;
	}

	public String getWfLabel() {
		return wfLabel;
	}

	public void setWfLabel(String wfLabel) {
		this.wfLabel = wfLabel;
	}

	public String getReason() {
		return reason;
	}

	public void setReason(String reason) {
		this.reason = reason;
	}



	public String getDisplayName() {
		return displayName;
	}

	public void setDisplayName(String displayName) {
		this.displayName = displayName;
	}

	
	
	
}

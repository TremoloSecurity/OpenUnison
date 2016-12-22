/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
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
package com.tremolosecurity.scalejs.data;

import java.util.ArrayList;
import java.util.List;

public class WorkflowRequest {
	String name;
	String reason;
	String encryptedParams;
	String uuid;
	List<String> subjects;
	boolean approved;
	String approvalReason;
	boolean doPreApproval;
	
	


	public String getUuid() {
		return uuid;
	}

	public void setUuid(String uuid) {
		this.uuid = uuid;
	}

	public WorkflowRequest() {
		this.subjects = new ArrayList<String>();
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getReason() {
		return reason;
	}

	public void setReason(String reason) {
		this.reason = reason;
	}

	public String getEncryptedParams() {
		return encryptedParams;
	}

	public void setEncryptedParams(String encryptedParams) {
		this.encryptedParams = encryptedParams;
	}

	

	public boolean isApproved() {
		return approved;
	}

	public void setApproved(boolean approved) {
		this.approved = approved;
	}

	public String getApprovalReason() {
		return approvalReason;
	}

	public void setApprovalReason(String approvalReason) {
		this.approvalReason = approvalReason;
	}

	public List<String> getSubjects() {
		return subjects;
	}

	public void setSubjects(List<String> subjects) {
		this.subjects = subjects;
	}

	public boolean isDoPreApproval() {
		return doPreApproval;
	}

	public void setDoPreApproval(boolean doPreApproval) {
		this.doPreApproval = doPreApproval;
	}
	
	
	
	
}

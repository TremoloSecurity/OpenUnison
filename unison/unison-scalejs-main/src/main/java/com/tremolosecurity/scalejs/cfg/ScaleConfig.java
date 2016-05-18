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
package com.tremolosecurity.scalejs.cfg;

import java.util.HashMap;
import java.util.Map;

public class ScaleConfig {
	String displayNameAttribute;
	String uidAttributeName;
	ScaleFrontPage frontPage;
	boolean canEditUser;
	boolean showPortalOrgs;
	String logoutURL;
	
	transient String workflowName;
	Map<String,ScaleAttribute> attributes;
	transient Map<String,ScaleAttribute> approvalAttributes;
	String roleAttribute;
	
	public ScaleConfig() {
		this.attributes = new HashMap<String,ScaleAttribute>();
		this.approvalAttributes = new HashMap<String,ScaleAttribute>();
		this.frontPage = new ScaleFrontPage();
	}

	public String getDisplayNameAttribute() {
		return displayNameAttribute;
	}

	public void setDisplayNameAttribute(String displayNameAttribute) {
		this.displayNameAttribute = displayNameAttribute;
	}

	public ScaleFrontPage getFrontPage() {
		return frontPage;
	}

	public void setFrontPage(ScaleFrontPage frontPage) {
		this.frontPage = frontPage;
	}

	public boolean isCanEditUser() {
		return canEditUser;
	}

	public void setCanEditUser(boolean canEditUser) {
		this.canEditUser = canEditUser;
	}

	public String getWorkflowName() {
		return workflowName;
	}

	public void setWorkflowName(String workflowName) {
		this.workflowName = workflowName;
	}

	public Map<String, ScaleAttribute> getAttributes() {
		return attributes;
	}

	public void setAttributes(Map<String, ScaleAttribute> attributes) {
		this.attributes = attributes;
	}

	public String getUidAttributeName() {
		return uidAttributeName;
	}

	public void setUidAttributeName(String uidAttributeName) {
		this.uidAttributeName = uidAttributeName;
	}

	public String getRoleAttribute() {
		return roleAttribute;
	}

	public void setRoleAttribute(String roleAttribute) {
		this.roleAttribute = roleAttribute;
	}

	public Map<String, ScaleAttribute> getApprovalAttributes() {
		return approvalAttributes;
	}

	public boolean isShowPortalOrgs() {
		return showPortalOrgs;
	}

	public void setShowPortalOrgs(boolean showPortalOrgs) {
		this.showPortalOrgs = showPortalOrgs;
	}

	public String getLogoutURL() {
		return logoutURL;
	}

	public void setLogoutURL(String logoutURL) {
		this.logoutURL = logoutURL;
	}
	
	

	
}

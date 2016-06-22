/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.scalejs.register.cfg;

import java.util.HashMap;
import java.util.Map;

import com.tremolosecurity.scalejs.cfg.ScaleAttribute;
import com.tremolosecurity.scalejs.cfg.ScaleFrontPage;

public class ScaleJSRegisterConfig {
	ScaleFrontPage frontPage;
	String logoutURL;
	transient String workflowName;
	Map<String,ScaleAttribute> attributes;
	boolean requireReason;
	boolean preSetPassword;
	transient String uidAttributeName;
	
	public ScaleJSRegisterConfig() {
		this.attributes = new HashMap<String,ScaleAttribute>();
		this.frontPage = new ScaleFrontPage();
	}


	public ScaleFrontPage getFrontPage() {
		return frontPage;
	}


	public void setFrontPage(ScaleFrontPage frontPage) {
		this.frontPage = frontPage;
	}


	public String getLogoutURL() {
		return logoutURL;
	}


	public void setLogoutURL(String logoutURL) {
		this.logoutURL = logoutURL;
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


	public boolean isRequireReason() {
		return requireReason;
	}


	public void setRequireReason(boolean requireReason) {
		this.requireReason = requireReason;
	}


	public boolean isPreSetPassword() {
		return preSetPassword;
	}


	public void setPreSetPassword(boolean preSetPassword) {
		this.preSetPassword = preSetPassword;
	}


	public String getUidAttributeName() {
		return uidAttributeName;
	}


	public void setUidAttributeName(String uidAttributeName) {
		this.uidAttributeName = uidAttributeName;
	}
	
	
}

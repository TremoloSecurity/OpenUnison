/*******************************************************************************
 * Copyright 2016, 2017 Tremolo Security, Inc.
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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.scalejs.cfg.ScaleAttribute;
import com.tremolosecurity.scalejs.cfg.ScaleFrontPage;

public class ScaleJSRegisterConfig {
	ScaleFrontPage frontPage;
	String homeURL;
	String logoutURL;
	transient String workflowName;
	Map<String,ScaleAttribute> attributes;
	List<String> attributeNameList;
	boolean requireReason;
	boolean preSetPassword;
	transient String uidAttributeName;
	boolean requireReCaptcha;
	String rcSiteKey;
	transient String rcSecretKey;
	boolean requireTermsAndConditions;
	String termsAndConditionsText;
	transient boolean useCustomSubmission;
	transient HashMap<String,Attribute> customSubmissionConfig;
	transient String customSubmissionClassName;
	transient boolean submitLoggedInUser;
	
	boolean reasonIsList;
	List<String> reasons;
	
	
	String submitButtonText;
	String submittedText;
	
	List<String> jsUris;
	
	
	
	boolean enableThirdColumn;
	
	public ScaleJSRegisterConfig() {
		this.attributes = new HashMap<String,ScaleAttribute>();
		this.frontPage = new ScaleFrontPage();
		this.attributeNameList = new ArrayList<String>();
		this.submitLoggedInUser = false;
		this.reasons = new ArrayList<String>();
		this.enableThirdColumn = false;
		this.jsUris = new ArrayList<String>();
	}

	

	public boolean isSubmitLoggedInUser() {
		return submitLoggedInUser;
	}



	public void setSubmitLoggedInUser(boolean submitLoggedInUser) {
		this.submitLoggedInUser = submitLoggedInUser;
	}



	public List<String> getAttributeNameList() {
		return this.attributeNameList;
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


	public boolean isRequireReCaptcha() {
		return requireReCaptcha;
	}


	public void setRequireReCaptcha(boolean requireReCaptcha) {
		this.requireReCaptcha = requireReCaptcha;
	}


	public String getRcSiteKey() {
		return rcSiteKey;
	}


	public void setRcSiteKey(String rcSiteKey) {
		this.rcSiteKey = rcSiteKey;
	}


	public String getRcSecretKey() {
		return rcSecretKey;
	}


	public void setRcSecretKey(String rcSecretKey) {
		this.rcSecretKey = rcSecretKey;
	}


	public boolean isRequireTermsAndConditions() {
		return requireTermsAndConditions;
	}


	public void setRequireTermsAndConditions(boolean requireTermsAndConditions) {
		this.requireTermsAndConditions = requireTermsAndConditions;
	}


	public String getTermsAndConditionsText() {
		return termsAndConditionsText;
	}


	public void setTermsAndConditionsText(String termsAndConditionsText) {
		this.termsAndConditionsText = termsAndConditionsText;
	}


	public boolean isUseCustomSubmission() {
		return useCustomSubmission;
	}


	public void setUseCustomSubmission(boolean useCustomSubmission) {
		this.useCustomSubmission = useCustomSubmission;
	}


	public HashMap<String, Attribute> getCustomSubmissionConfig() {
		return customSubmissionConfig;
	}


	public void setCustomSubmissionConfig(HashMap<String, Attribute> customSubmissionConfig) {
		this.customSubmissionConfig = customSubmissionConfig;
	}


	public String getCustomSubmissionClassName() {
		return customSubmissionClassName;
	}


	public void setCustomSubmissionClassName(String customSubmissionClassName) {
		this.customSubmissionClassName = customSubmissionClassName;
	}


	public String getHomeURL() {
		return homeURL;
	}


	public void setHomeURL(String homeURL) {
		this.homeURL = homeURL;
	}



	public String getSubmitButtonText() {
		return submitButtonText;
	}



	public void setSubmitButtonText(String submitButtonText) {
		this.submitButtonText = submitButtonText;
	}



	public String getSubmittedText() {
		return submittedText;
	}



	public void setSubmittedText(String submittedText) {
		this.submittedText = submittedText;
	}



	public boolean isReasonIsList() {
		return reasonIsList;
	}



	public void setReasonIsList(boolean reasonIsList) {
		this.reasonIsList = reasonIsList;
	}



	public List<String> getReasons() {
		return reasons;
	}



	public boolean isEnableThirdColumn() {
		return enableThirdColumn;
	}



	public void setEnableThirdColumn(boolean enableThirdColumn) {
		this.enableThirdColumn = enableThirdColumn;
	}



	public List<String> getJsUris() {
		return jsUris;
	}
	
	
	
	
	
}

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
package com.tremolosecurity.scalejs.register.data;

import java.util.*;

public class NewUserRequest {

	Map<String,String> attributes;
	String reason;
	String password;
	String password2;
	String reCaptchaCode;
	boolean checkedTermsAndConditions;
	
	public NewUserRequest() {
		this.attributes = new HashMap<String,String>();
	}

	public Map<String, String> getAttributes() {
		return attributes;
	}

	public void setAttributes(Map<String, String> attributes) {
		this.attributes = attributes;
	}

	public String getReason() {
		return reason;
	}

	public void setReason(String reason) {
		this.reason = reason;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getPassword2() {
		return password2;
	}

	public void setPassword2(String password2) {
		this.password2 = password2;
	}

	public String getReCaptchaCode() {
		return reCaptchaCode;
	}

	public void setReCaptchaCode(String reCaptchaCode) {
		this.reCaptchaCode = reCaptchaCode;
	}

	public boolean isCheckedTermsAndConditions() {
		return checkedTermsAndConditions;
	}

	public void setCheckedTermsAndConditions(boolean checkedTermsAndConditions) {
		this.checkedTermsAndConditions = checkedTermsAndConditions;
	}
	
	
}

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


package com.tremolosecurity.proxy.auth;

import java.util.ArrayList;
import java.util.List;

import com.tremolosecurity.proxy.auth.util.AuthStep;

public class AuthController {
	private AuthInfo authInfo;
	private ArrayList<AuthStep> authSteps;
	private RequestHolder holder;
	private AuthStep currentStep;

	public AuthController() {
		this.authSteps = new ArrayList<AuthStep>();
	}
	
	public AuthInfo getAuthInfo() {
		return authInfo;
	}

	public void setAuthInfo(AuthInfo authInfo) {
		this.authInfo = authInfo;
	}

	public ArrayList<AuthStep> getAuthSteps() {
		return authSteps;
	}


	public RequestHolder getHolder() {
		return holder;
	}

	public void setHolder(RequestHolder holder) {
		this.holder = holder;
	}

	public AuthStep getCurrentStep() {
		return currentStep;
	}

	public void setCurrentStep(AuthStep currentStep) {
		this.currentStep = currentStep;
	}
}

/*******************************************************************************
 * Copyright 2015 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.util;

import java.util.List;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.proxy.az.AzRule;
import com.tremolosecurity.proxy.az.VerifyEscalation;

public interface EscalationRule {

	public enum RunOptions {
		alreadyRun,
		run,
		notReadyYet,
		stopEscalating
	};
	
	public abstract RunOptions shouldExecute(User user)
			throws ProvisioningException;

	public abstract long getExecuteTS();

	public abstract void setExecuteTS(long executeTS);

	public abstract List<AzRule> getAzRules();

	public abstract void setAzRules(List<AzRule> azRules);

	public abstract VerifyEscalation getVerify();

	public abstract void setVerify(VerifyEscalation verify);

	public abstract boolean isCompleted();

	public abstract void setCompleted(boolean completed);

}
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
package com.tremolosecurity.provisioning.tasks.escalation;

import java.util.List;

import org.joda.time.DateTime;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.util.EscalationRule;
import com.tremolosecurity.proxy.az.AzRule;
import com.tremolosecurity.proxy.az.VerifyEscalation;

public class EsclationRuleImpl implements EscalationRule {
	long executeTS;
	List<AzRule> azRules;
	VerifyEscalation verify;
	
	boolean completed;
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.tasks.escalation.EscalationRule#shouldExecute(com.tremolosecurity.provisioning.core.User)
	 */
	@Override
	public RunOptions shouldExecute(User user) throws ProvisioningException {
		if (completed) {
			return RunOptions.alreadyRun;
		} else {
			if (System.currentTimeMillis() >= executeTS) {
				if (verify != null) {
					return this.verify.doEscalation(user, this);
				} else {
					return RunOptions.run;
				}
			} else {
				return RunOptions.notReadyYet;
			}
		}
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.tasks.escalation.EscalationRule#getExecuteTS()
	 */
	@Override
	public long getExecuteTS() {
		return executeTS;
	}
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.tasks.escalation.EscalationRule#setExecuteTS(long)
	 */
	@Override
	public void setExecuteTS(long executeTS) {
		this.executeTS = executeTS;
	}
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.tasks.escalation.EscalationRule#getAzRules()
	 */
	@Override
	public List<AzRule> getAzRules() {
		return azRules;
	}
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.tasks.escalation.EscalationRule#setAzRules(java.util.List)
	 */
	@Override
	public void setAzRules(List<AzRule> azRules) {
		this.azRules = azRules;
	}
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.tasks.escalation.EscalationRule#getVerify()
	 */
	@Override
	public VerifyEscalation getVerify() {
		return verify;
	}
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.tasks.escalation.EscalationRule#setVerify(com.tremolosecurity.proxy.az.VerifyEscalation)
	 */
	@Override
	public void setVerify(VerifyEscalation verify) {
		this.verify = verify;
	}
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.tasks.escalation.EscalationRule#isCompleted()
	 */
	@Override
	public boolean isCompleted() {
		return completed;
	}
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.tasks.escalation.EscalationRule#setCompleted(boolean)
	 */
	@Override
	public void setCompleted(boolean completed) {
		this.completed = completed;
	}
	
	
}

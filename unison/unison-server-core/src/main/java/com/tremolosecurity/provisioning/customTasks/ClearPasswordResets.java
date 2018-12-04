/*******************************************************************************
 * Copyright 2018 Tremolo Security, Inc.
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
//    Copyright 2018 Tremolo Security, Inc.
// 
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
// 
//        http://www.apache.org/licenses/LICENSE-2.0
// 
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.


package com.tremolosecurity.provisioning.customTasks;

import java.util.Map;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.proxy.auth.PasswordReset;
import com.tremolosecurity.saml.Attribute;

/**
 * ClearPasswordResets
 */
public class ClearPasswordResets implements CustomTask{

    String mechName;
	transient ConfigManager cfgMgr;

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.mechName = params.get("mechName").getValues().get(0);
		this.cfgMgr = task.getConfigManager();
	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.cfgMgr = task.getConfigManager();
	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		String uri = this.cfgMgr.getAuthMechs().get(mechName).getUri();
        PasswordReset mech = (PasswordReset) this.cfgMgr.getAuthMech(uri);
        mech.clearUserRequests(user.getUserID());
        return true;
	}

    
}
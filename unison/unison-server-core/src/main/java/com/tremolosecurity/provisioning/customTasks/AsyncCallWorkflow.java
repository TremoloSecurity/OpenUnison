/*******************************************************************************
 * Copyright 2022 Tremolo Security, Inc.
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

package com.tremolosecurity.provisioning.customTasks;

import java.util.Map;
import java.util.HashMap;


import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningParams;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.service.util.TremoloUser;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

public class AsyncCallWorkflow implements CustomTask {

	String workflowName;
    String uidAttributeName;
    transient WorkflowTask task;
    String workflowReason;
    
    @Override
    public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
        
        String localWorkflowName = task.renderTemplate(this.workflowName, request);

        TremoloUser newUser = new TremoloUser();
        newUser.setUid(user.getUserID());
        
        for (String attrName : user.getAttribs().keySet()) {
            newUser.getAttributes().add(user.getAttribs().get(attrName));
        }

        newUser.getGroups().addAll(user.getGroups());
        newUser.setUserPassword(user.getPassword());
        
        

        WFCall call = new WFCall();
        call.setReason(task.renderTemplate(this.workflowReason, request));
        call.setUidAttributeName(uidAttributeName);
        call.setUser(newUser);
        call.setRequestor(user.getUserID());
        call.getRequestParams().putAll(request);
        call.getRequestParams().put(ProvisioningParams.UNISON_EXEC_TYPE, ProvisioningParams.UNISON_EXEC_ASYNC);
        
        Workflow wf = task.getConfigManager().getProvisioningEngine().getWorkFlow(localWorkflowName);
        wf.executeWorkflow(call);
        
 
        return true;
    }

    @Override
    public void init(WorkflowTask task, Map<String, Attribute> config) throws ProvisioningException {
        this.task = task;
        this.workflowName = config.get("workflowName").getValues().get(0);
        this.uidAttributeName = config.get("uidAttributeName").getValues().get(0);
        this.workflowReason = config.get("workflowReason").getValues().get(0);

    }

    @Override
    public void reInit(WorkflowTask task) throws ProvisioningException {
        this.task = task;

    }

}

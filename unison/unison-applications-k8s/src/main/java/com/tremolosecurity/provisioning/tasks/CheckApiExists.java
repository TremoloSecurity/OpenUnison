/*
 * Copyright 2025 Tremolo Security, Inc.
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
 */

package com.tremolosecurity.provisioning.tasks;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningTarget;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

import java.util.Map;

public class CheckApiExists implements CustomTask {
    String apiGroup;
    String apiKind;
    String cluster;
    String attribute;

    transient WorkflowTask task;

    @Override
    public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
        apiGroup = params.get("apiGroup").getValues().get(0);
        apiKind = params.get("apiKind").getValues().get(0);
        cluster = params.get("cluster").getValues().get(0);
        attribute = params.get("attribute").getValues().get(0);

        this.task = task;
    }

    @Override
    public void reInit(WorkflowTask task) throws ProvisioningException {
        this.task = task;
    }

    @Override
    public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {

        String localCluster = this.task.renderTemplate(this.cluster,request);
        String localKind = this.task.renderTemplate(this.apiKind,request);
        String localGroup = this.task.renderTemplate(this.apiGroup,request);
        String localAttribute = this.task.renderTemplate(this.attribute,request);

        ProvisioningTarget target = task.getConfigManager().getProvisioningEngine().getTarget( localCluster);
        if (target == null) {
            throw new ProvisioningException(String.format("Target %s not found", localCluster));
        }

        OpenShiftTarget k8s = (OpenShiftTarget) target.getProvider();


        try {
            if (k8s.getApis().getUri(localGroup,localKind) != null) {
                user.getAttribs().put(localAttribute,new Attribute(localAttribute,"exists"));
            }
        } catch (Exception e) {
            throw new ProvisioningException(String.format("API %s/%s not found",localGroup, localKind), e);
        }


        return true;
    }
}

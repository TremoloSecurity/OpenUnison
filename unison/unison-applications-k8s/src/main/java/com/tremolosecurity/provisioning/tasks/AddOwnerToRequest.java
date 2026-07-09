/*
 * Copyright 2026 Tremolo Security, Inc.
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

import com.tremolosecurity.provisioning.core.*;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;
import org.apache.log4j.Logger;

import java.util.Map;

public class AddOwnerToRequest implements CustomTask {
    static transient  Logger logger = Logger.getLogger(AddOwnerToRequest.class.getName());
    String target = null;

    @Override
    public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
        target = params.get("target").getValues().get(0);
    }

    @Override
    public void reInit(WorkflowTask task) throws ProvisioningException {

    }

    @Override
    public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
        ProvisioningTarget target = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.target);
        if (target == null) {
            logger.warn("Could not find target " + this.target);
        } else {
            OpenShiftTarget k8s = (OpenShiftTarget) target.getProvider();
            StringBuilder b = new StringBuilder();

            request.put( b.append(this.target).append("_owner_kind").toString(),k8s.getOwnerKind());
            b.setLength(0);

            request.put( b.append(this.target).append("_owner_apiversion").toString(),k8s.getOwnerApiVersion());
            b.setLength(0);

            request.put( b.append(this.target).append("_owner_name").toString(),k8s.getOwnerName());
            b.setLength(0);

            request.put( b.append(this.target).append("_owner_uid").toString(),k8s.getOwnerUid());
            b.setLength(0);

            request.put( b.append(this.target).append("_owner_namespace").toString(),k8s.getOwnerNamespace());
            b.setLength(0);


        }
        return true;

    }
}

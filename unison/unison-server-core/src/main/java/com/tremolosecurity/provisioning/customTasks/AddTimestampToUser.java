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

package com.tremolosecurity.provisioning.customTasks;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

import java.util.Map;

public class AddTimestampToUser implements CustomTask {
    String attributeName;

    @Override
    public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
        this.attributeName = params.get("attributeName").getValues().get(0);
    }

    @Override
    public void reInit(WorkflowTask task) throws ProvisioningException {

    }

    @Override
    public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
        Attribute lastUpdated = new Attribute(this.attributeName,Long.toString(System.currentTimeMillis()));
        user.getAttribs().put(attributeName, lastUpdated);
        return true;
    }
}

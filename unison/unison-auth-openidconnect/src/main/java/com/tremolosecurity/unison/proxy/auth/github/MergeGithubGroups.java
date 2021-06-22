/*******************************************************************************
 * Copyright 2021 Tremolo Security, Inc.
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
package com.tremolosecurity.unison.proxy.auth.github;

import java.util.Map;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.tasks.CustomTask;
import com.tremolosecurity.saml.Attribute;

/**
 * MergeGithubGroups
 */
public class MergeGithubGroups implements com.tremolosecurity.provisioning.util.CustomTask {

    @Override
    public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
        

        if (user.getAttribs().get("githubOrgs") != null) {
            user.getGroups().addAll(user.getAttribs().get("githubOrgs").getValues());
        }

        if (user.getAttribs().get("githubTeams") != null) {
            user.getGroups().addAll(user.getAttribs().get("githubTeams").getValues());
        }

        

        return true;
    }

    @Override
    public void init(WorkflowTask user, Map<String, Attribute> request) throws ProvisioningException {

    }

    @Override
    public void reInit(WorkflowTask task) throws ProvisioningException {

    }

    

    
}
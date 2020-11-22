/*******************************************************************************
 * Copyright 2020 Tremolo Security, Inc.
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
package com.tremolosecurity.scalejs;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.TargetType;
import com.tremolosecurity.config.xml.WorkflowType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.util.DynamicWorkflow;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;
import com.tremolosecurity.util.NVP;

public class WorkflowListClusters implements DynamicWorkflow {

	@Override
	public List<Map<String, String>> generateWorkflows(WorkflowType wf, ConfigManager cfg,
			HashMap<String, Attribute> params) throws ProvisioningException {
		List<TargetType> targets = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getTargets().getTarget();
		List<Map<String, String>> k8sTargets = new ArrayList<Map<String, String>>();
		
		for (TargetType tt : targets) {
			if (tt.getClassName().equalsIgnoreCase("com.tremolosecurity.unison.openshiftv3.OpenShiftTarget")) {
				OpenShiftTarget target = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(tt.getName()).getProvider();
				
				Map<String,String> wfParams = new HashMap<String,String>();
				wfParams.put("cluster", tt.getName());
				wfParams.put("clusterlabel", target.getLabel());
				
				k8sTargets.add(wfParams);
			}
		}
		
		return k8sTargets;
	}

	@Override
	public List<Map<String, String>> generateWorkflows(WorkflowType wf, ConfigManager cfg,
			HashMap<String, Attribute> params, AuthInfo authInfo) throws ProvisioningException {
		return this.generateWorkflows(wf, cfg, params);
	}

}

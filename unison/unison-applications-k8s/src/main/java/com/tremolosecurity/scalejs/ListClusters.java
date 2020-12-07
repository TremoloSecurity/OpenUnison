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
import java.util.List;
import java.util.Map;

import com.tremolosecurity.config.xml.TargetType;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.scalejs.cfg.ScaleAttribute;
import com.tremolosecurity.scalejs.sdk.SourceList;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;
import com.tremolosecurity.util.NVP;

public class ListClusters implements SourceList {

	@Override
	public void init(ScaleAttribute attribute, Map<String, Attribute> config) {
		// TODO Auto-generated method stub

	}

	@Override
	public List<NVP> getSourceList(HttpFilterRequest request) throws Exception {
		List<TargetType> targets = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getTargets().getTarget();
		List<NVP> k8sTargets = new ArrayList<NVP>();
		
		for (TargetType tt : targets) {
			if (tt.getClassName().equalsIgnoreCase("com.tremolosecurity.unison.openshiftv3.OpenShiftTarget")) {
				OpenShiftTarget target = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(tt.getName()).getProvider();
				k8sTargets.add(new NVP(target.getLabel(),tt.getName()));
			}
		}
		
		return k8sTargets;
		
				
	}

	@Override
	public String validate(String value, HttpFilterRequest request) throws Exception {
		List<TargetType> targets = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getTargets().getTarget();
		for (TargetType tt : targets) {
			if (tt.getClassName().equalsIgnoreCase("com.tremolosecurity.unison.openshiftv3.OpenShiftTarget") && tt.getName().equals(value)) {
				return null;
			}
		}
		
		return new StringBuilder().append("Unknown cluster '").append(value).append("'").toString();
	}

}

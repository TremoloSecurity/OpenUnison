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

import org.apache.commons.io.filefilter.SuffixFileFilter;
import org.apache.log4j.Logger;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.WorkflowType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.util.DynamicWorkflow;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.saml.Attribute;

public class ListClusterApproverGroups implements DynamicWorkflow {

	static Logger logger = Logger.getLogger(ListClusterApproverGroups.class);
	
	@Override
	public List<Map<String, String>> generateWorkflows(WorkflowType wf, ConfigManager cfg,
			HashMap<String, Attribute> params) throws ProvisioningException {
		return new ArrayList<Map<String,String>>();
	}

	@Override
	public List<Map<String, String>> generateWorkflows(WorkflowType wf, ConfigManager cfg,
			HashMap<String, Attribute> params, AuthInfo authInfo) throws ProvisioningException {
		String clusterName = params.get("cluster").getValues().get(0);
		String groupsAttribute = params.get("groupsAttribute").getValues().get(0);
		boolean groupsAreDN = params.get("groupsAreDN").getValues().get(0).equalsIgnoreCase("true");
		String groupPrefix = params.get("groupPrefix").getValues().get(0);
		String suffix = params.get("groupSuffix") != null ? params.get("groupSuffix").getValues().get(0) : "";
		
		Attribute groups = authInfo.getAttribs().get(groupsAttribute);
		
		if (logger.isDebugEnabled()) {
			logger.debug("Groups: " + groups);
		}
		
		StringBuilder sb = new StringBuilder();
		
		List<Map<String,String>> workflowdata = new ArrayList<Map<String,String>>();
		
		for (String group : groups.getValues()) {
			
			sb.setLength(0);
			sb.append(groupPrefix).append(clusterName);
			String prefix = sb.toString();
			boolean ok = group.startsWith(prefix) &&    ( group.endsWith(suffix) );
			
			if (logger.isDebugEnabled()) {
				logger.debug("prefix: " + prefix + " suffix '" + suffix +  "' group: " + group + " ok? " + ok + " / " + group.startsWith(sb.toString()) + " / " + group.endsWith(suffix) );
			}
			
			if (ok) {
				Map<String,String> workflow = new HashMap<String,String>();
				workflow.put("groupName", group);
				workflow.put("namespaceName", group.substring(sb.toString().length() + 1 , group.length() - suffix.length())) ;
				workflow.put("nameSpace", group.substring(sb.toString().length() + 1 , group.length() - suffix.length()));
				workflowdata.add(workflow);
				
			}
		}
		
		return workflowdata;
		
	}

}

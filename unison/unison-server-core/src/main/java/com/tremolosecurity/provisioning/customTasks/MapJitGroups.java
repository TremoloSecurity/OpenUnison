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
package com.tremolosecurity.provisioning.customTasks;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.novell.ldap.util.DN;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

public class MapJitGroups implements CustomTask {
	
	Map<DN,List<String>> groupMap;
	String attributeName;

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.attributeName = params.get("attributeName").getValues().get(0);
		this.groupMap = new HashMap<DN,List<String>>();
		
		Attribute groups = params.get("groupMap");
		for (String map : groups.getValues()) {
			String groupName = map.substring(0,map.indexOf('='));
			String dn = map.substring(map.indexOf('=') + 1);
			DN groupDN = new DN(dn);
			List<String> groupsToMapTo = this.groupMap.get(groupDN);
			if (groupsToMapTo == null) {
				groupsToMapTo = new ArrayList<String>();
				this.groupMap.put(groupDN, groupsToMapTo);
			}
			
			groupsToMapTo.add(groupName);
			
			
		}

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		Attribute groupAttr = user.getAttribs().get(this.attributeName);
		Set<String> groupDNs = new HashSet<String>();
		
		if (groupAttr != null) {
			for (String dnFromAttr : groupAttr.getValues()) {
				groupDNs.add(new DN(dnFromAttr).toString().toLowerCase());
			}
		}
		
		for (DN groupDN : groupMap.keySet()) {
			if (groupDNs.contains(groupDN.toString().toLowerCase())) {
				user.getGroups().addAll(groupMap.get(groupDN));
			} else {
				user.getGroups().removeAll(groupMap.get(groupDN));
			}
		}
		return true;
	}

}

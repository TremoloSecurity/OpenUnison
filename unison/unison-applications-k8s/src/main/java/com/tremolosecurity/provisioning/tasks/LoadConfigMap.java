//    Copyright 2021 Tremolo Security, Inc.
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

package com.tremolosecurity.provisioning.tasks;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;

import com.tremolosecurity.k8s.util.K8sUtils;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

public class LoadConfigMap implements CustomTask {
	
	static Logger logger = Logger.getLogger(LoadConfigMap.class);

	transient WorkflowTask task;
	
	String target;
	String namespace;
	String configmap;
	Map<String,String> mapping;
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.target = params.get("target").getValues().get(0);
		this.namespace = params.get("namespace").getValues().get(0);
		this.configmap = params.get("configmap").getValues().get(0);
		this.mapping = new HashMap<String,String>();
		
		for (String val : params.get("mapping").getValues()) {
			String wfName = val.substring(0,val.indexOf('='));
			String cmName = val.substring(val.indexOf('=') + 1);
			
			this.mapping.put(wfName, cmName);
		}
		
		this.task = task;

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		try {
			
			String localTarget = this.task.renderTemplate(this.target, request);
			String localNamespace = this.task.renderTemplate(this.namespace, request);
			String localConfigMap = this.task.renderTemplate(this.configmap, request);
			
			if (logger.isDebugEnabled()) {
				logger.info("Loading " + localTarget + "." + localNamespace + "." + localConfigMap);
			}
			Map<String,String> cm = K8sUtils.loadConfigMap(localTarget, localNamespace, localConfigMap);
			
			logger.info("map : " + cm.toString());
			
			for (String wfname : mapping.keySet()) {
				logger.info("wfname : " + wfname);
				String cmname = this.mapping.get(wfname);
				logger.info("cmname : " + cmname);
				String cmval = cm.get(cmname);
				logger.info("cmval : " + cmval);
				if (cmval == null) {
					StringBuilder sb = new StringBuilder();
					sb.append("Unable to find key '").append(cmname).append("' in ").append(namespace).append(".").append(configmap);
					logger.warn(sb.toString());
				} else {
					logger.info("putting " + wfname + " - " + cmval);
					request.put(wfname, cmval);
				}
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not load configmap " + this.configmap + " from " + this.namespace);
		}
		
		return true;
	}

}

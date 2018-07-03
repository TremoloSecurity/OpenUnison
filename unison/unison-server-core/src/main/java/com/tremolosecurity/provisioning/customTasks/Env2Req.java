package com.tremolosecurity.provisioning.customTasks;

import java.util.HashMap;
import java.util.Map;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

/**
 * Env2Req
 */
public class Env2Req implements CustomTask {

    HashMap<String,String> mapping;

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.mapping = new HashMap<String,String>();
		for (String key : params.keySet()) {
            mapping.put(key, params.get(key).getValues().get(0));
        }
	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		
	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
        for (String key : this.mapping.keySet()) {
            request.put(key, System.getenv(this.mapping.get(key)));
        }
		return true;
	}

    
}
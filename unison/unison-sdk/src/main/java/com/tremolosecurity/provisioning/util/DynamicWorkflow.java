package com.tremolosecurity.provisioning.util;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.WorkflowType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.saml.Attribute;

public interface DynamicWorkflow {

	
	
	
	
	/**
	 * Generates a list of name/value pairs to be inserted into the request
	 * @param wf
	 * @param cfg
	 * @param params
	 * @return
	 * @throws ProvisioningException
	 */
	public List<Map<String,String>> generateWorkflows(WorkflowType wf,ConfigManager cfg,HashMap<String,Attribute> params) throws ProvisioningException;
	
}

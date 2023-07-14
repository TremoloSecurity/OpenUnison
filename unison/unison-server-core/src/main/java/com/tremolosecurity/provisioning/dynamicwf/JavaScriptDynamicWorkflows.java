package com.tremolosecurity.provisioning.dynamicwf;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Value;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.WorkflowType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.util.DynamicWorkflow;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.saml.Attribute;

public class JavaScriptDynamicWorkflows implements DynamicWorkflow {
	

	@Override
	public List<Map<String, String>> generateWorkflows(WorkflowType wf, ConfigManager cfg,
			HashMap<String, Attribute> params) throws ProvisioningException {
		return generateWorkflows(wf,cfg,params,null);
	}

	@Override
	public List<Map<String, String>> generateWorkflows(WorkflowType wf, ConfigManager cfg,
			HashMap<String, Attribute> params, AuthInfo authInfo) throws ProvisioningException {
		String javaScript = params.get("javaScript").getValues().get(0);
		Context context = Context.newBuilder("js").allowAllAccess(true).build();
		
		try {
		Value val = context.eval("js",javaScript);
		
		Value generateWorkflows = context.getBindings("js").getMember("generateWorkflows");
		if (generateWorkflows == null || ! generateWorkflows.canExecute()) {
			throw new ProvisioningException("Could not load generateWorkflows function");
		}
		
		
		Value workflows = generateWorkflows.execute(wf,cfg,params,authInfo);
		
		return (List<Map<String,String>>) workflows.as(Object.class);
		} finally {
			if (context != null) {
				context.close();
			}
		}
	}

}

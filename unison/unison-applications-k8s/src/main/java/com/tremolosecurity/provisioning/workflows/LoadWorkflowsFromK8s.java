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
package com.tremolosecurity.provisioning.workflows;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.util.List;
import java.util.Map;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.yaml.snakeyaml.Yaml;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.DynamicWorkflowType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.config.xml.WorkflowType;
import com.tremolosecurity.k8s.watch.K8sWatchTarget;
import com.tremolosecurity.k8s.watch.K8sWatcher;
import com.tremolosecurity.provisioning.core.ProvisioningEngine;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.targets.DynamicTargets;
import com.tremolosecurity.provisioning.targets.LoadTargetsFromK8s;
import com.tremolosecurity.saml.Attribute;

public class LoadWorkflowsFromK8s implements DynamicWorkflows, K8sWatchTarget {
	
static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(LoadWorkflowsFromK8s.class.getName());
	
	K8sWatcher k8sWatch;
	
	TremoloType tremolo;

	private ProvisioningEngine provisioningEngine;
	private ConfigManager cfgMgr;

	@Override
	public void addObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		JSONObject metadata = (JSONObject) item.get("metadata");
		String name = (String) metadata.get("name");
		logger.info("Creating workflow '" + name + "'");
		
		this.provisioningEngine.addDynamicWorkflow(this.createWorkflow(item, name));
		
	}

	@Override
	public void modifyObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		JSONObject metadata = (JSONObject) item.get("metadata");
		String name = (String) metadata.get("name");
		logger.info("Replacing workflow '" + name + "'");
		
		this.provisioningEngine.replaceDynamicWorkflow(this.createWorkflow(item, name));
		
	}

	@Override
	public void deleteObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		JSONObject metadata = (JSONObject) item.get("metadata");
		String name = (String) metadata.get("name");
		logger.info("Deleting workflow '" + name + "'");
		this.provisioningEngine.removeDynamicWorkflow(name);
		
	}
	
	private WorkflowType createWorkflow(JSONObject item, String name) throws ProvisioningException {
		WorkflowType wft = new WorkflowType();
		
		JSONObject spec = (JSONObject) item.get("spec");
		
		wft.setName(name);
		wft.setInList(((Boolean)spec.get("inList")));
		wft.setLabel((String)spec.get("label"));
		wft.setOrgid((String) spec.get("orgId"));
		
		JSONObject dynWfJson = (JSONObject) spec.get("dynamicConfiguration");
		if (dynWfJson != null) {
			DynamicWorkflowType dwt = new DynamicWorkflowType();
			wft.setDynamicConfiguration(dwt);
			Boolean isdyn = (Boolean) dynWfJson.get("dynamic");
			if (isdyn != null) {
				dwt.setDynamic(isdyn.booleanValue());
			}
			
			dwt.setClassName((String) dynWfJson.get("className"));
			JSONArray params = (JSONArray) dynWfJson.get("params");
			for (Object o : params) {
				JSONObject p = (JSONObject) o;
				ParamType pt = new ParamType();
				pt.setName((String)p.get("name"));
				pt.setValue((String) p.get("value"));
				dwt.getParam().add(pt);
			}
		}
		
		String wfJson = null;
		try {
			wfJson = convertYamlToJson((String) spec.get("tasks"));
			ParsedWorkflow pw = new ParseWorkflow().parseWorkflow(wfJson);
			if (pw.getError() != null) {
				throw new ProvisioningException("Invalid workflow '" + pw.getError() + "', path='" + pw.getErrorPath() + "'" );
			}
			wft.setTasks(pw.getWft().getTasks());
		} catch (JsonProcessingException e) {
			throw new ProvisioningException("Could not parse workflow tasks for '" + name + "'",e);
		}
		
		
		
		return wft;
	}
	
	
	String convertYamlToJson(String yaml) throws JsonMappingException, JsonProcessingException {
	    ObjectMapper yamlReader = new ObjectMapper(new YAMLFactory());
	    Object obj = yamlReader.readValue(yaml, Object.class);

	    ObjectMapper jsonWriter = new ObjectMapper();
	    return jsonWriter.writeValueAsString(obj);
	}

	@Override
	public void loadDynamicWorkflows(ConfigManager cfgMgr, ProvisioningEngine provisioningEngine,
			Map<String, Attribute> init) throws ProvisioningException {
		
		this.tremolo = cfgMgr.getCfg();
		String k8sTarget = 	init.get("k8starget").getValues().get(0);
		String namespace = init.get("namespace").getValues().get(0);
		String uri = "/apis/openunison.tremolo.io/v1/namespaces/" + namespace + "/workflows";
		
		
		this.provisioningEngine = provisioningEngine;
		this.cfgMgr = cfgMgr;
		
		this.k8sWatch = new K8sWatcher(k8sTarget,namespace,uri,this,cfgMgr,provisioningEngine);
		
		this.k8sWatch.initalRun();
		
	}



}

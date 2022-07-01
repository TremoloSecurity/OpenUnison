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
package com.tremolosecurity.provisioning.reports;

import java.util.HashMap;
import java.util.Map;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.OrgType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.ReportType;
import com.tremolosecurity.config.xml.TargetAttributeType;
import com.tremolosecurity.config.xml.TargetConfigType;
import com.tremolosecurity.config.xml.TargetType;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.k8s.watch.K8sWatchTarget;
import com.tremolosecurity.k8s.watch.K8sWatcher;
import com.tremolosecurity.openunison.util.config.OpenUnisonConfigLoader;
import com.tremolosecurity.provisioning.core.ProvisioningEngine;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.targets.DynamicTargets;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;

public class LoadReportsFromK8s implements DynamicReports, K8sWatchTarget {
	
	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(LoadReportsFromK8s.class.getName());
	
	K8sWatcher k8sWatch;
	
	TremoloType tremolo;

	private ProvisioningEngine provisioningEngine;
	private ConfigManager cfgMgr;

	@Override
	public void addObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		
		JSONObject metadata = (JSONObject) item.get("metadata");
		String name = (String) metadata.get("name");
		logger.info("Creating report '" + name + "'");
		createReport(item,name);
		
		
	}

	private void createReport(JSONObject item,String name) {
		ReportType report = new ReportType();
		JSONObject spec = (JSONObject) item.get("spec");
		
		StringBuffer b = new StringBuffer();
		
		b.setLength(0);
		OpenUnisonConfigLoader.integrateIncludes(b,(String) spec.get("name")  );
		report.setName(b.toString() );
		
		b.setLength(0);
		OpenUnisonConfigLoader.integrateIncludes(b,(String) spec.get("description")  );
		report.setDescription(b.toString() );
		
		b.setLength(0);
		OpenUnisonConfigLoader.integrateIncludes(b,(String) spec.get("orgId")  );
		report.setOrgID(b.toString() );
		
		b.setLength(0);
		OpenUnisonConfigLoader.integrateIncludes(b,(String) spec.get("sql")  );
		report.setSql(b.toString() );
		
		if (spec.get("groupings") == null) {
			report.setGroupings(false);
		} else {
			
			report.setGroupings((Boolean) spec.get("groupings"));
			
			if (report.isGroupings()) {
				b.setLength(0);
				OpenUnisonConfigLoader.integrateIncludes(b,(String) spec.get("groupBy")  );
				report.setGroupBy(b.toString() );
			}
		}
		
		if (spec.get("parameters") != null) {
			
			JSONObject parameters = (JSONObject) spec.get("parameters");
			Boolean beginDate = (Boolean) parameters.get("beginDate");
			if (beginDate != null && beginDate) {
				report.getParamater().add("beginDate");
			}
			
			Boolean endDate = (Boolean) parameters.get("endDate");
			if (endDate != null && endDate) {
				report.getParamater().add("endDate");
			}
			
			Boolean userKey = (Boolean) parameters.get("userKey");
			if (userKey != null && userKey) {
				report.getParamater().add("userKey");
			}
			
			Boolean currentUser = (Boolean) parameters.get("currentUser");
			if (currentUser != null && currentUser) {
				report.getParamater().add("currentUser");
			}
		}
		
		JSONArray headerFields = (JSONArray) spec.get("headerFields");
		if (headerFields != null) {
			for (Object o : headerFields) {
				report.getHeaderFields().add((String) o);
			}
		}
		
		JSONArray dataFields = (JSONArray) spec.get("dataFields");
		if (dataFields != null) {
			for (Object o : dataFields) {
				report.getDataFields().add((String) o);
			}
		}
		
		synchronized (this.cfgMgr.getCfg().getProvisioning().getReports()) {
			ReportType existingRep = null;
			for (ReportType rt : this.cfgMgr.getCfg().getProvisioning().getReports().getReport()) {
				if (rt.getName().equals(report.getName())) {
					existingRep = rt;
					break;
				}
			}
			
			if (existingRep != null ) {
				this.cfgMgr.getCfg().getProvisioning().getReports().getReport().remove(existingRep);
			}
			
			this.cfgMgr.getCfg().getProvisioning().getReports().getReport().add(report);
		}
		
		
	}

	@Override
	public void modifyObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		JSONObject metadata = (JSONObject) item.get("metadata");
		String name = (String) metadata.get("name");
		logger.info("Replacing report '" + name + "'");
		createReport(item,name);
		

	}

	@Override
	public void deleteObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		JSONObject metadata = (JSONObject) item.get("metadata");
		String name = (String) metadata.get("name");
		JSONObject spec = (JSONObject) item.get("spec");
		logger.info("Deleting report '" + name + "'");
		String reportName = (String) spec.get("name");
		synchronized (this.cfgMgr.getCfg().getProvisioning().getReports()) {
			ReportType existingRep = null;
			for (ReportType rt : this.cfgMgr.getCfg().getProvisioning().getReports().getReport()) {
				if (rt.getName().equals(reportName)) {
					existingRep = rt;
					break;
				}
			}
			
			if (existingRep != null ) {
				this.cfgMgr.getCfg().getProvisioning().getReports().getReport().remove(existingRep);
			}
			
		}

	}

	@Override
	public void loadDynamicReports(ConfigManager cfgMgr, ProvisioningEngine provisioningEngine,
			Map<String, Attribute> init) throws ProvisioningException {
		this.tremolo = cfgMgr.getCfg();
		String k8sTarget = 	init.get("k8starget").getValues().get(0);
		String namespace = init.get("namespace").getValues().get(0);
		
		
		
		this.provisioningEngine = provisioningEngine;
		this.cfgMgr = cfgMgr;
		
		this.k8sWatch = new K8sWatcher(k8sTarget,namespace,"reports","openunison.tremolo.io",this,cfgMgr,provisioningEngine);
		
		this.k8sWatch.initalRun();

	}

}

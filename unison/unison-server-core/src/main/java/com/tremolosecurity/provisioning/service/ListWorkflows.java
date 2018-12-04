/*
Copyright 2015, 2016 Tremolo Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


package com.tremolosecurity.provisioning.service;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;
import org.stringtemplate.v4.ST;

import com.google.gson.Gson;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.WorkflowType;
import com.tremolosecurity.lastmile.LastMile;
import com.tremolosecurity.provisioning.service.util.ProvisioningError;
import com.tremolosecurity.provisioning.service.util.ProvisioningResult;
import com.tremolosecurity.provisioning.service.util.WFDescription;
import com.tremolosecurity.provisioning.service.util.WFDescriptions;
import com.tremolosecurity.provisioning.util.DynamicWorkflow;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;


public class ListWorkflows extends HttpServlet {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(ListWorkflows.class.getName());
	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		
		try {
			String uuid = req.getParameter("uuid");
			
			ConfigManager cfgMgr = GlobalEntries.getGlobalEntries().getConfigManager();
			
			List<WorkflowType> wfs = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getWorkflows().getWorkflow();
			
			ArrayList<WFDescription> workflows = new ArrayList<WFDescription>();
			
			for (WorkflowType wf : wfs) {
				
				if (wf.isInList() != null && wf.isInList().booleanValue()) {
					
					if ( wf.getOrgid() == null || wf.getOrgid().equalsIgnoreCase(uuid)) { 
						
						if (wf.getDynamicConfiguration() != null && wf.getDynamicConfiguration().isDynamic()) {
							HashMap<String,Attribute> params = new HashMap<String,Attribute>();
							if (wf.getDynamicConfiguration().getParam() != null) {
								for (ParamType p : wf.getDynamicConfiguration().getParam()) {
									Attribute attr = params.get(p.getName());
									if (attr == null) {
										attr = new Attribute(p.getName());
										params.put(p.getName(), attr);
									}
									attr.getValues().add(p.getValue());
								}
							}
							
							
							DynamicWorkflow dwf = (DynamicWorkflow) Class.forName(wf.getDynamicConfiguration().getClassName()).newInstance();
							
							List<Map<String,String>> wfParams = dwf.generateWorkflows(wf, GlobalEntries.getGlobalEntries().getConfigManager(), params);
							
							StringBuffer b = new StringBuffer();
							b.append('/').append(URLEncoder.encode(wf.getName(),"UTF-8"));
							String uri = b.toString();
							for (Map<String,String> wfParamSet : wfParams) {
								DateTime now = new DateTime();
								DateTime expires = now.plusHours(1);
								
								LastMile lm = new LastMile(uri,now,expires,0,"");
								for (String key : wfParamSet.keySet()) {
									String val = wfParamSet.get(key);
									Attribute attr = new Attribute(key,val);	
									lm.getAttributes().add(attr);
								}
								
								WFDescription desc = new WFDescription();
								desc.setUuid(UUID.randomUUID().toString());
								desc.setName(wf.getName());
								
								ST st = new ST(wf.getLabel(),'$','$');
								for (String key : wfParamSet.keySet()) {
									st.add(key.replaceAll("[.]", "_"), wfParamSet.get(key));
								}
								
								desc.setLabel(st.render());
								
								
								st = new ST(wf.getDescription(),'$','$');
								for (String key : wfParamSet.keySet()) {
									st.add(key.replaceAll("[.]", "_"), wfParamSet.get(key));
								}
								desc.setDescription(st.render());
								
								desc.setEncryptedParams(lm.generateLastMileToken(cfgMgr.getSecretKey(cfgMgr.getCfg().getProvisioning().getApprovalDB().getEncryptionKey())));
								
								workflows.add(desc);
								
							}
							
							
						} else {
							WFDescription desc = new WFDescription();
							
							desc.setUuid(UUID.randomUUID().toString());
							desc.setName(wf.getName());
							desc.setLabel(wf.getLabel());
							desc.setDescription(wf.getDescription());
							
							
							workflows.add(desc);
						}
						
						
					}
				}
				
				
			}
			
			WFDescriptions descs = new WFDescriptions();
			descs.setWorkflows(workflows);
			
			Gson gson = new Gson();
			
			ProvisioningResult pres = new ProvisioningResult();
			pres.setSuccess(true);
			pres.setWfDescriptions(descs);
			
			resp.getOutputStream().print(gson.toJson(pres));
		} catch (Exception e) {
			
			logger.error("Could not load workflows",e);
			
			Gson gson = new Gson();
			
			ProvisioningResult pres = new ProvisioningResult();
			pres.setSuccess(false);
			pres.setError(new ProvisioningError("Could not load workflows"));
			
			resp.getOutputStream().print(gson.toJson(pres));
		}
	}
	
}

/*
Copyright 2015 Tremolo Security, Inc.

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
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.gson.Gson;
import com.tremolosecurity.config.xml.WorkflowType;
import com.tremolosecurity.provisioning.service.util.ProvisioningResult;
import com.tremolosecurity.provisioning.service.util.WFDescription;
import com.tremolosecurity.provisioning.service.util.WFDescriptions;
import com.tremolosecurity.server.GlobalEntries;


public class ListWorkflows extends HttpServlet {

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		
		String uuid = req.getParameter("uuid");
		
		
		
		List<WorkflowType> wfs = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getWorkflows().getWorkflow();
		
		ArrayList<WFDescription> workflows = new ArrayList<WFDescription>();
		
		for (WorkflowType wf : wfs) {
			
			if (wf.isInList() != null && wf.isInList().booleanValue()) {
				
				if (uuid == null || wf.getOrgid() == null || wf.getOrgid().equalsIgnoreCase(uuid)) { 
				
					WFDescription desc = new WFDescription();
					
					desc.setName(wf.getName());
					desc.setLabel(wf.getLabel());
					desc.setDescription(wf.getDescription());
					
					
					workflows.add(desc);
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
	}
	
}

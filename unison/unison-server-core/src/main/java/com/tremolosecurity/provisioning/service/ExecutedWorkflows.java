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
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.hibernate.Query;
import org.hibernate.Session;

import com.google.gson.Gson;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.objects.Approvals;
import com.tremolosecurity.provisioning.objects.Workflows;
import com.tremolosecurity.provisioning.service.util.ProvisioningError;
import com.tremolosecurity.provisioning.service.util.ProvisioningResult;
import com.tremolosecurity.server.GlobalEntries;


public class ExecutedWorkflows extends HttpServlet {

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		String userKey = req.getParameter("user");
		Session session = null;
		try {
			session = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getHibernateSessionFactory().openSession();
			//PreparedStatement ps = con.prepareStatement("select workflows.id,workflows.name from workflows inner join users on users.id=workflows.userid where workflows.completeTS IS NOT NULL AND userKey=?");
			
			Query query = session.createQuery("FROM Workflows WHERE Workflows.completeTS IS NOT NULL AND Workflows.users.userKey = :user_key");
			query.setParameter("user_key", userKey);
			List<com.tremolosecurity.provisioning.objects.Workflows> workflows = query.list();
			
			ArrayList<String> workflowids = new ArrayList<String>();
			
			for (Workflows wf : workflows) {
				if (wf.getApprovals().isEmpty()) {
					workflowids.add(wf.getName());
				} else {
					boolean approved = true;
					for (Approvals approval : wf.getApprovals()) {
						approved  = approved && (approval.getApproved() == 1 && approval.getApprovedTs() != null);
					}
				}
			}
			
			
			
			
			Gson gson = new Gson();
			ProvisioningResult resObj = new ProvisioningResult();
			resObj.setSuccess(true);
			resObj.setWorkflowIds(workflowids);
			resp.getOutputStream().println(gson.toJson(resObj));
		} catch (Exception e) {
			
			ProvisioningError pe = new ProvisioningError();
			pe.setError("Could not load executed workflows : " + e.getMessage());
			ProvisioningResult res = new ProvisioningResult();
			res.setSuccess(false);
			res.setError(pe);
			Gson gson = new Gson();
			
			resp.getWriter().write(gson.toJson(res));
			
			
		} finally {
			if (session != null) {
				session.close();
			}
		}
	}

}

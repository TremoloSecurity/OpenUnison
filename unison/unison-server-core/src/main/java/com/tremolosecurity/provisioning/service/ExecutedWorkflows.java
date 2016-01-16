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
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.gson.Gson;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.service.util.ProvisioningError;
import com.tremolosecurity.provisioning.service.util.ProvisioningResult;
import com.tremolosecurity.server.GlobalEntries;


public class ExecutedWorkflows extends HttpServlet {

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		String userKey = req.getParameter("user");
		Connection con = null;
		try {
			con = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getApprovalDBConn();
			PreparedStatement ps = con.prepareStatement("select workflows.id,workflows.name from workflows inner join users on users.id=workflows.userid where workflows.completeTS IS NOT NULL AND userKey=?");
			ps.setString(1, userKey);
			ResultSet rs = ps.executeQuery();
			ArrayList<String> workflowids = new ArrayList<String>();
			PreparedStatement approvals = con.prepareStatement("select * from approvals where workflow=? order by approvedTS DESC");
			while (rs.next()) {
				int id = rs.getInt("id");
				String name = rs.getString("name");
				
				approvals.setInt(1, id);
				ResultSet compApprovals = approvals.executeQuery();
				
				if (compApprovals.next()) {
					if (compApprovals.getInt("approved") == 1) {
						workflowids.add(rs.getString("name"));
					}
				} else {
					//no approval
					workflowids.add(rs.getString("name"));
				}
				
				compApprovals.close();
				
				
			}
			
			rs.close();
			ps.close();
			approvals.close();
			
			Gson gson = new Gson();
			ProvisioningResult resObj = new ProvisioningResult();
			resObj.setSuccess(true);
			resObj.setWorkflowIds(workflowids);
			resp.getOutputStream().println(gson.toJson(resObj));
		} catch (SQLException e) {
			
			ProvisioningError pe = new ProvisioningError();
			pe.setError("Could not load executed workflows : " + e.getMessage());
			ProvisioningResult res = new ProvisioningResult();
			res.setSuccess(false);
			res.setError(pe);
			Gson gson = new Gson();
			
			resp.getWriter().write(gson.toJson(res));
			
			
		} finally {
			if (con != null) {
				try {
					con.close();
				} catch (SQLException e) {
					
				}
			}
		}
	}

}

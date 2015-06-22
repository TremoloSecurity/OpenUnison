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


package com.tremolosecurity.provisioning.scheduler.jobs;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.apache.log4j.Logger;
import org.quartz.JobExecutionContext;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.scheduler.UnisonJob;



public class RemindApprovers extends UnisonJob {

	static Logger logger = Logger.getLogger(RemindApprovers.class.getName());
	
	@Override
	public void execute(ConfigManager configManager, JobExecutionContext context)
			throws ProvisioningException {
		
		if (configManager == null || configManager.getProvisioningEngine() == null) {
			logger.warn("System not fully initialized");
			return;
		}
		
		String sql = context.getJobDetail().getJobDataMap().getString("sql");
		String msg = context.getJobDetail().getJobDataMap().getString("message");
		int days = Integer.parseInt(context.getJobDetail().getJobDataMap().getString("days"));
		
		Connection con = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		try {
			
			
			
			
			con = configManager.getProvisioningEngine().getApprovalDBConn();
			ps = con.prepareStatement(sql);
			ps.setInt(1, days);
			rs = ps.executeQuery();
			while (rs.next()) {
				int daysOpen = rs.getInt("daysOpen");
				String label = rs.getString("label");
				String mail = rs.getString("mail");
				
				if (logger.isDebugEnabled()) {
					logger.debug("Notifying " + mail + " for " + label + " after " + daysOpen + " days");
				}
				
				String toSend = msg.replaceAll("[%]L", label).replaceAll("[%]D", Integer.toString(daysOpen));
				
				configManager.getProvisioningEngine().sendNotification(mail, toSend, "Open Approval for " + daysOpen + " days", new User(mail));
				
			}
		} catch (Exception e) {
			throw new ProvisioningException("Error reminding open approvers",e);
		} finally {
			try {
				if (rs != null) {
					rs.close();
				}
			} catch (SQLException e) {
				
			}
			
			try {
				if (ps != null) {
					ps.close();
				}
			} catch (SQLException e) {
				
			}
			
			try {
				if (con != null) {
					con.close();
				}
			} catch (SQLException e) {
				
			}
		}

	}

}

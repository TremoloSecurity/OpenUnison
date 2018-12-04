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


package com.tremolosecurity.provisioning.customTasks;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import java.util.HashSet;
import java.util.Map;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningTarget;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.core.providers.BasicDBInterface;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

public class JITBasicDBCreateGroups implements CustomTask {

	/**
	 * 
	 */
	private static final long serialVersionUID = -2741684082140777971L;
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(JITBasicDBCreateGroups.class.getName());
	transient WorkflowTask task;
	transient BasicDBInterface dbProvider;
	String targetName;
	transient String groupTableName;
	transient String nameField;
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params)
			throws ProvisioningException {
		this.task = task;
		Attribute attr = params.get("targetName");
		if (attr == null) {
			throw new ProvisioningException("targetName not set");
		}
		this.targetName = attr.getValues().get(0);
		this.loadGroupData();
	}
	
	private void loadGroupData() throws ProvisioningException {
		ProvisioningTarget target = task.getConfigManager().getProvisioningEngine().getTarget(this.targetName);
		if (target == null) {
			throw new ProvisioningException("Target '" + targetName + "' not found");
		}
		this.dbProvider = (BasicDBInterface) target.getProvider();
		this.groupTableName = this.dbProvider.getGroupTable();
		this.nameField = this.dbProvider.getGroupName();
	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;
		this.loadGroupData();

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request)
			throws ProvisioningException {
		
		if (user.getGroups().size() > 0) {
			Connection con = null;
			StringBuffer b = new StringBuffer();
			b.append("SELECT ").append(this.nameField).append(" FROM ").append(this.groupTableName).append(" WHERE ");
			for (String group : user.getGroups()) {
				b.append(this.nameField).append("=? OR ");
			}
			String sql = b.toString();
			sql = sql.substring(0,sql.length() - 3);
			if (logger.isDebugEnabled()) {
				logger.debug("SQL - " + sql);
			}
			
			try {
				con = this.dbProvider.getDS().getConnection();
				PreparedStatement ps = con.prepareStatement(sql);
				for (int i=0;i<user.getGroups().size();i++) {
					ps.setString(i + 1, user.getGroups().get(i));
				}
				ResultSet rs = ps.executeQuery();
				HashSet<String> existingGroups = new HashSet<String>();
				while (rs.next()) {
					existingGroups.add(rs.getString(this.nameField));
				}
				
				rs.close();
				ps.close();
				
				b.setLength(0);
				b.append("INSERT INTO ").append(this.groupTableName).append(" (").append(this.nameField).append(") VALUES (?)");
				ps = con.prepareStatement(b.toString());
				for (String groupName : user.getGroups()) {
					if (! existingGroups.contains(groupName)) {
						ps.setString(1, groupName);
						ps.executeUpdate();
						if (logger.isDebugEnabled()) {
							logger.debug("Adding group '" + groupName + "'");
						}
					}
				}
				ps.close();
			} catch (SQLException e) {
				throw new ProvisioningException("Could not update groups",e);
			} finally {
				if (con != null) {
					try {
						con.close();
					} catch (SQLException se) {
						
					}
				}
			}
		}
		
		return true;
		
	}

}

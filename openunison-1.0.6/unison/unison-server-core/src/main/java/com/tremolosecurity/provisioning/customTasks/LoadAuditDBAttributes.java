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


package com.tremolosecurity.provisioning.customTasks;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Map;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.core.providers.BasicDB;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

public class LoadAuditDBAttributes implements CustomTask {

	ArrayList<String> attrs;
	String nameAttr;
	transient ConfigManager cfg;
	
	
	transient WorkflowTask task;
	
	String SQL;
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params)
			throws ProvisioningException {
		this.attrs = new ArrayList<String>();
		Attribute cfgAttrs = params.get("name");
		
		for (String name : cfgAttrs.getValues()) {
			attrs.add(name);
		}
		
		this.nameAttr = params.get("nameAttr").getValues().get(0);
		
		this.cfg = task.getConfigManager();
		
		
		this.task = task;
		
		StringBuffer select = new StringBuffer();
		select.append("SELECT ");
		for (String name : attrs) {
			select.append(name).append(", ");
		}
		
		select.setLength(select.length() - 2);
		select.append(" FROM users WHERE userKey=?");
		
		this.SQL = select.toString();

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.cfg = task.getConfigManager();
		this.task = task;

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request)
			throws ProvisioningException {
		
		Connection con = null;
		
		try {
			con = this.cfg.getProvisioningEngine().getApprovalDBConn();
			
			PreparedStatement ps = con.prepareStatement(this.SQL);
			ps.setString(1, user.getAttribs().get(this.nameAttr).getValues().get(0));
			ResultSet rs = ps.executeQuery();
			
			if (rs.next()) {
				for (String name : this.attrs) {
					String val = rs.getString(name);
					if (val != null) {
						user.getAttribs().put(name, new Attribute(name,val));
					}
				}
			}
			
			rs.close();
			ps.close();
			
		} catch (SQLException e) {
			throw new ProvisioningException("Could not load attributes",e);
		} finally {
			if (con != null) {
				try {
					con.close();
				} catch (Exception e1) {
					//do nothing
				}
			}
		}
		
		return true;
		
	}

	

}

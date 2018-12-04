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


package com.tremolosecurity.unison.drupal.drupal7.provisioning;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.core.providers.BasicDBInterface;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

public class Drupal7GetSequence implements CustomTask {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(Drupal7GetSequence.class.getName());
	
	transient WorkflowTask task;
	String targetName;
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params)
			throws ProvisioningException {
		this.task = task;
		this.targetName = params.get("targetName").getValues().get(0);

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request)
			throws ProvisioningException {
		
		try {
			
			if (logger.isDebugEnabled()) {
				logger.debug("Searching for users.id");
				logger.debug("Looking for user : '" + user.getUserID() + "'");
			}
			
			User looking = task.getConfigManager().getProvisioningEngine().getTarget(this.targetName).findUser(user.getUserID(), new HashMap<String,Object>());
			
			if (logger.isDebugEnabled()) {
				logger.debug("User object : '" + looking + "'");
			}
			
			if (looking == null) {
				if (logger.isDebugEnabled()) {
					logger.debug("User not found");
				}
			}
			
			if (looking != null) {
				if (logger.isDebugEnabled()) {
					logger.debug("User found, setting to user id : '" + looking.getAttribs().get("uid").getValues().get(0) + "'");
				}
				user.getAttribs().put("drupalid",new Attribute("drupalid",looking.getAttribs().get("uid").getValues().get(0)));
				return true;
			}
		} catch (ProvisioningException pe) {
			//do nothing
			pe.printStackTrace();
		}
		
		
		UserStoreProvider provider = task.getConfigManager().getProvisioningEngine().getTarget(this.targetName).getProvider();
		BasicDBInterface dbprovider = (BasicDBInterface) provider;
		Connection con = null;
		try {
			if (logger.isDebugEnabled()) {
				logger.debug("Getting Connection");
			}
			
			con = dbprovider.getDS().getConnection();
			
			if (logger.isDebugEnabled()) {
				logger.debug("Preparing Statement");
			}
			
			PreparedStatement ps = con.prepareStatement("INSERT INTO sequences () VALUES ()",Statement.RETURN_GENERATED_KEYS);
			
			if (logger.isDebugEnabled()) {
				logger.debug("Executing Statement");
			}
			
			ps.executeUpdate();
			
			if (logger.isDebugEnabled()) {
				logger.debug("Getting key");
			}
			
			ResultSet rs = ps.getGeneratedKeys();
			rs.next();
			int id = rs.getInt(1);
			
			if (logger.isDebugEnabled()) {
				logger.debug("ID: '" + id + "'");
			}
			
			rs.close();
			ps.close();
			
			user.getAttribs().put("drupalid", new Attribute("drupalid",Integer.toString(id)));
			return true;
		} catch (SQLException e) {
			throw new ProvisioningException("Could not generate userid",e);
		} finally {
			if (con != null) {
				try {
					logger.info("Closing connection");
					con.close();
				} catch (Exception e1) {
					//do nothing
				}
			}
		}
		
		
		
		
	}

}

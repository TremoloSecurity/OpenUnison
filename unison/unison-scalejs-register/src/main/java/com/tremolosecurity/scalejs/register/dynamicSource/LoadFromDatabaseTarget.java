/*******************************************************************************
 * Copyright 2019 Tremolo Security, Inc.
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
package com.tremolosecurity.scalejs.register.dynamicSource;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.tremolosecurity.provisioning.core.providers.BasicDB;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.scalejs.cfg.ScaleAttribute;
import com.tremolosecurity.scalejs.sdk.SourceList;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.util.NVP;

public class LoadFromDatabaseTarget implements SourceList {

	String targetName;
	String noParamSQL;
	String paramSQL;
	String exactSQL;
	String nameField;
	String valueField;
	String errorMessage;
	int maxEntries;
	
	
	@Override
	public void init(ScaleAttribute attribute, Map<String, Attribute> config) {
		targetName = config.get("targetName").getValues().get(0);
		noParamSQL = config.get("noParamSQL").getValues().get(0);
		paramSQL = config.get("paramSQL").getValues().get(0);
		nameField = config.get("nameField").getValues().get(0);
		valueField = config.get("valueField").getValues().get(0);
		if (config.get("maxEntrie") == null) {
			maxEntries = Integer.parseInt(config.get("maxEntries").getValues().get(0));
		} else {
			maxEntries = Integer.parseInt(config.get("maxEntrie").getValues().get(0));
		}
		exactSQL = config.get("exactSQL").getValues().get(0);
		errorMessage = config.get("errorMessage").getValues().get(0);
		
	}

	@Override
	public List<NVP> getSourceList(HttpFilterRequest request) throws Exception {
		if (request.getParameter("search") == null) {
			BasicDB db = (BasicDB) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.targetName).getProvider();
			Connection con = db.getDS().getConnection();
			try {
				ArrayList<NVP> toReturn = new ArrayList<NVP>();
				
				Statement stmt = con.createStatement();
				ResultSet rs = stmt.executeQuery(noParamSQL);
				
				while (rs.next()) {
					toReturn.add(new NVP(rs.getString(nameField),rs.getString(valueField)));
					if (this.maxEntries > 0 && toReturn.size() > this.maxEntries) {
						rs.close();
						stmt.close();
						break;
					}
				}
				
				return toReturn;
			} finally {
				if (con != null) {
					con.close();
				}
			}
		} else {
			BasicDB db = (BasicDB) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.targetName).getProvider();
			Connection con = db.getDS().getConnection();
			try {
				ArrayList<NVP> toReturn = new ArrayList<NVP>();
				
				PreparedStatement stmt = con.prepareStatement(this.paramSQL);
				stmt.setString(1, "%" + request.getParameter("search").getValues().get(0) + "%");
				ResultSet rs = stmt.executeQuery();
				
				while (rs.next()) {
					toReturn.add(new NVP(rs.getString(nameField),rs.getString(valueField)));
					if (this.maxEntries > 0 && toReturn.size() > this.maxEntries) {
						rs.close();
						stmt.close();
						break;
					}
				}
				
				return toReturn;
			} finally {
				if (con != null) {
					con.close();
				}
			}
			
			
		}
	}

	@Override
	public String validate(String value, HttpFilterRequest request) throws Exception {
		BasicDB db = (BasicDB) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.targetName).getProvider();
		Connection con = db.getDS().getConnection();
		
		try {
			PreparedStatement stmt = con.prepareStatement(this.exactSQL);
			stmt.setString(1, value);
			ResultSet rs = stmt.executeQuery();
			
			String error = null;
			
			if (! rs.next()) {
				error = this.errorMessage;
			}
			
			rs.close();
			stmt.close();
			
			return error;
		} finally {
			if (con != null) {
				con.close();
			}
		}
	}

}

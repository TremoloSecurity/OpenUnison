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


package com.tremolosecurity.unison.drupal.drupal6.provisioning;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.providers.db.CustomDB;
import com.tremolosecurity.saml.Attribute;

public class DrupalProvider implements CustomDB {
	
	static Logger logger = Logger.getLogger(DrupalProvider.class.getName());
	
	static Set<String> primaryFields;
	static Map<String,Integer> fieldIDs;
	static Map<String,Integer> roleIDs;
	
	static {
		primaryFields = new HashSet<String>();
		primaryFields.add("name");
		primaryFields.add("pass");
		primaryFields.add("mail");
		primaryFields.add("mode");
		primaryFields.add("sort");
		primaryFields.add("threshhold");
		primaryFields.add("theme");
		primaryFields.add("signature");
		primaryFields.add("signature_format");
		primaryFields.add("created");
		primaryFields.add("access");
		primaryFields.add("login");
		primaryFields.add("status");
		primaryFields.add("timezone");
		primaryFields.add("language");
		primaryFields.add("picture");
		primaryFields.add("init");
		primaryFields.add("data");
		
		fieldIDs = new HashMap<String,Integer>();
		roleIDs = new HashMap<String,Integer>();
	}

	@Override
	public int createUser(Connection con, User user,
			Map<String, Attribute> attributes) throws ProvisioningException {
		StringBuffer insertSQL = new StringBuffer().append("INSERT INTO users (");
		
		ArrayList<String> vals = new ArrayList<String>();
		boolean first = true;
		for (String fieldName : attributes.keySet()) {
			if (primaryFields.contains(fieldName)) {
				Attribute attr = attributes.get(fieldName);
				vals.add(attr.getValues().get(0));
				if (! first) {
					insertSQL.append(',');
				} else {
					first = false;
				}
				
				insertSQL.append(attr.getName());
			}
		}
		
		insertSQL.append(") VALUES (");
		
		first = true;
		for (int i=0;i<vals.size();i++) {
			if (! first) {
				insertSQL.append(',');
			} else {
				first = false;
			}
			insertSQL.append('?');
		}
		
		insertSQL.append(')');
		
		if (logger.isDebugEnabled()) {
			logger.debug("SQL : '" + insertSQL.toString() + "'");
		}
		
		try {
			PreparedStatement psInsert = con.prepareStatement(insertSQL.toString(),Statement.RETURN_GENERATED_KEYS);
			for (int i=1;i<=vals.size();i++) {
				psInsert.setString(i, vals.get(i-1));
			}
			
			psInsert.executeUpdate();
			
			ResultSet rs = psInsert.getGeneratedKeys();
			rs.next();
			int id = rs.getInt(1);
			rs.close();
			psInsert.close();
			
			psInsert = con.prepareStatement("INSERT INTO profile_values (fid,uid,value) VALUES (?,?,?)");
			PreparedStatement psField = con.prepareStatement("SELECT fid FROM profile_fields WHERE name=?");
			
			for (String fieldName : attributes.keySet()) {
				if (! primaryFields.contains(fieldName)) {
					loadPofileNameID(psField, fieldName);
					
					int fieldID = fieldIDs.get(fieldName);
					psInsert.setInt(1, fieldID);
					psInsert.setInt(2, id);
					psInsert.setString(3,attributes.get(fieldName).getValues().get(0));
					psInsert.executeUpdate();
				}
			}
			
			psInsert.close();
			psField.close();
			
			return id;
			
		} catch (SQLException e) {
			throw new ProvisioningException("Could not create user",e);
		}
		
	}

	public void loadPofileNameID(PreparedStatement psField, String fieldName)
			throws SQLException, ProvisioningException {
		ResultSet rs;
		
		
		
		if (! fieldIDs.containsKey(fieldName)) {
			psField.setString(1, fieldName);
			rs = psField.executeQuery();
			if (! rs.next()) {
				StringBuffer b = new StringBuffer();
				b.append("There is no field named '").append(fieldName).append("' in Drupal");
				throw new ProvisioningException(b.toString());
			} else {
				int fid = rs.getInt("fid");
				fieldIDs.put(fieldName, fid);
				rs.close();
			}
			
		}
	}

	@Override
	public void addGroup(Connection con, int id, String name)
			throws ProvisioningException {
		try {
			if (! roleIDs.containsKey(name)) {
				PreparedStatement ps = con.prepareStatement("SELECT rid FROM role WHERE name=?");
				ps.setString(1, name);
				ResultSet rs = ps.executeQuery();
				if (! rs.next()) {
					rs.close();
					ps.close();
					StringBuffer b = new StringBuffer();
					b.append("Role '").append(name).append("' does not exist in Drupal");
					throw new ProvisioningException(b.toString());
				} else {
					int rid = rs.getInt("rid");
					roleIDs.put(name, rid);
					rs.close();
					ps.close();
				}
			}
			
			int rid = roleIDs.get(name);
			PreparedStatement ps = con.prepareStatement("INSERT INTO users_roles (uid,rid) VALUES (?,?)");
			ps.setInt(1,id);
			ps.setInt(2, rid);
			ps.executeUpdate();
			ps.close();
			
		} catch (SQLException e) {
			throw new ProvisioningException("Can not add group to user",e);
		}

	}

	@Override
	public void deleteGroup(Connection con, int id, String name)
			throws ProvisioningException {
		try {
			if (! roleIDs.containsKey(name)) {
				PreparedStatement ps = con.prepareStatement("SELECT rid FROM role WHERE name=?");
				ps.setString(1, name);
				ResultSet rs = ps.executeQuery();
				if (! rs.next()) {
					rs.close();
					ps.close();
					StringBuffer b = new StringBuffer();
					b.append("Role '").append(name).append("' does not exist in Drupal");
					throw new ProvisioningException(b.toString());
				} else {
					int rid = rs.getInt("rid");
					roleIDs.put(name, rid);
					rs.close();
					ps.close();
				}
			}
			
			int rid = roleIDs.get(name);
			PreparedStatement ps = con.prepareStatement("DELETE FROM users_roles WHERE uid=? AND rid=?");
			ps.setInt(1,id);
			ps.setInt(2, rid);
			ps.executeUpdate();
			ps.close();
			
		} catch (SQLException e) {
			throw new ProvisioningException("Can not add group to user",e);
		}

	}

	@Override
	public void deleteUser(Connection con, int id) throws ProvisioningException {
		try {
			PreparedStatement ps = con.prepareStatement("DELETE FROM user WHERE uid=?");
			ps.setInt(1, id);
			ps.executeUpdate();
			ps.close();
			
			ps = con.prepareStatement("DELETE FROM users_roles WHERE uid=?");
			ps.setInt(1, id);
			ps.executeUpdate();
			ps.close();
			
			ps = con.prepareStatement("DELETE FROM profile_fields WHERE uid=?");
			ps.setInt(1, id);
			ps.executeUpdate();
			ps.close();
			
			
		} catch (SQLException e) {
			throw new ProvisioningException("Could not delete user",e);
		}
		

	}

	@Override
	public void beginUpdate(Connection con, int id,
			Map<String, Object> request) throws ProvisioningException {
		

	}

	@Override
	public void updateField(Connection con, int id,
			Map<String, Object> request, String attributeName,
			String oldValue, String newValue) throws ProvisioningException {
		try {
			if (primaryFields.contains(attributeName)) {
				StringBuffer sql = new StringBuffer();
				sql.append("UPDATE users SET ").append(attributeName).append("=? WHERE uid=?");
				PreparedStatement ps = con.prepareStatement(sql.toString());
				ps.setString(1, newValue);
				ps.setInt(2, id);
				ps.executeUpdate();
				ps.close();
			} else {
				PreparedStatement psField = con.prepareStatement("SELECT fid FROM profile_fields WHERE name=?");
				loadPofileNameID(psField, attributeName);
				int fid = fieldIDs.get(attributeName);
				psField.close();
				
				PreparedStatement ps = con.prepareStatement("UPDATE profile_values SET value=? WHERE fid=? AND uid=?");
				ps.setString(1, newValue);
				ps.setInt(2,fid);
				ps.setInt(3, id);
				int res = ps.executeUpdate();
				ps.close();
				if (res == 0) {
					ps = con.prepareStatement("INSERT INTO profile_values (fid,uid,value) VALUES (?,?,?)");
					ps.setInt(1,fid);
					ps.setInt(2, id);
					ps.setString(3, newValue);
					ps.executeUpdate();
					ps.close();
				}
			}
		} catch (SQLException e) {
			StringBuffer b = new StringBuffer();
			b.append("Could not update user attribute '").append(attributeName).append("'");
			throw new ProvisioningException(b.toString(),e);
		}

	}

	@Override
	public void clearField(Connection con, int id,
			Map<String, Object> request, String attributeName,
			String oldValue) throws ProvisioningException {
		try {
			PreparedStatement psField = con.prepareStatement("SELECT fid FROM profile_fields WHERE name=?");
			loadPofileNameID(psField, attributeName);
			int fid = fieldIDs.get(attributeName);
			
			PreparedStatement ps = con.prepareStatement("DELETE FROM profile_values WHERE fid=? AND uid=?");
			ps.setInt(1,fid);
			ps.setInt(2, id);
			ps.executeUpdate();
			ps.close();
			
			
		} catch (SQLException e) {
			StringBuffer b = new StringBuffer("Could not clear user attribute '").append(attributeName).append("'");
			throw new ProvisioningException(b.toString(),e);
		}

	}

	@Override
	public void completeUpdate(Connection con, int id,
			Map<String, Object> request) throws ProvisioningException {
		
		
	}

	@Override
	public boolean listCustomGroups() {
	
		return false;
	}

	@Override
	public List<String> findGroups(Connection con, int id,
			Map<String, Object> request) throws ProvisioningException {
		// TODO Auto-generated method stub
		return null;
	}

	

}

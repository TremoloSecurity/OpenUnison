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


package com.tremolosecurity.unison.provisioning.providers.ext;

import java.sql.Connection;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashSet;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.providers.db.CustomDB;
import com.tremolosecurity.saml.Attribute;

public class WordPressProvider implements CustomDB {

	Logger logger = Logger.getLogger(WordPressProvider.class.getName());
	
	HashSet<String> wp_usersFields;
	
	public WordPressProvider() {
		this.wp_usersFields = new HashSet<String>();
		this.wp_usersFields.add("user_login");
		this.wp_usersFields.add("user_pass");
		this.wp_usersFields.add("user_nicename");
		this.wp_usersFields.add("user_email");
		this.wp_usersFields.add("user_url");
		this.wp_usersFields.add("user_registered");
		this.wp_usersFields.add("user_activation_key");
		this.wp_usersFields.add("user_status");
		this.wp_usersFields.add("display_name");
	}
	
	@Override
	public int createUser(Connection con, User user,
			Map<String, Attribute> attributes) throws ProvisioningException {
		try {
			PreparedStatement psinsert = con.prepareStatement("INSERT INTO wp_users (user_login,user_nicename,user_email,user_registered,user_status,display_name) VALUES (?,?,?,?,?,?)",Statement.RETURN_GENERATED_KEYS);
			psinsert.setString(1, user.getUserID());
			psinsert.setString(2, attributes.get("user_nicename").getValues().get(0));
			psinsert.setString(3, attributes.get("user_email").getValues().get(0));
			psinsert.setDate(4, new Date( new DateTime().getMillis()));
			psinsert.setInt(5, 0);
			psinsert.setString(6, attributes.get("display_name").getValues().get(0));
			psinsert.executeUpdate();
			
			ResultSet rs = psinsert.getGeneratedKeys();
			rs.next();
			int id = rs.getInt(1);
			
			HashSet<String> proced = new HashSet<String>();
			
			PreparedStatement meta = con.prepareStatement("INSERT INTO wp_usermeta (user_id,meta_key,meta_value) VALUES (?,?,?)");
			meta.setInt(1, id);
			meta.setString(2, "first_name");
			meta.setString(3, attributes.get("first_name").getValues().get(0));
			meta.executeUpdate();
			proced.add("first_name");
			
			meta.setInt(1, id);
			meta.setString(2, "last_name");
			meta.setString(3, attributes.get("last_name").getValues().get(0));
			meta.executeUpdate();
			proced.add("last_name");
			
			meta.setInt(1, id);
			meta.setString(2, "nickname");
			meta.setString(3, attributes.get("display_name").getValues().get(0));
			meta.executeUpdate();
			proced.add("nickname");
			
			meta.setInt(1, id);
			meta.setString(2, "description");
			meta.setString(3, "");
			meta.executeUpdate();
			proced.add("description");
			
			meta.setInt(1, id);
			meta.setString(2, "rich_editing");
			meta.setString(3, "true");
			meta.executeUpdate();
			proced.add("rich_editing");
			
			meta.setInt(1, id);
			meta.setString(2, "comment_shortcuts");
			meta.setString(3, "false");
			meta.executeUpdate();
			proced.add("comment_shortcuts");
			
			meta.setInt(1, id);
			meta.setString(2, "admin_color");
			meta.setString(3, "fresh");
			meta.executeUpdate();
			proced.add("admin_color");
			
			meta.setInt(1, id);
			meta.setString(2, "use_ssl");
			meta.setString(3, "1");
			meta.executeUpdate();
			proced.add("use_ssl");
			
			
			meta.setInt(1, id);
			meta.setString(2, "show_admin_bar_front");
			meta.setString(3, "true");
			meta.executeUpdate();
			proced.add("show_admin_bar_front");
			
			meta.setInt(1, id);
			meta.setString(2, "show_admin_bar_admin");
			meta.setString(3, "false");
			meta.executeUpdate();
			proced.add("show_admin_bar_admin");
			
			
			meta.setInt(1, id);
			meta.setString(2, "aim");
			meta.setString(3, "");
			meta.executeUpdate();
			proced.add("aim");
			
			meta.setInt(1, id);
			meta.setString(2, "yim");
			meta.setString(3, "");
			meta.executeUpdate();
			proced.add("yim");
			
			meta.setInt(1, id);
			meta.setString(2, "jabber");
			meta.setString(3, "");
			meta.executeUpdate();
			proced.add("jabber");
			
			meta.setInt(1, id);
			meta.setString(2, "wp_user_level");
			meta.setString(3, "0");
			meta.executeUpdate();
			proced.add("wp_user_level");
			
			
			meta.setInt(1, id);
			meta.setString(2, "_bbp_last_posted");
			meta.setString(3, "");
			meta.executeUpdate();
			proced.add("_bb_last_posted");
			
			for (String key : attributes.keySet()) {
				if (! this.wp_usersFields.contains(key) && ! proced.contains(key)) {
					Attribute attr = attributes.get(key);
					for (String val : attr.getValues()) {
						meta.setInt(1, id);
						meta.setString(2, key);
						meta.setString(3, val);
						meta.executeUpdate();
					}
					proced.add(key);
					
				}
			}
			
			return id;
			
		} catch (SQLException e) {
			throw new ProvisioningException("Could not create user",e);
		}
	}

	private ArrayList<String> parseGroups(String group) {
		ArrayList<String> groupNames = new ArrayList<String>();
		
		int start = group.indexOf('"');
		while (start > 0) {
			int end = group.indexOf('"',start + 1);
			String groupName = group.substring(start + 1,end);
			groupNames.add(groupName);
			start = group.indexOf('"',end + 1);
		}
		
		return groupNames;
		
		
	}
	
	private String serializeGroups(ArrayList<String> groups) {
		StringBuffer ser = new StringBuffer();
		ser.append("a:").append(groups.size()).append(":{");
		for (String group : groups) {
			ser.append("s:").append(group.length()).append(":\"").append(group).append("\";b:1;");
		}
		ser.append("}");
		return ser.toString();
		
	}
	
	@Override
	public void addGroup(Connection con, int id, String name)
			throws ProvisioningException {
		try {
			
			boolean isAdd = false;
			
			PreparedStatement ps = con.prepareStatement("SELECT meta_value FROM wp_usermeta WHERE user_id=? AND meta_key=?");
			ps.setInt(1, id);
			ps.setString(2, "wp_capabilities");
			
			String groups = "";
			ArrayList<String> oldGroups = new ArrayList<String>();
			
			ResultSet rs = ps.executeQuery();
			isAdd = ! rs.next();
			if (! isAdd) {
				groups = rs.getString("meta_value");
				oldGroups = this.parseGroups(groups);
			}
			
			ps.close();
			
			
			
			oldGroups.add(name);
			String serialized = this.serializeGroups(oldGroups);
			
			if (isAdd) {
				ps = con.prepareStatement("INSERT INTO wp_usermeta (user_id,meta_key,meta_value) VALUES (?,?,?)");				
				ps.setInt(1, id);
				ps.setString(2, "wp_capabilities");
				ps.setString(3, serialized);
				ps.executeUpdate();
				ps.close();
			} else {
				ps = con.prepareStatement("UPDATE wp_usermeta SET meta_value=? where user_id=? AND meta_key=?");
				ps.setString(1, serialized);
				ps.setInt(2, id);
				ps.setString(3, "wp_capabilities");
				ps.executeUpdate();
				ps.close();
			}
				
				
			
			
			
		} catch (SQLException e) {
			throw new ProvisioningException("Could not delete group",e);
		}

	}

	@Override
	public void deleteGroup(Connection con, int id, String name)
			throws ProvisioningException {
		try {
			PreparedStatement ps = con.prepareStatement("SELECT meta_value FROM wp_usermeta WHERE user_id=? AND meta_key=?");
			ps.setInt(1, id);
			ps.setString(2, "wp_capabilities");
			
			ArrayList<String> oldGroups = new ArrayList<String>();
			
			ResultSet rs = ps.executeQuery();
			if (rs.next()) {
				String groups = rs.getString("meta_value");
				oldGroups = this.parseGroups(groups);
			}
			
			ps.close();
			
			
			
			if (oldGroups.remove(name)) {
				String serialized = this.serializeGroups(oldGroups);
				ps = con.prepareStatement("UPDATE wp_usermeta SET meta_value=? where user_id=? AND meta_key=?");
				ps.setString(1, serialized);
				ps.setInt(2, id);
				ps.setString(3, "wp_capabilities");
				ps.executeUpdate();
				ps.close();
			}
			
			
		} catch (SQLException e) {
			throw new ProvisioningException("Could not delete group",e);
		}

	}

	@Override
	public void deleteUser(Connection con, int id) throws ProvisioningException {
		try {
			PreparedStatement ps = con.prepareStatement("DELETE FROM wp_users WHERE ID=?");
			ps.setInt(1, id);
			ps.executeUpdate();
			
			ps = con.prepareStatement("DELETE FROM wp_usermeta WHERE user_id=?");
			ps.setInt(1, id);
			ps.executeUpdate();
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
			if (this.wp_usersFields.contains(attributeName) ) {
				StringBuffer b = new StringBuffer();
				b.append("UPDATE wp_users SET ").append(attributeName).append("=? WHERE id=?");
				PreparedStatement ps = con.prepareStatement(b.toString());
				
				ps.setString(1, newValue);
				ps.setInt(2, id);
				ps.executeUpdate();
			} else {
				PreparedStatement ps = con.prepareStatement("UPDATE wp_usermeta SET meta_value=? WHERE user_id=? AND meta_key=?");
				
				ps.setString(1, newValue);
				ps.setInt(2, id);
				ps.setString(3, attributeName);
				ps.executeUpdate();
			}
		} catch (SQLException e) {
			throw new ProvisioningException("Could not update attribute",e);
		}

	}

	@Override
	public void clearField(Connection con, int id,
			Map<String, Object> request, String attributeName,
			String oldValue) throws ProvisioningException {
		try {
			if (this.wp_usersFields.contains(attributeName) ) {
				StringBuffer b = new StringBuffer();
				b.append("UPDATE wp_users SET ").append(attributeName).append("=? WHERE id=?");
				PreparedStatement ps = con.prepareStatement(b.toString());
				
				ps.setString(1, "");
				ps.setInt(2, id);
				ps.executeUpdate();
			} else {
				PreparedStatement ps = con.prepareStatement("UPDATE wp_usermeta SET meta_value=? WHERE user_id=? AND meta_key=?");
				
				ps.setString(1, "");
				ps.setInt(2, id);
				ps.setString(3, attributeName);
				ps.executeUpdate();
			}
		} catch (SQLException e) {
			throw new ProvisioningException("Could not update attribute",e);
		}

	}

	@Override
	public void completeUpdate(Connection con, int id,
			Map<String, Object> request) throws ProvisioningException {
		

	}

	@Override
	public boolean listCustomGroups() {
		return true;
	}

	@Override
	public List<String> findGroups(Connection con, int id,
			Map<String, Object> request) throws ProvisioningException {
		try {
			ArrayList<String> groups = new ArrayList<String>();
			PreparedStatement ps = con.prepareStatement("SELECT meta_value FROM wp_usermeta WHERE user_id=? AND meta_key=?");
			ps.setInt(1, id);
			ps.setString(2, "wp_capabilities");
			
			ResultSet rs = ps.executeQuery();
			if (rs.next()) {
				String groupString = rs.getString("meta_value");
				groups = this.parseGroups(groupString);
			}
			
			ps.close();
			
			
			return groups;
		} catch (SQLException e) {
			throw new ProvisioningException("Could not update attribute",e);
		}
	}

}

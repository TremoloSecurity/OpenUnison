package com.tremolosecurity.unison.openshiftv3.model.groups;

import java.util.HashSet;

import com.tremolosecurity.unison.openshiftv3.model.Response;

public class Group extends Response {
	java.util.Set<String> users;
	
	public Group() {
		super();
		this.users = new HashSet<String>();
	}

	public java.util.Set<String> getUsers() {
		return users;
	}

	public void setUsers(java.util.Set<String> users) {
		this.users = users;
	}
	
	 
}

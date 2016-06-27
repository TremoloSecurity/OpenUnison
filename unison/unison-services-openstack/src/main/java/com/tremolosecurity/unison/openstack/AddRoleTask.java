package com.tremolosecurity.unison.openstack;

import java.util.HashSet;
import java.util.Map;

import com.google.gson.Gson;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.openstack.model.Role;

public class AddRoleTask implements CustomTask {

	String name;
	String scope;
	String project;
	String domain;
	
	boolean remove;
	private transient WorkflowTask task;
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		if (params.get("name") != null) {
			name = params.get("name").getValues().get(0);
		}
		
		if (params.get("scope") != null) {
			scope = params.get("scope").getValues().get(0);
		}
		
		if (params.get("domain") != null) {
			domain = params.get("domain").getValues().get(0);
		}
		
		if (params.get("project") != null) {
			project = params.get("project").getValues().get(0);
		}
		
		if (params.get("remove") != null) {
			remove = params.get("remove").getValues().get(0).equalsIgnoreCase("true");
		} else {
			remove = false;
		}
		
		this.task = task;

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		Role r = new Role();
		if (name != null) {
			r.setName(task.renderTemplate(name, request));
		} else {
			r.setName((String)request.get("role_name")); 
		}
		
		if (scope != null) {
			r.setScope(task.renderTemplate(scope, request));
		} else {
			r.setScope("project");
		}
		
		if (domain != null) {
			r.setDomain(task.renderTemplate(domain, request));
		} else {
			if (r.getScope().equalsIgnoreCase("project")) {
				r.setDomain((String) request.get("project_domain_name"));
			} else {
				r.setDomain((String) request.get("domain_name"));
			}
		}
		
		if (project != null) {
			r.setProject(task.renderTemplate(project, request));
		} else {
			r.setProject((String) request.get("project_name"));
		}
		
		Attribute attr = user.getAttribs().get("roles");
		if (attr == null) {
			attr = new Attribute("roles");
			user.getAttribs().put("roles", attr);
		} 
		Gson gson = new Gson();
		HashSet<Role> roles = new HashSet<Role>();
		for (String roleJSON : attr.getValues()) {
			roles.add(gson.fromJson(roleJSON,Role.class));
		}
		
		attr.getValues().clear();
		if (remove) {
			roles.remove(r);
		} else {
			roles.add(r);
		}
		
		for (Role rx : roles) {
			attr.getValues().add(gson.toJson(rx));
		}
		
		return true;
	}

}

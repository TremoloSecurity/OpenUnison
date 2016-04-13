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
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import org.hibernate.Query;
import org.hibernate.Session;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.core.providers.BasicDB;
import com.tremolosecurity.provisioning.objects.UserAttributes;
import com.tremolosecurity.provisioning.objects.Users;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

public class LoadAuditDBAttributes implements CustomTask {

	HashSet<String> attrs;
	String nameAttr;
	transient ConfigManager cfg;

	transient WorkflowTask task;

	String SQL;

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.attrs = new HashSet<String>();
		Attribute cfgAttrs = params.get("name");

		for (String name : cfgAttrs.getValues()) {
			attrs.add(name);
		}

		this.nameAttr = params.get("nameAttr").getValues().get(0);

		this.cfg = task.getConfigManager();

		this.task = task;

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.cfg = task.getConfigManager();
		this.task = task;

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {

		Session session = null;

		try {
			session = this.cfg.getProvisioningEngine().getHibernateSessionFactory().openSession();

			Query query = session.createQuery("FROM Users WHERE userKey = :user_key");
			query.setParameter("user_key", user.getAttribs().get(this.nameAttr).getValues().get(0));
			List<com.tremolosecurity.provisioning.objects.Users> users = query.list();

			Users userObj = users.get(0);

			for (UserAttributes attr : userObj.getUserAttributeses()) {
				if (this.attrs.contains(attr.getName())) {
					user.getAttribs().put(attr.getName(), new Attribute(attr.getName(), attr.getValue()));
				}
			}

		} catch (Exception e) {
			throw new ProvisioningException("Could not load attributes", e);
		} finally {
			if (session != null) {

				session.close();

			}
		}

		return true;

	}

}

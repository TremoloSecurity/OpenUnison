/*******************************************************************************
 * Copyright 2023 Tremolo Security, Inc.
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

package com.tremolosecurity.az;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningTarget;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.az.AzException;
import com.tremolosecurity.proxy.az.CustomAuthorization;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

public class RBACBindingAuthorization implements CustomAuthorization {
	
	static Logger logger = Logger.getLogger(RBACBindingAuthorization.class);
	
	Workflow wf;

	@Override
	public void init(Map<String, Attribute> config) throws AzException {
		// TODO Auto-generated method stub

	}

	@Override
	public void loadConfigManager(ConfigManager cfg) throws AzException {
		// TODO Auto-generated method stub

	}

	@Override
	public void setWorkflow(Workflow wf) throws AzException {
		this.wf = wf;

	}

	
	
	@Override
	public boolean isAuthorized(AuthInfo subject, String... params) throws AzException {
		String ltarget = params[0];
		String lscope = params[1];
		String lbinding = params[2];
		String attr = params[3];
		String lbase = params[4];
		String lnamespace = null;
		if (params.length == 6) {
			lnamespace = params[5];
		}
		
		
		String target = wf == null ? ltarget : wf.getTasks().get(0).renderTemplate(ltarget, wf.getRequest());
		String scope = wf == null ? lscope : wf.getTasks().get(0).renderTemplate(lscope, wf.getRequest());
		String binding = wf == null ? lbinding : wf.getTasks().get(0).renderTemplate(lbinding, wf.getRequest());
		String base = wf == null ? lbase : wf.getTasks().get(0).renderTemplate(lbase, wf.getRequest());
		String namespace = null;
		if (lnamespace != null) {
			namespace = wf == null ? lnamespace : wf.getTasks().get(0).renderTemplate(lnamespace, wf.getRequest());
		}
		
		
		try {
			Set<String> rbacUsers = this.retrieveUsersFromBinding(target, scope, namespace,binding);
			
			Attribute attribute = subject.getAttribs().get(attr);
			if (attribute == null) {
				logger.warn(String.format("No mail attribute for %s",subject.getUserDN()));
				return false;
			}
			
			return rbacUsers.contains(attribute.getValues().get(0));
			
			
		} catch (Exception e) {
			throw new AzException("Could not check bindings",e);
		}		
	}

	
	Set<String> retrieveUsersFromBinding(String target,String scope, String namespace, String rolebinding) throws Exception {
		if (logger.isDebugEnabled()) logger.debug("retrieve from rbac " + target + " / " + namespace + " / " + rolebinding);
		Set<String> listOfUsers = new HashSet<String>();
		
		ProvisioningTarget t = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(target);
		if (t == null) {
			throw new ProvisioningException("Target " + target + " not found");
		}
		
		OpenShiftTarget k8s = (OpenShiftTarget) t.getProvider();
		
		HttpCon con = null;
		try {
			con = k8s.createClient();
			String json = null;
			
			if (namespace != null) {
				if (namespace.equals("*")) {
					json = k8s.callWS(k8s.getAuthToken(), con, "/apis/rbac.authorization.k8s.io/v1/rolebindings");
				} else {
					json = k8s.callWS(k8s.getAuthToken(), con, String.format("/apis/rbac.authorization.k8s.io/v1/namespaces/%s/rolebindings",namespace));
				}
				
			} else {
				json = k8s.callWS(k8s.getAuthToken(), con, String.format("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",namespace));
			}
			
			
			
			
			if (logger.isDebugEnabled()) logger.debug("Found JSON : " + json);
			
			JSONObject resp = (JSONObject) new JSONParser().parse(json);
			JSONArray items = (JSONArray) resp.get("items");
			
			for (Object o : items) {
				JSONObject binding = (JSONObject) o;
				
				JSONObject roleRef = (JSONObject) binding.get("roleRef");
				
				String kind = (String) roleRef.get("kind");
				String name = (String) roleRef.get("name");
				
				if (kind.equals(scope) && name.equals(rolebinding)) {
					JSONArray subjects = (JSONArray) binding.get("subjects");
					if (subjects != null) {
						for (Object oo : subjects) {
							JSONObject subject = (JSONObject) oo;
							if (logger.isDebugEnabled()) logger.debug("subject: "  + subject) ;
							if (subject.get("kind").equals("User")) {
								listOfUsers.add((String) subject.get("name"));
							}
						}
					}
				}
				
				
				
			}
			
			
			
			
			
		} finally {
			if (con != null) {
				con.getHttp().close();
				
				con.getBcm().close();
			}
			
			
		}
		
		if (logger.isDebugEnabled()) logger.debug("List of users: " + listOfUsers);
		
		return listOfUsers;
	}
	
	@Override
	public List<String> listPossibleApprovers(String... params) throws AzException {
		if (logger.isDebugEnabled()) logger.debug("in list approvers");
		String ltarget = params[0];
		String lscope = params[1];
		String lbinding = params[2];
		String attr = params[3];
		String lbase = params[4];
		String lnamespace = null;
		if (params.length == 6) {
			lnamespace = params[5];
		}
		
		
		String target = wf == null ? ltarget : wf.getTasks().get(0).renderTemplate(ltarget, wf.getRequest());
		String scope = wf == null ? lscope : wf.getTasks().get(0).renderTemplate(lscope, wf.getRequest());
		String binding = wf == null ? lbinding : wf.getTasks().get(0).renderTemplate(lbinding, wf.getRequest());
		String base = wf == null ? lbase : wf.getTasks().get(0).renderTemplate(lbase, wf.getRequest());
		String namespace = null;
		if (lnamespace != null) {
			namespace = wf == null ? lnamespace : wf.getTasks().get(0).renderTemplate(lnamespace, wf.getRequest());
		}
		
		try {
			Set<String> rbacUsers = this.retrieveUsersFromBinding(target, scope, namespace,binding);
			List<String> users = new ArrayList<String>();
			
			for (String userid : rbacUsers) {
				if (logger.isDebugEnabled()) logger.debug("searching for user:" + userid);
				LDAPSearchResults ldapRes = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(base, 2, equal(attr,userid).toString(), new ArrayList<String>());
				if (ldapRes.hasMore()) {
					if (logger.isDebugEnabled()) logger.debug("user found");
					LDAPEntry entry = ldapRes.next();
					users.add(entry.getDN());
				}
			}
			
			if (logger.isDebugEnabled()) logger.debug("found user: " + users);
			
			return users;
			
		} catch (Exception e) {
			throw new AzException("Could not check bindings",e);
		}
		
		
	}

	@Override
	public Workflow getWorkflow() {
		return this.wf;
	}

}

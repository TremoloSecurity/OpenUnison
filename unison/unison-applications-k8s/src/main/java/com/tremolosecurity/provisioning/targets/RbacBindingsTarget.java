/*******************************************************************************
 * Copyright 2023 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/

package com.tremolosecurity.provisioning.targets;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.json.simple.JSONObject;
import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.parser.JSONParser;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.k8s.model.Binding;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningTarget;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class RbacBindingsTarget implements UserStoreProvider {
	public static final String USER_BINDINGS = "tremolo.io/k8s-rbac/user-bindings";

	public static final String RBAC_TARGETS_BY_LABEL = "tremolo.io/k8s-rbac/targets-by-label";

	static Logger logger = Logger.getLogger(RbacBindingsTarget.class);

	String targetName;

	@Override
	public void createUser(User user, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {

		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}

		Workflow workflow = (Workflow) request.get("WORKFLOW");

		ProvisioningTarget target = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine()
				.getTarget(this.targetName);
		if (target == null) {
			throw new ProvisioningException("Could not find target " + this.targetName);
		}
		OpenShiftTarget k8s = (OpenShiftTarget) target.getProvider();

		// load all cluster roles
		HttpCon con = null;
		JSONParser parser = new JSONParser();
		try {
			con = k8s.createClient();

			for (String group : user.getGroups()) {
				if (group.startsWith("crb:")) {
					String crb = group.substring(group.indexOf(':') + 1);
					String uri = String.format("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/%s", crb);
					String resp = k8s.callWS(k8s.getAuthToken(), con, uri);
					JSONObject root = (JSONObject) parser.parse(resp);
					String kind = (String) root.get("kind");
					if (kind == null || !kind.equalsIgnoreCase("ClusterRoleBinding")) {
						logger.warn(String.format("Group %s for user %s does not exist, skipping", group,
								user.getUserID()));
					} else {
						JSONArray subjects = (JSONArray) root.get("subjects");
						boolean found = false;
						boolean hasUsers = true;
						if (subjects != null) {
							for (Object oo : subjects) {
								JSONObject subject = (JSONObject) oo;
								kind = (String) subject.get("kind");
								if (kind.equalsIgnoreCase("User")) {
									String userName = (String) subject.get("name");
									if (userName != null && userName.equals(user.getUserID())) {
										found = true;
										break;
									}
								}
							}
						} else {
							hasUsers = false;
						}

						if (!found) {
							if (hasUsers) {

								String patch = String.format("[\n" + "                        {\n"
										+ "                          \"op\":\"add\",\n"
										+ "                          \"path\":\"/subjects/-\",\n"
										+ "                          \"value\": {\"kind\":\"User\",\"name\":\"%s\"}\n"
										+ "                        }\n" + "                      ]", user.getUserID());
								k8s.callWSPatchJson(k8s.getAuthToken(), con, uri, patch, "application/json-patch+json");
							} else {
								String patch = String.format("{\"subjects\":[{\"kind\":\"User\",\"name\":\"%s\"}]}",
										user.getUserID());
								k8s.callWSPatchJson(k8s.getAuthToken(), con, uri, patch,
										"application/strategic-merge-patch+json");
							}

							GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(
									targetName, false, ActionType.Add, approvalID, workflow, "clusterrolebinding", crb);
						}
					}
				} else if (group.startsWith("rb:")) {

					int firstColon = group.indexOf(':');
					int secondColon = group.indexOf(':', firstColon + 1);

					String namespace = group.substring(firstColon + 1, secondColon);
					String rb = group.substring(secondColon + 1);
					String uri = String.format("/apis/rbac.authorization.k8s.io/v1/namespaces/%s/rolebindings/%s",
							namespace, rb);
					String resp = k8s.callWS(k8s.getAuthToken(), con, uri);
					JSONObject root = (JSONObject) parser.parse(resp);
					String kind = (String) root.get("kind");
					if (kind == null || !kind.equalsIgnoreCase("RoleBinding")) {
						logger.warn(String.format("Group %s for user %s does not exist, skipping", group,
								user.getUserID()));
					} else {
						JSONArray subjects = (JSONArray) root.get("subjects");
						boolean found = false;
						boolean hasUsers = true;
						if (subjects != null) {
							for (Object oo : subjects) {
								JSONObject subject = (JSONObject) oo;
								kind = (String) subject.get("kind");
								if (kind.equalsIgnoreCase("User")) {
									String userName = (String) subject.get("name");
									if (userName != null && userName.equals(user.getUserID())) {
										found = true;
										break;
									}
								}
							}
						} else {
							hasUsers = false;
						}

						if (!found) {
							logger.info("has subjects: " + hasUsers);
							if (hasUsers) {
								String patch = String.format("[\n" + "                        {\n"
										+ "                          \"op\":\"add\",\n"
										+ "                          \"path\":\"/subjects/-\",\n"
										+ "                          \"value\": {\"kind\":\"User\",\"name\":\"%s\"}\n"
										+ "                        }\n" + "                      ]", user.getUserID());
								k8s.callWSPatchJson(k8s.getAuthToken(), con, uri, patch, "application/json-patch+json");
							} else {
								String patch = String.format("{\"subjects\":[{\"kind\":\"User\",\"name\":\"%s\"}]}",
										user.getUserID());

								k8s.callWSPatchJson(k8s.getAuthToken(), con, uri, patch,
										"application/strategic-merge-patch+json");
							}

							GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(
									targetName, false, ActionType.Add, approvalID, workflow, "rolebinding",
									String.format("%s:%s", namespace, rb));
						}
					}

				} else {
					logger.warn(String.format("Group %s for user %s is not an RBAC binding, skipping", group,
							user.getUserID()));
				}
			}

		} catch (Exception e) {
			throw new ProvisioningException("Could not load bindings for " + user.getUserID(), e);
		} finally {
			if (con != null) {
				try {
					con.getHttp().close();
				} catch (IOException e) {

				}

				con.getBcm().close();
			}
		}
	}

	@Override
	public void setUserPassword(User user, Map<String, Object> request) throws ProvisioningException {
		// TODO Auto-generated method stub

	}

	@Override
	public void syncUser(User user, boolean addOnly, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		// first run create
		this.createUser(user, attributes, request);

		if (!addOnly) {
			HashSet<String> groupsToKeep = new HashSet<String>();
			groupsToKeep.addAll(user.getGroups());
			deleteBindings(user, request, groupsToKeep);
		}

	}

	@Override
	public void deleteUser(User user, Map<String, Object> request) throws ProvisioningException {

		deleteBindings(user, request, new HashSet<String>());

	}

	private void deleteBindings(User user, Map<String, Object> request, HashSet<String> groupsToKeep)
			throws ProvisioningException {
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}

		Workflow workflow = (Workflow) request.get("WORKFLOW");

		ProvisioningTarget target = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine()
				.getTarget(this.targetName);
		if (target == null) {
			throw new ProvisioningException("Could not find target " + this.targetName);
		}
		OpenShiftTarget k8s = (OpenShiftTarget) target.getProvider();

		// load all cluster roles
		HttpCon con = null;
		JSONParser parser = new JSONParser();
		try {
			con = k8s.createClient();
			String resp = k8s.callWS(k8s.getAuthToken(), con, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings");
			JSONObject root = (JSONObject) parser.parse(resp);
			JSONArray items = (JSONArray) root.get("items");
			if (items == null) {
				throw new ProvisioningException("Response not list " + resp);
			}

			for (Object o : items) {
				JSONObject binding = (JSONObject) o;
				JSONObject metadata = (JSONObject) binding.get("metadata");
				String name = (String) metadata.get("name");
				String groupname = String.format("crb:%s", name);
				if (!groupsToKeep.contains(groupname)) {
					JSONArray subjects = (JSONArray) binding.get("subjects");
					if (subjects != null) {
						JSONArray newSubjects = new JSONArray();

						for (Object oo : subjects) {
							JSONObject subject = (JSONObject) oo;
							String kind = (String) subject.get("kind");
							if (kind.equalsIgnoreCase("User")) {
								String userName = (String) subject.get("name");
								if (userName == null || !userName.equals(user.getUserID())) {
									newSubjects.add(subject);
								}
							} else {
								newSubjects.add(subject);
							}
						}

						if (newSubjects.size() < subjects.size()) {
							JSONObject newRoot = new JSONObject();
							newRoot.put("subjects", newSubjects);
							String patch = newRoot.toJSONString();
							String patchUri = String.format(
									"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/%s?fieldManager=kubectl-edit&fieldValidation=Strict",
									name);
							k8s.callWSPatchJson(k8s.getAuthToken(), con, patchUri, patch);
							GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(
									targetName, false, ActionType.Delete, approvalID, workflow, "clusterrolebinding",
									name);
						}
					}
				}
			}

			// rolebindings
			resp = k8s.callWS(k8s.getAuthToken(), con, "/apis/rbac.authorization.k8s.io/v1/rolebindings");
			root = (JSONObject) parser.parse(resp);
			items = (JSONArray) root.get("items");
			if (items == null) {
				throw new ProvisioningException("Response not list " + resp);
			}

			for (Object o : items) {
				JSONObject binding = (JSONObject) o;
				JSONObject metadata = (JSONObject) binding.get("metadata");
				String name = (String) metadata.get("name");
				String namespace = (String) metadata.get("namespace");
				String groupname = String.format("rb:%s:%s", namespace, name);

				if (!groupsToKeep.contains(groupname)) {
					JSONArray subjects = (JSONArray) binding.get("subjects");
					if (subjects != null) {
						JSONArray newSubjects = new JSONArray();

						for (Object oo : subjects) {
							JSONObject subject = (JSONObject) oo;
							String kind = (String) subject.get("kind");
							if (kind.equalsIgnoreCase("User")) {
								String userName = (String) subject.get("name");
								if (userName == null || !userName.equals(user.getUserID())) {
									newSubjects.add(subject);
								}
							} else {
								newSubjects.add(subject);
							}
						}

						if (newSubjects.size() < subjects.size()) {
							JSONObject newRoot = new JSONObject();
							newRoot.put("subjects", newSubjects);
							String patch = newRoot.toJSONString();
							String patchUri = String.format(
									"/apis/rbac.authorization.k8s.io/v1/namespaces/%s/rolebindings/%s?fieldManager=kubectl-edit&fieldValidation=Strict",
									namespace, name);
							k8s.callWSPatchJson(k8s.getAuthToken(), con, patchUri, patch);
							GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(
									targetName, false, ActionType.Delete, approvalID, workflow, "rolebinding",
									String.format("%s:%s", namespace, name));
						}
					}
				}
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not load bindings for " + user.getUserID(), e);
		} finally {
			if (con != null) {
				try {
					con.getHttp().close();
				} catch (IOException e) {

				}

				con.getBcm().close();
			}
		}
	}

	Binding createBindingObj(JSONObject roleRef, String namespace, String bindingName) {
		boolean namespaced = roleRef.get("kind").equals("Role");
		String name = (String) roleRef.get("name");
		return new Binding(name, namespaced, namespaced ? namespace : null, this.targetName, bindingName);
	}

	@Override
	public User findUser(String userID, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		User user = new User(userID);
		Map<String, Binding> bindings = new HashMap<String, Binding>();

		ProvisioningTarget target = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine()
				.getTarget(this.targetName);
		if (target == null) {
			throw new ProvisioningException("Could not find target " + this.targetName);
		}
		OpenShiftTarget k8s = (OpenShiftTarget) target.getProvider();

		// load all cluster roles
		HttpCon con = null;
		JSONParser parser = new JSONParser();
		try {
			con = k8s.createClient();
			String resp = k8s.callWS(k8s.getAuthToken(), con, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings");
			JSONObject root = (JSONObject) parser.parse(resp);
			JSONArray items = (JSONArray) root.get("items");
			if (items == null) {
				throw new ProvisioningException("Response not list " + resp);
			}

			for (Object o : items) {
				JSONObject binding = (JSONObject) o;
				JSONObject metadata = (JSONObject) binding.get("metadata");
				String name = (String) metadata.get("name");
				JSONArray subjects = (JSONArray) binding.get("subjects");
				if (subjects != null) {
					for (Object oo : subjects) {
						JSONObject subject = (JSONObject) oo;
						String kind = (String) subject.get("kind");
						if (kind.equalsIgnoreCase("User")) {
							String userName = (String) subject.get("name");
							if (userName != null && userName.equals(user.getUserID())) {
								String groupName = new StringBuilder().append("crb:").append(name).toString();
								user.getGroups().add(groupName);
								JSONObject roleRef = (JSONObject) binding.get("roleRef");

								bindings.put(groupName, this.createBindingObj(roleRef, null, name));

							}
						}
					}
				}
			}

			// rolebindings
			resp = k8s.callWS(k8s.getAuthToken(), con, "/apis/rbac.authorization.k8s.io/v1/rolebindings");
			root = (JSONObject) parser.parse(resp);
			items = (JSONArray) root.get("items");
			if (items == null) {
				throw new ProvisioningException("Response not list " + resp);
			}

			for (Object o : items) {
				JSONObject binding = (JSONObject) o;
				JSONObject metadata = (JSONObject) binding.get("metadata");
				String name = (String) metadata.get("name");
				String namespace = (String) metadata.get("namespace");
				JSONArray subjects = (JSONArray) binding.get("subjects");
				if (subjects != null) {
					for (Object oo : subjects) {
						JSONObject subject = (JSONObject) oo;
						String kind = (String) subject.get("kind");
						if (kind.equalsIgnoreCase("User")) {
							String userName = (String) subject.get("name");
							if (userName != null && userName.equals(user.getUserID())) {
								String groupName = new StringBuilder().append("rb:").append(namespace).append(':')
										.append(name).toString();
								JSONObject roleRef = (JSONObject) binding.get("roleRef");

								bindings.put(groupName, this.createBindingObj(roleRef, namespace, name));
								user.getGroups().add(groupName);
							}
						}
					}
				}
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not load bindings for " + user.getUserID(), e);
		} finally {
			if (con != null) {
				try {
					con.getHttp().close();
				} catch (IOException e) {

				}

				con.getBcm().close();
			}
		}

		request.put(USER_BINDINGS, bindings);

		return user;
	}

	@Override
	public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr, String name) throws ProvisioningException {
		Attribute targetName = cfg.get("target");
		if (targetName == null) {
			throw new ProvisioningException("target is required");
		}

		this.targetName = targetName.getValues().get(0);

	}

	@Override
	public void shutdown() throws ProvisioningException {
		// TODO Auto-generated method stub

	}

	public static String findTargetNameByLabel(String label, String sourceTarget, String sourceNamespace,
			String labelAnnotation) throws Exception {
		HashMap<String, String> labels = (HashMap<String, String>) GlobalEntries.getGlobalEntries()
				.get(RBAC_TARGETS_BY_LABEL);
		if (labels == null) {
			labels = new HashMap<String, String>();
			GlobalEntries.getGlobalEntries().set(RBAC_TARGETS_BY_LABEL, labels);
		}

		String targetName = labels.get(labels);
		if (targetName == null) {
			synchronized (labels) {
				ProvisioningTarget t = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine()
						.getTarget(sourceTarget);
				if (t == null) {
					logger.warn(String.format("Can not load target %s", sourceTarget));
					return null;
				}

				OpenShiftTarget k8s = (OpenShiftTarget) t.getProvider();

				String uri = String.format("/apis/openunison.tremolo.io/v1/namespaces/%s/targets", sourceNamespace);

				logger.info("Searching uri " + uri);
				HttpCon con = null;
				con = k8s.createClient();

				try {
					JSONObject targets = (JSONObject) new JSONParser().parse(k8s.callWS(k8s.getAuthToken(), con, uri));

					JSONArray items = (JSONArray) targets.get("items");
					if (items == null) {
						logger.warn(String.format("Not able to load %s, %s", uri, targets.toString()));
						return null;
					}

					for (Object o : items) {
						logger.info("Target: " + o.toString());
						JSONObject target = (JSONObject) o;
						JSONObject metadata = (JSONObject) target.get("metadata");
						JSONObject spec = (JSONObject) target.get("spec");

						String className = (String) spec.get("className");
						if (className.equals("com.tremolosecurity.provisioning.targets.RbacBindingsTarget")) {
							logger.info("found rbac target");
							String labelFromObj = (String) metadata.get("name");
							JSONObject annotations = (JSONObject) metadata.get("annotations");
							if (annotations != null) {
								logger.info("found annotations");
								String localLabel = (String) annotations.get(labelAnnotation);
								if (localLabel != null && localLabel.equals(label)) {
									String name = (String) metadata.get("name");
									labels.put(label, name);
									return name;
								}

							}

							
						}
					}
					
					return null;

				} finally {
					if (con != null) {
						con.getHttp().close();
						con.getBcm().close();
					}
				}
			}
		} else {
			return targetName;
		}
	}

	public String getTargetName() {
		return targetName;
	}

}

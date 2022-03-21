package com.tremolosecurity.proxy.az;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningTarget;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class UserHasSessionAz implements CustomAuthorization {

	static Logger logger = Logger.getLogger(UserHasSessionAz.class);
	
	String targetName;
	String namespace;
	
	
	@Override
	public void init(Map<String, Attribute> config) throws AzException {
		this.targetName = config.get("target").getValues().get(0);
		this.namespace = config.get("namespace").getValues().get(0);

	}

	@Override
	public void loadConfigManager(ConfigManager cfg) throws AzException {
		

	}

	@Override
	public void setWorkflow(Workflow wf) throws AzException {
		// this approval rule wouldn't be used for workflows

	}

	@Override
	public boolean isAuthorized(AuthInfo subject, String... params) throws AzException {
		String subjectDNSum = DigestUtils.sha1Hex(subject.getUserDN());
		
		String uri = new StringBuilder("/apis/openunison.tremolo.io/v1/namespaces/").append(this.namespace).append("/oidc-sessions?labelSelector=tremolo.io%2Fuser-dn%3D").append(subjectDNSum).toString();
		if (logger.isDebugEnabled()) {
			logger.debug("Looking for '" + uri + "'");
		}
		HttpCon client = null;
		
		try {
			ProvisioningTarget k8sTarget = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.targetName);
			if (k8sTarget == null) {
				throw new AzException("Could not find target '" + this.targetName + "'");
			}
			
			OpenShiftTarget k8s = (OpenShiftTarget) k8sTarget.getProvider();
		
		
		
		
			client = k8s.createClient();
			String token = k8s.getAuthToken();
			String jsonResponse = k8s.callWS(token, client, uri);
			
			JSONObject root = (JSONObject) new JSONParser().parse(jsonResponse);
			JSONArray items = (JSONArray) root.get("items");
			if (items == null) {
				throw new AzException("Unexpected result : '" + jsonResponse + "'");
			}
			
			return items.size() > 0;
		} catch (Exception e) {
			throw new AzException("Could not check if " + subject.getUserDN() + " has any sessions",e);
		} finally {
			if (client != null) {
				try {
					client.getHttp().close();
				} catch (IOException e) {
					
				}
				client.getBcm().close();
			}
		}
		
		
		
		
		
	}

	@Override
	public List<String> listPossibleApprovers(String... params) throws AzException {
		// this approval rule wouldn't be used for workflows
		return new ArrayList<String>();
	}

	@Override
	public Workflow getWorkflow() {
		// this approval rule wouldn't be used for workflows
		return null;
	}

}

package com.tremolosecurity.provisioning.tasks;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

import jcifs.Config;

public class WaitForObjectCreation implements CustomTask {
	
	static Logger logger = Logger.getLogger(WaitForObjectCreation.class);
	
	List<String> uris;
	long timeOut;
	String targetName;
	
	transient WorkflowTask task;

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		Attribute uris = params.get("uris");
		if (uris == null) {
			throw new ProvisioningException("uris not configured");
		}
		
		this.uris = new ArrayList<String>();
		this.uris.addAll(uris.getValues());
		
		Attribute timeOut = params.get("timeOutMillis");
		if (timeOut == null) {
			throw new ProvisioningException("timeOutMillis not configured");
		}
		
		this.timeOut = Long.parseLong(timeOut.getValues().get(0));
		
		Attribute targetName = params.get("targetName");
		if (targetName == null) {
			throw new ProvisioningException("targetName not configured");
		}
		
		this.targetName = targetName.getValues().get(0);
		
		this.task = task;

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		
		long start = System.currentTimeMillis();
		
		for (String uri : this.uris) {
			
			String localUri = task.renderTemplate(uri, request);
			
			boolean found = false;
			
			while (! found) {
				OpenShiftTarget k8s = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.targetName).getProvider();
				
				HttpCon con = null;
				
				try {
					String token = k8s.getAuthToken();
					con = k8s.createClient();
					
					found = k8s.isObjectExistsByPath(token, con, localUri);
					
					if (! found) {
						if ((start + this.timeOut) < System.currentTimeMillis()) {
							throw new ProvisioningException("Timeout waiting for " + localUri);
						} else {
							logger.info(localUri + " not found, waiting 30 seconds");
						}
						
						Thread.sleep(30000);
					} else {
						logger.info(localUri + " found");
					}
					
				} catch (Exception e) {
					throw new ProvisioningException("Could not wait for object creation",e);
				} finally {
					if (con != null) {
						try {
							con.getHttp().close();
						} catch (IOException e) {
							//do nothing
						}
						con.getBcm().close();
					}
				}
			}
		}
		
		return true;
	}

}

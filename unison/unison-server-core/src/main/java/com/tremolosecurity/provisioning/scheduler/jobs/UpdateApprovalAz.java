/*
Copyright 2015, 2018 Tremolo Security, Inc.

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


package com.tremolosecurity.provisioning.scheduler.jobs;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.jms.*;

import com.tremolosecurity.provisioning.scheduler.jobs.util.DisposeConnection;
import org.hibernate.query.Query;
import org.quartz.JobExecutionContext;

import com.google.gson.Gson;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.jms.JMSSessionHolder;
import com.tremolosecurity.provisioning.objects.Approvals;
import com.tremolosecurity.provisioning.scheduler.UnisonJob;
import com.tremolosecurity.provisioning.tasks.Approval;
import com.tremolosecurity.provisioning.util.EncryptedMessage;



public class UpdateApprovalAz extends UnisonJob {


	static JMSSessionHolder session;

	private synchronized void createConnections(ConfigManager configManager,String queueName) throws JMSException, ProvisioningException {
		if (session == null) {
			session = com.tremolosecurity.provisioning.jms.JMSConnectionFactory.getConnectionFactory().getSession(queueName);
		}
	}
	
	@Override
	public void execute(ConfigManager configManager, JobExecutionContext context)
			throws ProvisioningException {


		
		String queueName = context.getJobDetail().getJobDataMap().getString("queueName");
		
		if (configManager == null || configManager.getProvisioningEngine() == null) {
			return;
		}


		
		org.hibernate.Session hsession = configManager.getProvisioningEngine().getHibernateSessionFactory().openSession();
		
		
		try {

			this.createConnections(configManager,queueName);
			
			HashMap<Integer,String> approvals = new HashMap<Integer,String>();
			//PreparedStatement findOpenApprovals = con.prepareStatement("SELECT id,workflowObj FROM approvals WHERE approved IS NULL");
			
			
			
			Query query = hsession.createQuery("FROM Approvals WHERE approved IS NULL");
			List<com.tremolosecurity.provisioning.objects.Approvals> approvalObjs = query.list();
			
			for (Approvals aprv : approvalObjs) {
				approvals.put(aprv.getId(), aprv.getWorkflowObj());
			}
			
			
			
			
			Gson gson = new Gson();
			for (int approvalID : approvals.keySet()) {
				HashMap<Integer,String> wf = new HashMap<Integer,String>();
				wf.put(approvalID, approvals.get(approvalID));
				
				EncryptedMessage em = configManager.getProvisioningEngine().encryptObject(wf);
				
				synchronized (session) {
					TextMessage tmsg = session.getSession().createTextMessage(gson.toJson(em));
					tmsg.setStringProperty("JMSXGroupID", "unison-updateaz");
					
					session.getMessageProduceer().send(tmsg);
				}
			}
			

			
		} catch(Throwable t) {
			
			
			throw new ProvisioningException("Could not process open approvals",t);
		} finally {
			if (hsession != null) {
				hsession.close();
			}
		}
		

	}

	

}

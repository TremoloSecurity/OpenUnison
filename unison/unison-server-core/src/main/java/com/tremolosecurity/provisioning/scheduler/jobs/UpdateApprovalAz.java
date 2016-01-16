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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.jms.MessageProducer;
import javax.jms.ObjectMessage;
import javax.jms.Session;
import javax.jms.TextMessage;

import org.quartz.JobExecutionContext;

import com.google.gson.Gson;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.scheduler.UnisonJob;
import com.tremolosecurity.provisioning.tasks.Approval;
import com.tremolosecurity.provisioning.util.EncryptedMessage;



public class UpdateApprovalAz extends UnisonJob {

	
	
	@Override
	public void execute(ConfigManager configManager, JobExecutionContext context)
			throws ProvisioningException {
		
		
		String queueName = context.getJobDetail().getJobDataMap().getString("queueName");
		
		if (configManager == null || configManager.getProvisioningEngine() == null) {
			return;
		}
		
		
		Connection con = null;
		try {
			con = configManager.getProvisioningEngine().getApprovalDBConn();
		} catch (SQLException e) {
			throw new ProvisioningException("Could not load connection",e);
		}
		
		try {
			
			javax.jms.Connection connection = configManager.getProvisioningEngine().getQueueConnection();
			Session session = connection.createSession(false, javax.jms.Session.AUTO_ACKNOWLEDGE);
			javax.jms.Queue queue = session.createQueue(queueName);
			MessageProducer mp = session.createProducer(queue);
			
			HashMap<Integer,String> approvals = new HashMap<Integer,String>();
			PreparedStatement findOpenApprovals = con.prepareStatement("SELECT id,workflowObj FROM approvals WHERE approved IS NULL");
			ResultSet rs = findOpenApprovals.executeQuery();
			while (rs.next()) {
				approvals.put(rs.getInt("id"), rs.getString("workflowObj"));
				
			}
			
			rs.close();
			findOpenApprovals.close();
			Gson gson = new Gson();
			for (int approvalID : approvals.keySet()) {
				HashMap<Integer,String> wf = new HashMap<Integer,String>();
				wf.put(approvalID, approvals.get(approvalID));
				
				EncryptedMessage em = configManager.getProvisioningEngine().encryptObject(wf);
				TextMessage tmsg = session.createTextMessage(gson.toJson(em));
				
				
				mp.send(tmsg);
			}
			
			mp.close();
			session.close();
			
			
		} catch(Throwable t) {
			try {
				con.rollback();
			} catch (SQLException e) {
				
			}
			
			throw new ProvisioningException("Could not process open approvals",t);
		} finally {
			if (con != null) {
				try {
					con.close();
				} catch (SQLException e) {
					
				}
			}
		}
		

	}

	

}

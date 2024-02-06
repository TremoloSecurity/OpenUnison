/*
Copyright 2015, 2017 Tremolo Security, Inc.

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


package com.tremolosecurity.provisioning.core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.util.Stack;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.jms.JMSException;
import javax.jms.Message;
import javax.jms.MessageConsumer;
import javax.jms.MessageListener;
import javax.jms.ObjectMessage;
import javax.jms.TextMessage;

import org.apache.logging.log4j.Logger;
import org.apache.qpid.jms.message.JmsMessage;

import com.cedarsoftware.util.io.JsonReader;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.tasks.CallWorkflow;
import com.tremolosecurity.provisioning.util.EncryptedMessage;

import com.tremolosecurity.provisioning.util.TaskHolder;
import com.tremolosecurity.server.GlobalEntries;

public class TaskConsumer implements MessageListener {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(TaskConsumer.class.getName());

	private ProvisioningEngine prov;
	private ConfigManager cfgMgr;

	public TaskConsumer(ProvisioningEngine provisioningEngine,ConfigManager cfgMgr) {
		this.prov = provisioningEngine;
		this.cfgMgr = cfgMgr;
	}

	@Override
	public void onMessage(Message msg) {
		
		WorkflowHolder wfHolder = null;
		TextMessage bmsg = null;
		
		try {
			bmsg = (TextMessage) msg;
			
			if (bmsg.getBooleanProperty("unisonignore")) {
				
				if (logger.isDebugEnabled()) {
					logger.debug("ignoring message");
				}
				bmsg.acknowledge();
				return;
			}
			
			String json = null;
			
			try {
				byte[] b64decoded = org.bouncycastle.util.encoders.Base64.decode(bmsg.getText());
				InflaterInputStream decompressor = new InflaterInputStream(new ByteArrayInputStream(b64decoded),new Inflater(true));
				byte[] decomped = decompressor.readAllBytes();
				json = new String(decomped);
			} catch (Throwable t) {
				logger.warn("message is legacy, not base64 encoded",t);
				json = bmsg.getText();
			}
			

			
			
			
			EncryptedMessage encMsg = (EncryptedMessage) JsonReader.jsonToJava(json);
			
			
			wfHolder = (WorkflowHolder) this.prov.decryptObject(encMsg);
		
			//Re-initialize the workflow
			wfHolder.getWorkflow().reInit(cfgMgr);
			
			TaskHolder th = wfHolder.getWfStack().peek();
			WorkflowTask task = th.getParent().get(th.getPosition());
			
			
			
			th.setPosition(th.getPosition() + 1);
			
			User user = th.getCurrentUser();
			if (user == null) {
				user = wfHolder.getUser();
			}
			
			
			
			
			if (task.doTask(user, wfHolder.getRequest())) {
				if (isDone(wfHolder,null)) {
					wfHolder.getWorkflow().completeWorkflow();
				} else {
					((ProvisioningEngineImpl) this.prov).enqueue(wfHolder);
				}
			} else {
				if (isDone(wfHolder,task)) {
					wfHolder.getWorkflow().completeWorkflow();
				} else {
					//do nothing
				}
			}

			// if this is from qpid, set the achnowledgement mode manually
			if (msg instanceof JmsMessage) {
				msg.setIntProperty("JMS_AMQP_ACK_TYPE", 1);
			}
			
			msg.acknowledge();
			
		
		} catch (Throwable t) {
			
			
			
			
			if (this.cfgMgr.getCfg().getProvisioning().getQueueConfig().isManualDlq()) {
				// manually managing the DLQ.  First, log the error
				logger.error(t);
				
				// determine if too many retries
				int numberOfTries = 0;
				try {
					numberOfTries = msg.getIntProperty("TremoloNumTries");
				} catch (JMSException e) {
					numberOfTries = 0;
				}
				numberOfTries++;
				
				if (numberOfTries >= this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getManualDlqMaxAttempts()) {
					this.cfgMgr.getProvisioningEngine().dlqMessage(bmsg);
				} else {
					try {
						((ProvisioningEngineImpl) this.cfgMgr.getProvisioningEngine()).reEnQueueTask(bmsg,numberOfTries);
					} catch (Exception e) {
						logger.error("Could not re-enqueue workflow",e);
					}
				}
				
				try {
					// if this is from qpid, set the achnowledgement mode manually
					if (msg instanceof JmsMessage) {
						msg.setIntProperty("JMS_AMQP_ACK_TYPE", 1);
					}
					
					msg.acknowledge();
				} catch (JMSException e) {
					logger.error("Error handling failed message",e);
				}
				
			}
			
			// if this is from qpid, set the achnowledgement mode manually
			else if (msg instanceof JmsMessage) {
				logger.error("Error processing message",t);
				try {
					msg.setIntProperty("JMS_AMQP_ACK_TYPE", 2);
					msg.acknowledge();
					
				} catch (JMSException e) {
					logger.error("error setting message rejected property",e);
				}
			} else {
			
			
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				PrintWriter baout = new PrintWriter(baos);
				t.printStackTrace(baout);
				baout.flush();
				baout.close();
				StringBuffer b = new StringBuffer();
				b.append("Could not execute task\n").append(new String(baos.toByteArray()));
				throw new RuntimeException(b.toString(),t);
			}
		}
		
	}
	
	private boolean isDone(WorkflowHolder holder, WorkflowTask task) {
		if (holder.getWfStack().isEmpty()) {
			return true;
		} else {
			TaskHolder th = holder.getWfStack().peek();
			if ((th.getPosition() < th.getParent().size()) || (task != null && task.isOnHold())) {
				return false;
			} else {
				holder.getWfStack().pop();
				return isDone(holder,null);
			}
		}
	}

	

}

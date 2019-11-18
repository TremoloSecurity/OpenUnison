/*******************************************************************************
 * Copyright 2019 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.jms;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

import javax.jms.Connection;
import javax.jms.ConnectionFactory;
import javax.jms.JMSException;
import javax.jms.MessageProducer;
import javax.jms.Session;
import javax.jms.TextMessage;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;

import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.server.StopableThread;



public class JMSConnection {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(JMSConnection.class.getName());
	
	
	Connection con;
	ConnectionFactory cf;
	List<JMSSessionHolder> sessions;
	int count;
	int max;
	
	Session keepAliveSession;
	MessageProducer keepAliveMp;
	
	public JMSConnection(ConnectionFactory cf,int max) throws JMSException {
		this.cf = cf;
		this.con = cf.createConnection();
		this.con.start();
		this.sessions = new ArrayList<JMSSessionHolder>();
		this.createKeepAlive();
		count = 1;
		this.max = max;
		
		StopableThread st = new StopableThread() {

			@Override
			public void run() {
				// TODO Auto-generated method stub
				
			}

			@Override
			public void stop() {
				if (con != null) {
					try {
						con.close();
					} catch (Throwable t) {
						//do noting
					}
				}
				
			}
			
		};
		
		GlobalEntries.getGlobalEntries().getConfigManager().addThread(st);
		
		
		
		st = new StopableThread() {
			long lastCheck;
			long timeToWait = 60000L;
			
			
			
			
			
			boolean keepRunning = true;
			
			
			
			@Override
			public void run() {
				
				if (GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning() != null) {
					timeToWait = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getQueueConfig().getKeepAliveMillis(); 
				}
				
				while (keepRunning) {
					long now = System.currentTimeMillis();
					if (lastCheck == 0 || (now-lastCheck >= timeToWait)) {
						synchronized(keepAliveSession) {
							try {
								TextMessage tm = keepAliveSession.createTextMessage(UUID.randomUUID().toString());
								tm.setStringProperty("JMSXGroupID", "unison-keepalive");
								tm.setBooleanProperty("unisonignore", true);
								
								
								if (logger.isDebugEnabled()) {
									logger.debug("Sending keepalive for " + con);
								}
								
								keepAliveMp.send(tm);
							} catch (Throwable t) {
								logger.warn("Could not send keep alive for " + con + ", recreating",t);
								try {
									rebuild();
								} catch (JMSException e) {
									logger.error("Could not recreate connection",e);
								}
							}
						}
						lastCheck = now;
					} else {
						try {
							
							Thread.sleep(10000);
						} catch (InterruptedException e) {
							
						}
					}
				}
				
			}

			@Override
			public void stop() {
				keepRunning = false;
				
			}
			
		};
		
		
		
		GlobalEntries.getGlobalEntries().getConfigManager().addThread(st);
		new Thread(st).start();
		
	}

	

	public Connection getCon() {
		return con;
	}
	
	private void createKeepAlive() throws JMSException {
		String queueName = "";
		ConfigManager cfgMgr = GlobalEntries.getGlobalEntries().getConfigManager();  
		
		boolean isMultiTask = false;
		
		if (cfgMgr.getCfg().getProvisioning() != null) {
			isMultiTask = cfgMgr.getCfg().getProvisioning().getQueueConfig().isMultiTaskQueues(); 
		}
		
		
		
		if (isMultiTask) {
			queueName = cfgMgr.getCfg().getProvisioning().getQueueConfig().getTaskQueueName().replace("{x}", Integer.toString(ThreadLocalRandom.current().nextInt(1,cfgMgr.getCfg().getProvisioning().getQueueConfig().getNumQueues())));
		} else {
			
			String taskQueueName = "unison-tasks";
			
			if (cfgMgr.getCfg().getProvisioning() != null) {
				taskQueueName = cfgMgr.getCfg().getProvisioning().getQueueConfig().getTaskQueueName();
			}
			
			queueName = taskQueueName;
		}
		this.keepAliveSession = this.con.createSession(false, javax.jms.Session.AUTO_ACKNOWLEDGE);
		this.keepAliveMp = this.keepAliveSession.createProducer(this.keepAliveSession.createQueue(queueName));
	}
	
	public void rebuild() throws JMSException {
		this.con = cf.createConnection();
		for (JMSSessionHolder session : sessions) {
			session.rebuild();
		}
		createKeepAlive();
	}
	
	public void sendKeepAlive() throws ProvisioningException {
		try {
			TextMessage tm = this.keepAliveSession.createTextMessage(UUID.randomUUID().toString());
			tm.setStringProperty("JMSXGroupID", "unison-keepalive");
			tm.setBooleanProperty("unisonignore", true);
			
			logger.info("Sending keepalive for " + this.con);
			if (logger.isDebugEnabled()) {
				logger.debug("Sending keepalive for " + this.con);
			}
			
			this.keepAliveMp.send(tm);
		} catch (Throwable t) {
			logger.warn("Could not send keepalive for " + this.con + ", recreating",t);
			try {
				this.rebuild();
			} catch (JMSException e) {
				throw new ProvisioningException("Could not recreate connection",e);
			}
		}
	}
	
	public synchronized JMSSessionHolder createSession(String queueName) throws JMSException {
		if (count < max) {
			JMSSessionHolder session = new JMSSessionHolder(this,queueName);
			this.sessions.add(session);
			count++;
			return session;
		} else { 
			return null;
		}
	}
	
	
}

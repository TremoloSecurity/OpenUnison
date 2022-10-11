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
	private static final String QPID_CON_FACTORY = "org.apache.qpid.jms.JmsConnectionFactory";


	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(JMSConnection.class.getName());
	
	
	Connection con;
	ConnectionFactory cf;
	List<JMSSessionHolder> sessions;
	int count;
	int max;
	int achknowledgementMode;

	
	public JMSConnection(ConnectionFactory cf,int max) throws JMSException {
		if (logger.isDebugEnabled()) {
			logger.debug("Creating new connection " + cf);
		}
		
		if (cf.getClass().getName().equalsIgnoreCase(JMSConnection.QPID_CON_FACTORY)) {
			this.achknowledgementMode = javax.jms.Session.CLIENT_ACKNOWLEDGE;
		} else {
			this.achknowledgementMode = javax.jms.Session.AUTO_ACKNOWLEDGE;
		}
		
		
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
		
		
		if (logger.isDebugEnabled()) {
			logger.debug("Creating new connection checking thread");
		}
		st = new StopableThread() {
			long lastCheck;
			long timeToWait = 60000L;
			
			
			
			
			
			boolean keepRunning = true;
			
			
			
			@Override
			public void run() {
				
				if (GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning() != null &&  GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getQueueConfig() != null) {
					timeToWait = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getQueueConfig().getKeepAliveMillis(); 
				}
				
				while (keepRunning) {
					long now = System.currentTimeMillis();
					if (lastCheck == 0 || (now-lastCheck >= timeToWait)) {
						
						
						for (JMSSessionHolder session : sessions) {
							synchronized (session.getSession()) {
								sendKeepAliveMessage(session);
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

			private void sendKeepAliveMessage(JMSSessionHolder sessionHolder) {
				try {
					TextMessage tm = sessionHolder.getSession().createTextMessage(UUID.randomUUID().toString());
					tm.setStringProperty("JMSXGroupID", "unison-keepalive");
					tm.setBooleanProperty("unisonignore", true);
					
					
					if (logger.isDebugEnabled()) {
						logger.debug("Sending keepalive for " + sessionHolder.getQueueName());
					}
					
					sessionHolder.getMessageProduceer().send(tm);
				} catch (Throwable t) {
					logger.warn("Could not send keep alive for " + sessionHolder.getQueueName() + ", recreating",t);
					try {
						if (keepRunning) {
							rebuild();
						}
					} catch (JMSException e) {
						logger.error("Could not recreate connection",e);
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
		
		if (cfgMgr.getCfg().getProvisioning() != null && cfgMgr.getCfg().getProvisioning().getQueueConfig() != null) {
			isMultiTask = cfgMgr.getCfg().getProvisioning().getQueueConfig().isMultiTaskQueues(); 
		}
		
		
		
		if (isMultiTask) {
			queueName = cfgMgr.getCfg().getProvisioning().getQueueConfig().getTaskQueueName().replace("{x}", Integer.toString(ThreadLocalRandom.current().nextInt(1,cfgMgr.getCfg().getProvisioning().getQueueConfig().getNumQueues())));
		} else {
			
			String taskQueueName = "unison-tasks";
			
			if (cfgMgr.getCfg().getProvisioning() != null && cfgMgr.getCfg().getProvisioning().getQueueConfig() != null) {
				taskQueueName = cfgMgr.getCfg().getProvisioning().getQueueConfig().getTaskQueueName();
			}
			
			queueName = taskQueueName;
		}
		if (logger.isDebugEnabled()) {
			logger.debug("Creating keepalive session for '" + queueName + "'");
		}

	}
	
	public void rebuild() throws JMSException {
		if (logger.isDebugEnabled()) {
			logger.debug("Rebuilding " + this.con);
		}
		this.con = cf.createConnection();
		this.con.start();
		for (JMSSessionHolder session : sessions) {
			session.rebuild();
		}
		createKeepAlive();
	}
	
	public int getAckcnolwedgeMode() {
		return this.achknowledgementMode;
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
	
	public synchronized void removeSession(String queueName)  {
		for (int i=0;i<this.sessions.size();i++) {
			if (sessions.get(i).getQueueName().equalsIgnoreCase(queueName)) {
				sessions.remove(i);
			}
		}
	}
	
	
}

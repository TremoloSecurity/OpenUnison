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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import jakarta.jms.ConnectionFactory;
import jakarta.jms.JMSException;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.server.GlobalEntries;

public class JMSConnectionFactory {

	static JMSConnectionFactory jmsFactory;
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(JMSConnectionFactory.class);
	
	
	synchronized public static JMSConnectionFactory getConnectionFactory() throws ProvisioningException {
		if (jmsFactory == null) {
			jmsFactory = new JMSConnectionFactory();
		}
		
		return jmsFactory;
	}

	private ConfigManager cfgMgr;
	private List<JMSConnection> cons;
	private ConnectionFactory cf;
	
	private boolean isInternalQueue() {
		if (GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning() != null && GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getQueueConfig() != null && ! GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getQueueConfig().isIsUseInternalQueue()) {
			return false;
		} else {
			return true;
		}
	}
	
	public JMSConnectionFactory() throws ProvisioningException {
		this.cfgMgr = GlobalEntries.getGlobalEntries().getConfigManager();
		
		try {
			if (this.isInternalQueue()) {
				
				Class<ConnectionFactory> factoryClass = (Class<ConnectionFactory>) Class.forName("org.apache.activemq.ActiveMQConnectionFactory");
				Constructor<ConnectionFactory> cfInit = factoryClass.getConstructor(String.class);
				cf = (ConnectionFactory) cfInit.newInstance("vm://localhost/localhost");
				
			} else {
				cf = (ConnectionFactory) Class.forName(this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getConnectionFactory()).newInstance();
				for (ParamType pt : this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getParam()) {
					String methodName = "set" + pt.getName().toUpperCase().charAt(0) + pt.getName().substring(1);
					
					try {
						Method m = Class.forName(this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getConnectionFactory()).getMethod(methodName, String.class);
						m.invoke(cf, pt.getValue());
					} catch (NoSuchMethodException e) {
						try {
						//lets try int
						Method m = Class.forName(this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getConnectionFactory()).getMethod(methodName, int.class);
						m.invoke(cf, Integer.parseInt(pt.getValue()));
						} catch (NoSuchMethodException e1) {
							//lets try long
							Method m = Class.forName(this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getConnectionFactory()).getMethod(methodName, long.class);
							m.invoke(cf, Long.parseLong(pt.getValue()));
						}
					}
				}
			}
		} catch (NoSuchMethodException | InvocationTargetException | InstantiationException | IllegalAccessException | ClassNotFoundException e2) {
			throw new ProvisioningException("Could not initialize jms",e2);
		} finally {
			
		}
		
		this.cons = new ArrayList<JMSConnection>();
	}
	
	public synchronized JMSSessionHolder getSession(String queueName) throws ProvisioningException {
		if (logger.isDebugEnabled()) {
			logger.debug("Getting session for '" + queueName + "'");
		}
		
		try {
			if (cons.size() == 0) {
				if (logger.isDebugEnabled()) {
					logger.debug("No connections - '" + queueName + "'");
				}
				int maxSessions = 10;
				
				if (this.cfgMgr.getCfg().getProvisioning() != null && this.cfgMgr.getCfg().getProvisioning().getQueueConfig() != null) {
					maxSessions = this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getMaxSessionsPerConnection();
				}
				
				if (logger.isDebugEnabled()) {
					logger.debug("Creating JMS Connection for '" + queueName + "' with " + maxSessions + " sessions");
				}
				
				JMSConnection con = new JMSConnection(cf,maxSessions);
				this.cons.add(con);
				
			}
			
			if (logger.isDebugEnabled()) {
				logger.debug("Retrieving session for '" + queueName + "'");
			}
			
			JMSSessionHolder session = null;
			
			synchronized (cons) {
				JMSConnection con = cons.get(cons.size() - 1);
				session = con.createSession(queueName);
			}
			
			if (logger.isDebugEnabled()) {
				logger.debug("Session for '" + queueName + "' - '" + session + "'");
			}
			
			if (session == null) {
				if (logger.isDebugEnabled()) {
					logger.debug("Creating new connection '" + queueName + "'");
				}
				
				JMSConnection con = new JMSConnection(cf,this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getMaxSessionsPerConnection());
				this.cons.add(con);
				session = cons.get(cons.size() - 1).createSession(queueName);
				
				if (logger.isDebugEnabled()) {
					logger.debug("Session 2 for '" + queueName + "' - '" + session + "'");
				}
			}
			
			
			
			return session;
		} catch (JMSException e) {
			throw new ProvisioningException("Could not initialize session",e);
		}
	}
}

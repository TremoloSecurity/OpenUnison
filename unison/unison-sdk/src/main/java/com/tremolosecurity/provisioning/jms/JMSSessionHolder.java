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

import javax.jms.JMSException;
import javax.jms.MessageConsumer;
import javax.jms.MessageListener;
import javax.jms.MessageProducer;
import javax.jms.Queue;
import javax.jms.Session;

import org.apache.logging.log4j.Logger;

public class JMSSessionHolder {
	
	JMSConnection con;
	
	Session session;
	Queue queue;
	String queueName;
	MessageProducer mp;
	MessageListener ml;
	MessageConsumer mc;
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(JMSSessionHolder.class);
	
	public JMSSessionHolder(JMSConnection con,String queueName) throws JMSException {
		if (logger.isDebugEnabled()) {
			logger.debug("Creating new JMSSessionHolder for '" + queueName + "'", new Exception("For Thread Dump"));
			
		}
		this.con = con;
		this.session = con.getCon().createSession(false, javax.jms.Session.AUTO_ACKNOWLEDGE);
		this.queueName = queueName;
		this.queue = session.createQueue(this.queueName);
		
	}
	
	public void rebuild() throws JMSException {
		if (logger.isDebugEnabled()) {
			logger.debug("Rebuilding JMSSessionHolder for '" + queueName + "'" );
		}
		this.session = con.getCon().createSession(false, javax.jms.Session.AUTO_ACKNOWLEDGE);
		this.queue = session.createQueue(this.queueName);
		
		if (mp != null) {
			this.mp = session.createProducer(queue);
		} 
		
		
		if (mc != null)  {
			this.mc = session.createConsumer(queue);
			this.mc.setMessageListener(ml);
		}
	}
	
	public void setMessageListener(MessageListener ml) throws JMSException {
		this.ml = ml;
		if (mc == null) {
			this.mc = session.createConsumer(this.queue);
		}
		this.mc.setMessageListener(ml);
	}
	
	public MessageConsumer getMessageConsumer() throws JMSException {
		if (mc == null) {
			this.mc = session.createConsumer(this.queue);
		}
		
		return this.mc;
	}
	
	public MessageProducer getMessageProduceer() throws JMSException {
		if (this.mp == null) {
			
			this.mp = session.createProducer(queue);
		}
		
		return this.mp;
	}
	
	public Session getSession() {
		return this.session;
	}

	public String getQueueName() {
		return this.queueName;
	}
}

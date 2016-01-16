/*******************************************************************************
 * Copyright 2015 Tremolo Security, Inc.
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
package com.tremolosecurity.openunison.util.queue;

import java.lang.reflect.Method;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.UUID;

import javax.jms.ConnectionFactory;
import javax.jms.Message;
import javax.jms.MessageConsumer;
import javax.jms.MessageProducer;
import javax.jms.Queue;
import javax.jms.Session;
import javax.jms.TextMessage;

import org.apache.log4j.Logger;

import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.TremoloType;

public class QueUtils {

	static Logger logger = Logger.getLogger(QueUtils.class.getName());
	
	public static void emptyDLQ(TremoloType config,String dlqName) throws Exception {
		
		if (config.getProvisioning().getQueueConfig().isIsUseInternalQueue()) {
			throw new Exception("This feature is not available for interal queues");
		}
		
		String dlqSessionID = UUID.randomUUID().toString();
		
		logger.info("DLQ Run : " + dlqSessionID);
		
		logger.info("Connecting to " + config.getProvisioning().getQueueConfig().getConnectionFactory());
		ConnectionFactory cf = (ConnectionFactory) Class.forName(config.getProvisioning().getQueueConfig().getConnectionFactory()).newInstance();
		for (ParamType pt : config.getProvisioning().getQueueConfig().getParam()) {
			String methodName = "set" + pt.getName().toUpperCase().charAt(0) + pt.getName().substring(1);
			Method m = Class.forName(config.getProvisioning().getQueueConfig().getConnectionFactory()).getMethod(methodName, String.class);
			m.invoke(cf, pt.getValue());
		}
		
		javax.jms.Connection con = cf.createConnection();
		con.start();
		
		logger.info("Connected");
		
		logger.info("Creating queue " + dlqName);
		
		Session session = con.createSession(false, Session.CLIENT_ACKNOWLEDGE);
		Queue queue = session.createQueue(dlqName);
		
		MessageConsumer consumer = session.createConsumer(queue);
		
		logger.info("Checking for messages");
		
		Message receivedMessage = consumer.receive(1000);
		
		HashMap<String,MessageProducer> qs = new HashMap<String,MessageProducer>();
		
		while (receivedMessage != null) {
			logger.info("Processing message : " + receivedMessage.getJMSMessageID());
			
			if (receivedMessage.getStringProperty("dlqRunID") != null && receivedMessage.getStringProperty("dlqRunID").equalsIgnoreCase(dlqSessionID)) {
				logger.info("Message already processed, stopping the run");
				break;
			} 
			
			
			String originalQueue = receivedMessage.getStringProperty("OriginalQueue");
			logger.info("Adding message " + receivedMessage.getJMSMessageID() + " to queue " + originalQueue);
			
			TextMessage m = session.createTextMessage();
			
			m.setStringProperty("dlqRunID", dlqSessionID);
			
			m.setText(((TextMessage) receivedMessage).getText());
			
			Enumeration enumer = receivedMessage.getPropertyNames();
			while (enumer.hasMoreElements()) {
				String propName = (String) enumer.nextElement();
				m.setObjectProperty(propName, receivedMessage.getObjectProperty(propName));
			}
			
			
			if (qs.containsKey(originalQueue)) {
				qs.get(originalQueue).send(m);
			} else {
				Queue q = session.createQueue(originalQueue);
				MessageProducer lmp = session.createProducer(q);
				qs.put(originalQueue, lmp);
				lmp.send(m);
			}
			
			receivedMessage.acknowledge();
			//session.commit();
			
			logger.info("Message Sent");
			logger.info("Receiving Next Message");
			receivedMessage = consumer.receive(1000);
		}
		
		for (String key : qs.keySet()) {
			qs.get(key).close();
		}
		
		consumer.close();
		session.close();
		con.close();
		
		logger.info("Queue Emptied");
		
	}
}

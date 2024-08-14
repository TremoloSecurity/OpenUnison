/*******************************************************************************
 * Copyright 2015, 2017 Tremolo Security, Inc.
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

import jakarta.jms.ConnectionFactory;
import jakarta.jms.Destination;
import jakarta.jms.JMSException;
import jakarta.jms.Message;
import jakarta.jms.MessageConsumer;
import jakarta.jms.MessageProducer;
import jakarta.jms.Queue;
import jakarta.jms.Session;
import jakarta.jms.TextMessage;

import org.apache.logging.log4j.Logger;
import org.apache.qpid.jms.message.JmsMessage;
import org.apache.qpid.jms.message.JmsTextMessage;
import org.apache.qpid.jms.provider.amqp.message.AmqGetAnnotations;
import org.apache.qpid.jms.provider.amqp.message.AmqpJmsMessageFacade;
import org.apache.qpid.jms.provider.amqp.message.AmqpJmsTextMessageFacade;

import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.TremoloType;

import net.sourceforge.myvd.types.Bool;

public class QueUtils {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(QueUtils.class.getName());
	
	public static void emptyDLQ(TremoloType config,String dlqName, String originalQueueAttributeName) throws Exception {
		
		if (config.getProvisioning().getQueueConfig().isIsUseInternalQueue()) {
			throw new Exception("This feature is not available for interal queues");
		}


		try {

			String dlqSessionID = UUID.randomUUID().toString();

			logger.info("DLQ Run : " + dlqSessionID);

			logger.info("Connecting to " + config.getProvisioning().getQueueConfig().getConnectionFactory());
			ConnectionFactory cf = (ConnectionFactory) Class.forName(config.getProvisioning().getQueueConfig().getConnectionFactory()).newInstance();
			for (ParamType pt : config.getProvisioning().getQueueConfig().getParam()) {
				String methodName = "set" + pt.getName().toUpperCase().charAt(0) + pt.getName().substring(1);
				Method m = Class.forName(config.getProvisioning().getQueueConfig().getConnectionFactory()).getMethod(methodName, String.class);
				m.invoke(cf, pt.getValue());
			}

			jakarta.jms.Connection con = cf.createConnection();
			con.start();

			logger.info("Connected");

			logger.info("Creating queue " + dlqName);

			Session session = con.createSession(false, Session.CLIENT_ACKNOWLEDGE);
			
			
			
			Queue queue = session.createQueue(dlqName);

			MessageConsumer consumer = session.createConsumer(queue);

			logger.info("Checking for messages");
			
			
			
			
			final Bool runDone = new Bool(false);
			
			
			
			LastMessageTime last = new LastMessageTime();
			last.lastMessageTime = System.currentTimeMillis();
			HashMap<String, MessageProducer> qs = new HashMap<String, MessageProducer>();
			
			consumer.setMessageListener(receivedMessage -> {
				try {
					logger.info("Processing message : " + receivedMessage.getJMSMessageID());
					synchronized(last) {
						last.lastMessageTime = System.currentTimeMillis();
					}
					if (receivedMessage.getStringProperty("dlqRunID") != null && receivedMessage.getStringProperty("dlqRunID").equalsIgnoreCase(dlqSessionID)) {
						logger.info("Message already processed, stopping the run");
						runDone.setValue(true);
						return;
					}
					
					if (receivedMessage.getBooleanProperty("unisonignore")) {
						
						if (logger.isDebugEnabled()) {
							logger.debug("ignoring message");
						}
						receivedMessage.acknowledge();
						receivedMessage = consumer.receive(1000);
						return;
					}


					String originalQueue = null;
					
					
					
					if (receivedMessage instanceof JmsMessage) {
						
						AmqGetAnnotations aga = new AmqGetAnnotations((AmqpJmsMessageFacade) ((JmsMessage) receivedMessage).getFacade());
						originalQueue = aga.getMessageAnnotation(originalQueueAttributeName);
						
					}
					
					
					
					
					if (originalQueue == null) {
						if (originalQueueAttributeName != null) {
							
							originalQueue = receivedMessage.getStringProperty(originalQueueAttributeName);
						} else {
							originalQueue = receivedMessage.getStringProperty("OriginalQueue");
						}
					}
					
					
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
					
					// if this is from qpid, set the achnowledgement mode manually
					if (receivedMessage instanceof JmsMessage) {
						receivedMessage.setIntProperty("JMS_AMQP_ACK_TYPE", 1);
					}

					receivedMessage.acknowledge();
					//session.commit();

					logger.info("Message Sent");
				} catch (JMSException e) {
					runDone.setValue(true);
					logger.error("Could not process message",e);
				}
            });
			
			
			
			
			
			
			
			
			
			while (! runDone.getValue()) {
				logger.info("Sleeping for 1 second...");
				Thread.sleep(1000);
				
				synchronized (last) {
					if (System.currentTimeMillis() - last.lastMessageTime > 1000) {
						logger.info("No new messages for 1 second, ending run");
						runDone.setValue(true);
					}
				}
			}
			
			
			for (String key : qs.keySet()) {
				qs.get(key).close();
			}

			consumer.close();
			session.close();
			con.close();

			logger.info("Queue Emptied");
		} catch (Throwable t) {
			logger.warn("Error while clearing DLQ",t);
		}
	}
}

class LastMessageTime {
	long lastMessageTime;
}

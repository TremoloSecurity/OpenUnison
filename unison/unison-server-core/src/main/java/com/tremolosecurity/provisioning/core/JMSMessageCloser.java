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


package com.tremolosecurity.provisioning.core;

import javax.jms.Connection;
import javax.jms.JMSException;
import javax.jms.MessageConsumer;
import javax.jms.Session;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.server.StopableThread;

public class JMSMessageCloser implements StopableThread {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(JMSMessageCloser.class.getName());
	Session session;
	MessageConsumer consumer;
	private Connection con;
	
	public JMSMessageCloser(Session session,MessageConsumer consumer) {
		this.session = session;
		this.consumer = consumer;
	}
	
	public JMSMessageCloser(Connection con,Session session,MessageConsumer consumer) {
		this.session = session;
		this.consumer = consumer;
		this.con = con;
	}
	
	
	@Override
	public void run() {
		//We actually don't care
	}

	@Override
	public void stop() {
		try {
			consumer.setMessageListener(null);
			consumer.close();
			
			if (this.con != null) {
				this.con.close();
			}
		} catch (JMSException e) {
			logger.warn("Could not close consumer",e);
		}
		
		try {
			session.close();
		} catch (JMSException e) {
			logger.warn("Could not close session",e);
		}

	}

	public Connection getCon() {
		return con;
	}
	
	

}

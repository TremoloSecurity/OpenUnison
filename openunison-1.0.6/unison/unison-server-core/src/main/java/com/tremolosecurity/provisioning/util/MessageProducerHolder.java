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


package com.tremolosecurity.provisioning.util;

import javax.jms.Connection;
import javax.jms.MessageProducer;
import javax.jms.Session;

public class MessageProducerHolder {
	MessageProducer producer;
	Connection con;
	Session session;
	
	public MessageProducerHolder(Connection con,MessageProducer producer,Session session) {
		this.con = con;
		this.producer = producer;
		this.session = session;
	}

	public MessageProducer getProducer() {
		return producer;
	}

	public Connection getCon() {
		return con;
	}

	public Session getSession() {
		return session;
	}
	
	
	
	
}

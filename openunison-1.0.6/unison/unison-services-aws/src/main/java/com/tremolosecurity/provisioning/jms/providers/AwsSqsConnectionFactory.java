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


package com.tremolosecurity.provisioning.jms.providers;

import javax.jms.Connection;
import javax.jms.ConnectionFactory;
import javax.jms.JMSContext;
import javax.jms.JMSException;

import org.skyscreamer.nevado.jms.NevadoConnectionFactory;
import org.skyscreamer.nevado.jms.connector.amazonaws.AmazonAwsSQSConnectorFactory;

public class AwsSqsConnectionFactory implements ConnectionFactory {

	private NevadoConnectionFactory factory;
	
	
	public AwsSqsConnectionFactory() {
		this.factory = new NevadoConnectionFactory();
		this.factory.setSqsConnectorFactory(new AmazonAwsSQSConnectorFactory());
	}
	
	@Override
	public Connection createConnection() throws JMSException {
		return factory.createConnection();
	}

	@Override
	public Connection createConnection(String arg0, String arg1)
			throws JMSException {
		return factory.createConnection(arg0, arg1);
	}

	@Override
	public JMSContext createContext() {
		return this.createContext();
	}

	@Override
	public JMSContext createContext(int arg0) {
		return this.createContext(arg0);
	}

	@Override
	public JMSContext createContext(String arg0, String arg1) {
		
		return this.createContext(arg0, arg1);
	}

	@Override
	public JMSContext createContext(String arg0, String arg1, int arg2) {
		
		return this.createContext(arg0, arg1, arg2);
	}

	public void setUseAsync(String val) {
		((AmazonAwsSQSConnectorFactory) this.factory.getSqsConnectorFactory()).setUseAsyncSend(Boolean.getBoolean(val));
	}
	
	public void setUseSecure(String val) {
		((AmazonAwsSQSConnectorFactory) this.factory.getSqsConnectorFactory()).setSecure(Boolean.getBoolean(val));
	}
	
	public void setAwsAccessKey(String val) {
		factory.setAwsAccessKey(val);
		
	}
	
	public void setAwsSecretKey(String val) {
		factory.setAwsSecretKey(val);
	}
	
	public void setEndPoint(String val) {
		this.factory.setAwsSQSEndpoint(val);
	}
	
}

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

import com.amazon.sqs.javamessaging.SQSConnectionFactory;
import com.amazon.sqs.javamessaging.SQSConnectionFactory.Builder;
import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.internal.StaticCredentialsProvider;



public class AwsSqsConnectionFactory implements ConnectionFactory {

	private SQSConnectionFactory factory;
	
	
	String secretKey;
	String accessKey;
	String regionName;
	
	ClientConfiguration clientConfig;
	
	public AwsSqsConnectionFactory() {
		
		
	}
	
	@Override
	public Connection createConnection() throws JMSException {
		Builder builder = SQSConnectionFactory.builder().withAWSCredentialsProvider(new StaticCredentialsProvider(new BasicAWSCredentials(this.accessKey,this.secretKey)));
		
		if (this.regionName != null && ! this.regionName.isEmpty()) {
			builder = builder.withRegionName(regionName);
		}
		
		this.factory = builder.build();
		
		return factory.createConnection();
	}

	@Override
	public Connection createConnection(String arg0, String arg1)
			throws JMSException {
		return factory.createConnection(arg0, arg1);
	}

	@Override
	public JMSContext createContext() {
		return this.factory.createContext();
	}

	@Override
	public JMSContext createContext(int arg0) {
		return this.factory.createContext(arg0);
	}

	@Override
	public JMSContext createContext(String arg0, String arg1) {
		
		return this.factory.createContext(arg0, arg1);
	}

	@Override
	public JMSContext createContext(String arg0, String arg1, int arg2) {
		
		return this.factory.createContext(arg0, arg1, arg2);
	}


	
	
	
	public void setAwsAccessKey(String val) {
		this.accessKey = val;
		
	}
	
	public void setAwsSecretKey(String val) {
		this.secretKey = val;
	}
	

	public void setRegion(String val) {
		this.regionName = val;
	}
	
	
}

/*
Copyright 2015, 2017 Tremolo Security, Inc.

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

import jakarta.jms.Connection;
import jakarta.jms.ConnectionFactory;
import jakarta.jms.JMSContext;
import jakarta.jms.JMSException;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.SqsClientBuilder;

import com.amazon.sqs.javamessaging.ProviderConfiguration;
import com.amazon.sqs.javamessaging.SQSConnectionFactory;


public class AwsSqsConnectionFactory implements ConnectionFactory {

	
	
	
	String secretKey;
	String accessKey;
	String regionName;
	
	
	
	public AwsSqsConnectionFactory() {
		
		
	}
	
	@Override
	public Connection createConnection() throws JMSException {
		SQSConnectionFactory factory;
		
		
		
		SqsClientBuilder builder = SqsClient.builder();
		
		
		
		if (this.accessKey == null || this.accessKey.isEmpty()) {
			
		} else {
			
			builder = builder.credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create(this.accessKey,this.secretKey)));
			
		}
		
		if (this.regionName != null && ! this.regionName.isEmpty()) {
			builder = builder.region(software.amazon.awssdk.regions.Region.of(this.regionName)); 
					
					
		}
		
		factory = new SQSConnectionFactory(new ProviderConfiguration(),builder.build());
		
		return factory.createConnection();
	}

	@Override
	public Connection createConnection(String arg0, String arg1)
			throws JMSException {
		return null;
	}

	@Override
	public JMSContext createContext() {
		return null;
	}

	@Override
	public JMSContext createContext(int arg0) {
		return null;
	}

	@Override
	public JMSContext createContext(String arg0, String arg1) {
		
		return null;
	}

	@Override
	public JMSContext createContext(String arg0, String arg1, int arg2) {
		
		return null;
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

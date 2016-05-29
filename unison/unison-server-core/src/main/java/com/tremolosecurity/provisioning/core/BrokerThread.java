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


import org.apache.activemq.broker.BrokerService;
import org.apache.logging.log4j.Logger;

import com.tremolosecurity.server.StopableThread;

public class BrokerThread implements StopableThread {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(BrokerThread.class.getName());
	BrokerService broker;
	ProvisioningEngineImpl engine;
	
	public BrokerThread(BrokerService broker,ProvisioningEngineImpl engine) {
		this.broker = broker;
		this.engine = engine;
	}
	
	@Override
	public void run() {
		try {
			broker.start();
		} catch (Exception e) {
			logger.error("Can not start broker",e);
		}
		
	}

	@Override
	public void stop() {
		try {
			broker.stop();
			engine.endBroker();
		} catch (Exception e) {
			logger.error("Can not stop broker",e);
		}
		BrokerHolder.reset();
	}
	

}

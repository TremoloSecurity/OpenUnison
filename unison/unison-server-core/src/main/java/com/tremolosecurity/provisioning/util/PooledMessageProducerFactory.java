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


package com.tremolosecurity.provisioning.util;

import javax.jms.Connection;
import javax.jms.MessageProducer;
import javax.jms.Queue;
import javax.jms.Session;

import org.apache.commons.pool2.PooledObject;
import org.apache.commons.pool2.PooledObjectFactory;
import org.apache.commons.pool2.impl.DefaultPooledObject;
import org.apache.commons.pool2.impl.GenericObjectPool;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningEngineImpl;

public class PooledMessageProducerFactory implements PooledObjectFactory<MessageProducerHolder> {

	ProvisioningEngineImpl prov;
	ConfigManager cfg;
	String taskQueueName;
	
	
	public PooledMessageProducerFactory(ConfigManager cfgMgr, ProvisioningEngineImpl provisioningEngineImpl,String queueName) {
		this.cfg = cfgMgr;
		this.prov = provisioningEngineImpl;
		
		/*taskQueueName = "TremoloUnisonTaskQueue";
		if (this.cfg.getCfg().getProvisioning() != null && this.cfg.getCfg().getProvisioning().getQueueConfig() != null) {
			taskQueueName = this.cfg.getCfg().getProvisioning().getQueueConfig().getTaskQueueName();
		}*/
		
		this.taskQueueName = queueName;
	}
	
	@Override
	public void activateObject(PooledObject<MessageProducerHolder> mph)
			throws Exception {
		//do nothing
		
	}

	@Override
	public void destroyObject(PooledObject<MessageProducerHolder> mph)
			throws Exception {
		mph.getObject().getProducer().close();
		mph.getObject().getSession().close();
		mph.getObject().getCon().close();
		
	}

	@Override
	public PooledObject<MessageProducerHolder> makeObject() throws Exception {
		Connection con = prov.getQueueConnection();
		Session session = con.createSession(false, Session.AUTO_ACKNOWLEDGE);
		Queue q = session.createQueue(taskQueueName);
		MessageProducer mp = session.createProducer(q);
		return new DefaultPooledObject(new MessageProducerHolder(con,mp,session));
	}

	@Override
	public void passivateObject(PooledObject<MessageProducerHolder> arg0)
			throws Exception {
		//Do nothing
		
	}

	@Override
	public boolean validateObject(PooledObject<MessageProducerHolder> mph) {
		//TODO need something here?
		return true;
	}

}

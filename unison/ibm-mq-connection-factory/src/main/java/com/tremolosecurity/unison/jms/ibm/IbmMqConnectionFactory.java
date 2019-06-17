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

package com.tremolosecurity.unison.jms.ibm;

import javax.jms.Connection;
import javax.jms.ConnectionFactory;
import javax.jms.JMSContext;
import javax.jms.JMSException;

import com.ibm.msg.client.jms.JmsConnectionFactory;
import com.ibm.msg.client.jms.JmsFactoryFactory;
import com.ibm.msg.client.wmq.WMQConstants;

/**
 * IbmMqConnectionFactory
 */
public class IbmMqConnectionFactory implements ConnectionFactory {

    JmsConnectionFactory mqConnectionFactory;

    public IbmMqConnectionFactory() throws JMSException {
        JmsFactoryFactory ff = JmsFactoryFactory.getInstance(WMQConstants.WMQ_PROVIDER);
        mqConnectionFactory = ff.createConnectionFactory();
        this.mqConnectionFactory.setIntProperty(WMQConstants.WMQ_CONNECTION_MODE, WMQConstants.WMQ_CM_CLIENT);
        this.mqConnectionFactory.setBooleanProperty(WMQConstants.USER_AUTHENTICATION_MQCSP, true);
    }

	@Override
	public Connection createConnection() throws JMSException {
		return mqConnectionFactory.createConnection();
	}

	@Override
	public Connection createConnection(String userName, String password) throws JMSException {
		return mqConnectionFactory.createConnection(userName, password);
	}

	@Override
	public JMSContext createContext() {
		return mqConnectionFactory.createContext();
	}

	@Override
	public JMSContext createContext(String userName, String password) {
		return mqConnectionFactory.createContext(userName, password);
	}

	@Override
	public JMSContext createContext(String userName, String password, int sessionMode) {
		return mqConnectionFactory.createContext(userName, password, sessionMode);
	}

	@Override
	public JMSContext createContext(int sessionMode) {
		return mqConnectionFactory.createContext(sessionMode);
	}

    public void setHost(String host) throws JMSException {
        this.mqConnectionFactory.setStringProperty(WMQConstants.WMQ_HOST_NAME, host);
    }

    public String getHost() throws JMSException {
        return this.mqConnectionFactory.getStringProperty(WMQConstants.WMQ_HOST_NAME);
    }

    public void setPort(String port) throws NumberFormatException, JMSException {
        this.mqConnectionFactory.setIntProperty(WMQConstants.WMQ_PORT, Integer.parseInt(port));
    }

    public String getPort() throws JMSException {
        return Integer.toString(this.mqConnectionFactory.getIntProperty(WMQConstants.WMQ_PORT));
    }
    
    public void setQueueManager(String qmgr) throws JMSException {
        this.mqConnectionFactory.setStringProperty(WMQConstants.WMQ_QUEUE_MANAGER, qmgr);
    }

    public String getQueueManager() throws JMSException {
        return this.mqConnectionFactory.getStringProperty(WMQConstants.WMQ_QUEUE_MANAGER);
    }

    public void setApplicationName(String appName) throws JMSException {
        this.mqConnectionFactory.setStringProperty(WMQConstants.WMQ_APPLICATIONNAME, appName);
    }

    public String getApplicationName() throws JMSException {
        return this.mqConnectionFactory.getStringProperty(WMQConstants.WMQ_APPLICATIONNAME);
    }

    public void setChannel(String channel) throws JMSException {
        this.mqConnectionFactory.setStringProperty(WMQConstants.WMQ_CHANNEL, channel);
    }

    public String getChannel() throws JMSException {
        return this.mqConnectionFactory.getStringProperty(WMQConstants.WMQ_CHANNEL);
    }
}
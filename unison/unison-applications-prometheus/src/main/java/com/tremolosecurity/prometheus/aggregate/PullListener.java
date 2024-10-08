/*
Copyright 2018 Tremolo Security, Inc.

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

package com.tremolosecurity.prometheus.aggregate;


import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.prometheus.data.AggregateURL;
import com.tremolosecurity.prometheus.sdk.AdditionalMetrics;
import com.tremolosecurity.prometheus.util.CloseSession;
import com.tremolosecurity.prometheus.util.PrometheusUtils;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.UnisonMessageListener;
import com.tremolosecurity.provisioning.jms.JMSConnectionFactory;
import com.tremolosecurity.provisioning.jms.JMSSessionHolder;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.util.JsonTools;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import jakarta.jms.Connection;
import jakarta.jms.JMSException;
import jakarta.jms.Message;
import jakarta.jms.MessageConsumer;
import jakarta.jms.MessageProducer;
import jakarta.jms.Queue;
import jakarta.jms.Session;
import jakarta.jms.TextMessage;

import org.apache.logging.log4j.Logger;


public class PullListener extends UnisonMessageListener {
    PullMetrics pull;
    String sendToQueueName;

    static Logger logger = org.apache.logging.log4j.LogManager.getLogger(PullListener.class.getName());

    AdditionalMetrics additionalMetrics;

    JMSSessionHolder jmsSession;

    HashMap<String, Attribute> attributes;
    
    
    
	@Override
	public void init(ConfigManager cfg, HashMap<String, Attribute> attributes) throws ProvisioningException {
        Gson gson = new Gson();
        String urlList;
		try {
			urlList = PrometheusUtils.decompress(attributes.get("urls").getValues().get(0));
		} catch (IOException e1) {
			throw new ProvisioningException("Could not decompress url configuration",e1);
		}

        


        Type listType = new TypeToken<ArrayList<AggregateURL>>(){}.getType();
        this.pull = new PullMetrics((List<AggregateURL>)gson.fromJson(urlList, listType),cfg);

        this.sendToQueueName = attributes.get("sendToQueueName").getValues().get(0);
        this.attributes = attributes;
        if (attributes.get("additionalMetricsClassName") != null) {
            try {
                this.additionalMetrics = (AdditionalMetrics) Class.forName(attributes.get("additionalMetricsClassName").getValues().get(0)).newInstance();
                
			} catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
				throw new ProvisioningException("Could not instantiate additional metrics");
			}
        }
	}

	@Override
	public void onMessage(ConfigManager cfg, Object payload, Message msg) throws ProvisioningException {
        //no data right now, maybe in the future
        PullRequest pr = (PullRequest) payload;
        logger.debug("in message");
        pullData(cfg,pr);

        
    }

	private synchronized void pullData(ConfigManager cfg,PullRequest request) throws ProvisioningException {

        buildQueueConnections(cfg);

        logger.debug("in pull data");
        PullResponse pullResponse;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintWriter out = new PrintWriter(baos);
        logger.debug("pulling from remote systems");
        try {
			pull.writeMetrics(out);
		} catch (IOException e) {
            logger.warn("Can not pull logs",e);
            pullResponse = new PullResponse("",request.getId(),false);
        }
        logger.debug("pull done");
        
        if (this.additionalMetrics != null) {
            this.additionalMetrics.addMetrics(out);
        }

        logger.debug("compressing response");
		try {
			pullResponse = new PullResponse(PrometheusUtils.compress(new String(baos.toByteArray())),request.getId(),true);
		} catch (IOException e1) {
			pullResponse = new PullResponse("",request.getId(),false);
			
			
		}
        logger.debug("response compressed");
        
		try {
            

            
           synchronized (this.jmsSession) {
        	   logger.debug("creating and sending message");
               TextMessage tm = this.jmsSession.getSession().createTextMessage( JsonTools.writeObjectToJson(pullResponse));
               tm.setStringProperty("JMSXGroupID", "unison-prometheus-response");
               this.jmsSession.getMessageProduceer().send(tm);
               logger.debug("sent");
           }
            

            

        } catch (JMSException e) {
            logger.warn("Can not send response",e);
        }
	}

	private void buildQueueConnections(ConfigManager cfg) throws ProvisioningException {
		try {
            if (jmsSession == null) {
                logger.debug("creating queues");
                this.jmsSession = JMSConnectionFactory.getConnectionFactory().getSession(this.sendToQueueName);
                if (this.additionalMetrics != null) {
                    this.additionalMetrics.init(this, cfg, attributes);
                }
                logger.debug("created queues");
            }
        } catch (Throwable t) {
            throw new ProvisioningException("Could not initailize queues");
        }
	}
    
    @Override
    public boolean isEncrypted() {
        return false;
    }

    public JMSSessionHolder getJMSSession() {
        return this.jmsSession;
    }

} 
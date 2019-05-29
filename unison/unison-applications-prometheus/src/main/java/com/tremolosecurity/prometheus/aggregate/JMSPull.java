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

import com.cedarsoftware.util.io.JsonReader;
import com.cedarsoftware.util.io.JsonWriter;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.prometheus.sdk.AdditionalMetrics;
import com.tremolosecurity.prometheus.util.CloseSession;
import com.tremolosecurity.prometheus.util.PrometheusUtils;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.server.StopableThread;

import java.io.IOException;
import java.io.Writer;
import javax.jms.JMSException;
import javax.jms.MessageConsumer;
import javax.jms.MessageProducer;
import javax.jms.Queue;
import javax.jms.Session;
import javax.jms.TextMessage;
import javax.jms.Message;
import javax.jms.Connection;
import org.apache.logging.log4j.Logger;

public class JMSPull implements HttpFilter {
    static Logger logger = org.apache.logging.log4j.LogManager.getLogger(JMSPull.class.getName());

    String requestQueueName;
    String responseQueueName;
    String instance;
    String job;

    Connection connection = null;
    Session session = null;
    Queue requestQueue = null;
    Queue responseQueue = null;
    MessageConsumer responseQueueConsumer = null;
    
    MessageProducer mp = null;

    private ConfigManager cfg;
    private HttpFilterConfig httpCfg;
    
    AdditionalMetrics additionalMetrics;

    long maxWaitTime;

	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain) throws Exception {
        runPull(response);
	}

	private synchronized void runPull(HttpFilterResponse response) throws IOException {
		
		try {

            if (connection == null) {
                connection = cfg.getProvisioningEngine().getQueueConnection();

                session = connection.createSession(false, javax.jms.Session.AUTO_ACKNOWLEDGE);
                requestQueue = session.createQueue(this.requestQueueName);
                
                responseQueue = session.createQueue(this.responseQueueName);
                responseQueueConsumer = session.createConsumer(responseQueue);
                
                mp = session.createProducer(requestQueue);

                cfg.addThread(new CloseSession(connection,session));

                if (this.additionalMetrics != null) {
                    this.additionalMetrics.init(this, cfg, this.httpCfg);
                }
            }

            //first lets drain the response queue
            
            Message m = null;
            logger.debug("Purging existing messages");
            while (  (m = responseQueueConsumer.receiveNoWait()) != null) {
                if (logger.isDebugEnabled()) {
                    logger.debug("purging : " + m.getJMSMessageID());
                }

            }
            logger.debug("Done perging");

            
            PullRequest pullRequest = new PullRequest();
            
            TextMessage tm = session.createTextMessage(JsonWriter.objectToJson(pullRequest));
            tm.setStringProperty("JMSXGroupID", "unison-prometheus-request");
            mp.send(tm);
            
            
            PullResponse pullResponse  = null;
            boolean found = false;
            while (! found) {
                tm = (TextMessage) responseQueueConsumer.receive(this.maxWaitTime);
                if (tm == null) {
                    throw new Exception("No response in time");
                }
                
                

                pullResponse = (PullResponse) JsonReader.jsonToJava(tm.getText());
                found = pullResponse.getId().equals(pullRequest.getId());

                if (! found) {
                    logger.warn("Discarding response to request " + pullResponse.getId());
                }
            }

            if (! pullResponse.isSuccess()) {
                throw new Exception("Could not pull metrics");
            }

            response.getWriter().write(PrometheusUtils.decompress(pullResponse.getData()));
            

            Writer writer = response.getWriter();

            if (this.additionalMetrics != null) {
                this.additionalMetrics.addMetrics(writer);
            }

            writer.write("# HELP remote_up Determines if the system is alive or not\n");
            writer.write("# TYPE remote_up gauge\n");
            writer.write("remote_up");
            writer.write("{");
            writer.write("remote_job");
            writer.write("=\"");
            writeEscapedLabelValue(writer, this.job);
            writer.write("\",");
            writer.write("remote_instance");
            writer.write("=\"");
            writeEscapedLabelValue(writer, this.instance);
            writer.write("\"} ");
            writer.write("1.0");
            writer.write('\n');

            response.getWriter().flush();


        } catch (Throwable t) {
            Writer writer = response.getWriter();

            writer.write("# HELP remote_up Determines if the system is alive or not\n");
            writer.write("# TYPE remote_up gauge\n");
            writer.write("remote_up");
            writer.write("{");
            writer.write("remote_job");
            writer.write("=\"");
            writeEscapedLabelValue(writer, this.job);
            writer.write("\",");
            writer.write("remote_instance");
            writer.write("=\"");
            writeEscapedLabelValue(writer, this.instance);
            writer.write("\"} ");
            writer.write("0.0");
            writer.write('\n');

            response.getWriter().flush();
            logger.warn("Can not send response",t);

            //TODO - purge the queue if this fails
        } 
	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain, byte[] arg3,
			int arg4) throws Exception {
		
	}

	@Override
	public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer arg3) throws Exception {
		
	}

	@Override
	public void initFilter(HttpFilterConfig cfg) throws Exception {
        this.cfg = cfg.getConfigManager();
        this.requestQueueName = cfg.getAttribute("requeustQueueName").getValues().get(0);
        this.responseQueueName = cfg.getAttribute("responseQueueName").getValues().get(0);
        this.job = cfg.getAttribute("job").getValues().get(0);
        this.instance = cfg.getAttribute("instance").getValues().get(0);
        this.httpCfg = cfg;
        this.maxWaitTime = Long.parseLong(cfg.getAttribute("maxWaitTime").getValues().get(0));

        if (cfg.getAttribute("additionalMetricsClassName") != null) {
            try {
                this.additionalMetrics = (AdditionalMetrics) Class.forName(cfg.getAttribute("additionalMetricsClassName").getValues().get(0)).newInstance();
                
			} catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
				throw new Exception("Could not instantiate additional metrics");
            }
            
            
        }
    }
    
    private static void writeEscapedLabelValue(Writer writer, String s) throws IOException {
        for (int i = 0; i < s.length(); i++) {
          char c = s.charAt(i);
          switch (c) {
          case '\\':
            writer.append("\\\\");
            break;
          case '\"':
            writer.append("\\\"");
            break;
          case '\n':
            writer.append("\\n");
            break;
          default:
            writer.append(c);
          }
        }
      }

}


/*******************************************************************************
 * Copyright 2024 Tremolo Security, Inc.
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
package com.tremolosecurity.activemq;

import java.util.ArrayList;
import java.util.HashMap;

import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.log4j.Logger;

import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.server.StopableThread;

public class ChooseAmq implements HttpFilter{
    String namespace;

    String primary;
    String backup;

    String primaryUrl;
    String backupHost;

    Logger logger = Logger.getLogger(ChooseAmq.class.getName());

    @Override
    public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain) throws Exception {
        


        

        HashMap<String,String> uriParams = (HashMap<String,String>) request.getAttribute("TREMOLO_URI_PARAMS");
        String hostName = (String) GlobalEntries.getGlobalEntries().get("amq.server");
        if (hostName == null) {
            hostName = primary;
        }
        uriParams.put("amq.server",hostName);

        

        chain.nextFilter(request,response,chain);
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
        logger.info("Starting config");
        this.namespace = cfg.getAttribute("namespace").getValues().get(0);
        this.primary = "amq." + namespace + ".svc";
        this.backup = "amq-backup." + namespace + ".svc";

        this.primaryUrl = "https://" + primary + ":8162/";
        this.backupHost = "https://" + backup + ":8162/";
        logger.info("Completing config");

        StopableThread amqhb = new StopableThread() {
            boolean keepRunning = true;

            @Override
            public void run() {
                BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(GlobalEntries.getGlobalEntries().getConfigManager().getHttpClientSocketRegistry());
                RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).setRedirectsEnabled(false).build();

                CloseableHttpClient http = HttpClients.custom()
                                        .setConnectionManager(bhcm)
                                        .setDefaultRequestConfig(rc)
                                        .build();


                while (keepRunning) {

                    HttpGet check = new HttpGet(primaryUrl);

                    try {
                        http.execute(check);
                        check.abort();
                        GlobalEntries.getGlobalEntries().set("amq.server",primary);
                        logger.info("Can connect to primary");
                    } catch (Exception e) {
                        GlobalEntries.getGlobalEntries().set("amq.server",backup);
                        logger.info("Can't connect to primary, switching to backup");
                    }


                    try {
                        Thread.sleep(5000);
                    } catch (InterruptedException e) {
                        // do nothing
                    }
                }    
            }

            @Override
            public void stop() {
                this.keepRunning = false;
            }
            
        };

        new Thread(amqhb).start();

        GlobalEntries.getGlobalEntries().getConfigManager().addThread(amqhb);
    }
    
}

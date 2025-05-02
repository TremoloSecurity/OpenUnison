/*
 * Copyright 2025 Tremolo Security, Inc.
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
 */

package com.tremolosecurity.jobs;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.scheduler.UnisonJob;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;
import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.quartz.JobExecutionContext;

import java.io.IOException;

public class ClearLogouts extends UnisonJob {
    static Logger logger = Logger.getLogger(ClearLogouts.class);
    @Override
    public void execute(ConfigManager configManager, JobExecutionContext context) throws ProvisioningException {
        String targetName = context.getJobDetail().getJobDataMap().getString("targetName");
        String namespace = context.getJobDetail().getJobDataMap().getString("namespace");

        OpenShiftTarget target = (OpenShiftTarget) configManager.getProvisioningEngine().getTarget(targetName).getProvider();
        if (target == null) {
            logger.error(String.format("Target %s not found", targetName));
            return;
        }

        String uri = String.format("/apis/openunison.tremolo.io/v1/namespaces/%s/endsessions",namespace);
        HttpCon http = null;
        try {
            http = target.createClient();
            String jsonResp = target.callWS(target.getAuthToken(),http,uri);
            JSONObject root = (JSONObject) new JSONParser().parse(jsonResp);
            JSONArray items = (JSONArray) root.get("items");
            if (items != null) {
                for (int i = 0; i < items.size(); i++) {
                    JSONObject endsession = (JSONObject) items.get(i);
                    JSONObject metadata = (JSONObject) endsession.get("metadata");
                    String creationTimestamp = (String) metadata.get("creationTimestamp");

                    DateTime created = new DateTime(creationTimestamp);
                    if (created.plusMinutes(1).isBeforeNow()) {
                        String name = metadata.get("name").toString();
                        String uriToDeletes = String.format("/apis/openunison.tremolo.io/v1/namespaces/%s/endsessions/%s",namespace,name);
                        String jsonDelResp = target.callWSDelete(target.getAuthToken(),http,uriToDeletes);
                        if (logger.isDebugEnabled()) {
                            logger.debug(jsonDelResp);
                        }

                    }

                }
            }
        } catch (Exception e) {
            throw new ProvisioningException("Could not clear endsessions",e);
        } finally {
            if (http != null) {
                try {
                    http.getBcm().close();
                } catch (Exception e) {}

                try {
                    http.getHttp().close();
                } catch (IOException e) {

                }

            }
        }


    }
}

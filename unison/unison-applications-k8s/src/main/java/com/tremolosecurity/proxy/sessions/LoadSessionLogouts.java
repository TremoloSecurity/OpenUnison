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

package com.tremolosecurity.proxy.sessions;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.k8s.watch.K8sWatchTarget;
import com.tremolosecurity.k8s.watch.K8sWatcher;
import com.tremolosecurity.provisioning.core.ProvisioningEngine;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.listeners.DynamicQueueListeners;
import com.tremolosecurity.proxy.SessionManager;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import org.json.simple.JSONObject;

import java.util.Map;

public class LoadSessionLogouts implements K8sWatchTarget {
    private TremoloType tremolo;
    private ConfigManager cfgMgr;
    private K8sWatcher k8sWatch;

    @Override
    public void addObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
        JSONObject spec = (JSONObject) item.get("spec");
        if (spec != null) {
            String userdn = (String) spec.get("dn");
            SessionManager sessionManager = (SessionManager) GlobalEntries.getGlobalEntries().get(ProxyConstants.TREMOLO_SESSION_MANAGER);
            sessionManager.logoutAll(userdn);
        }


    }

    @Override
    public void modifyObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
        // do nothing
    }

    @Override
    public void deleteObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
        // do nothing
    }


    public void loadEndSessions(ConfigManager cfgMgr, ProvisioningEngine provisioningEngine, String k8sTarget, String namespace) throws ProvisioningException {
        this.tremolo = cfgMgr.getCfg();
        this.cfgMgr = cfgMgr;

        String uri = "/apis/openunison.tremolo.io/v1/namespaces/" + namespace + "/endsessions";

        this.k8sWatch = new K8sWatcher(k8sTarget,namespace,"endsessions","openunison.tremolo.io",this,cfgMgr,provisioningEngine);
        this.k8sWatch.initalRun();
    }
}

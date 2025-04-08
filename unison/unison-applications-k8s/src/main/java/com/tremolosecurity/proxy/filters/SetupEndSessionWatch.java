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

package com.tremolosecurity.proxy.filters;

import com.tremolosecurity.proxy.filter.*;
import com.tremolosecurity.proxy.sessions.LoadSessionLogouts;
import com.tremolosecurity.server.GlobalEntries;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SetupEndSessionWatch implements HttpFilter {
    private static final Logger log = LoggerFactory.getLogger(SetupEndSessionWatch.class);
    String k8sTarget;
    String namespace;

    LoadSessionLogouts logouts;

    @Override
    public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain) throws Exception {


        chain.nextFilter(request, response, chain);
    }

    @Override
    public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain, StringBuffer data) throws Exception {

    }

    @Override
    public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain, byte[] data, int length) throws Exception {

    }



    @Override
    public void initFilter(HttpFilterConfig config) throws Exception {
        this.k8sTarget = config.getAttribute("k8sTarget").getValues().get(0);
        this.namespace = config.getAttribute("namespace").getValues().get(0);
        logouts = new LoadSessionLogouts();

        logouts.loadEndSessions(GlobalEntries.getGlobalEntries().getConfigManager(),GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine(),k8sTarget,namespace);
    }
}

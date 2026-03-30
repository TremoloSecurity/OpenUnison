/*
 * Copyright 2026 Tremolo Security, Inc.
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

import com.tremolosecurity.proxy.dynamicconfiguration.LoadJavaScriptsFromK8s;
import com.tremolosecurity.proxy.filter.*;
import com.tremolosecurity.proxy.secretversions.SecretVersionsWatch;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import org.apache.log4j.Logger;

public class SetupSyncJs implements HttpFilter {
    static Logger logger = Logger.getLogger(SetupSyncJs.class.getName());
    static LoadJavaScriptsFromK8s watch;
    static Integer semaphore = 1;





    @Override
    public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain) throws Exception {



        chain.nextFilter(request, response, chain);
    }

    @Override
    public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain, StringBuffer data) throws Exception {
        chain.nextFilterResponseText(request, response, chain, data);
    }

    @Override
    public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain, byte[] data, int length) throws Exception {
        chain.nextFilterResponseBinary(request, response, chain, data, length);
    }

    @Override
    public synchronized void initFilter(HttpFilterConfig config) throws Exception {


        Attribute attr;

        String target;
        String ns;



        attr = config.getAttribute("target");
        if (attr != null) {
            target = attr.getValues().get(0);
        } else {
            throw new Exception("No target");
        }

        attr = config.getAttribute("ns");
        if (attr != null) {
            ns = attr.getValues().get(0);
        } else {
            throw new Exception("No ns");
        }





        synchronized (semaphore) {
            if (watch == null) {
                this.watch = new LoadJavaScriptsFromK8s();
                this.watch.loadJavaScripts(GlobalEntries.getGlobalEntries().getConfigManager(), target, ns);

                GlobalEntries.getGlobalEntries().set("javascripts", watch);

            }
        }
    }
}

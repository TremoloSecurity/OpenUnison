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

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.myvd.dataObj.ClusterInfo;
import com.tremolosecurity.proxy.auth.AddPortalRolesToUserData;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.RequestHolder;
import com.tremolosecurity.proxy.filter.*;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import jakarta.servlet.http.HttpSession;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class ClusterGroups2Attribute implements HttpFilter {
    static Logger logger = Logger.getLogger(ClusterGroups2Attribute.class.getName());
    String clusterName;

    @Override
    public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain) throws Exception {
        HttpSession session = request.getSession();
        UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
        RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
        AuthInfo user = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
        ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);

        Map<String, ClusterInfo> clusterAz = (Map<String, ClusterInfo>) session.getAttribute(AddPortalRolesToUserData.NS_SESSION_NAME);

        logger.info("ClusterAZ : " + clusterAz);

        if (clusterAz != null) {
            List<String> clusterGroups = new ArrayList<String>();

            ClusterInfo clusterInfo = clusterAz.get("N/A");
            logger.info("clusterInfo NA : " + clusterInfo);
            if (clusterInfo != null) {

                clusterGroups.addAll(clusterInfo.getGroups());
            }

            clusterInfo = clusterAz.get(clusterName);
            logger.info("clusterInfo : " + clusterInfo);
            if (clusterInfo != null) {
                clusterGroups.addAll(clusterInfo.getGroups());
            }

            logger.info("clusterGroups : " + clusterGroups);

            String attributeName = new StringBuilder().append("groups-").append(this.clusterName).toString();
            Attribute attr = new Attribute(attributeName);
            attr.setValues(clusterGroups);
            user.getAttribs().put(attributeName,attr);
        }

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
    public void initFilter(HttpFilterConfig config) throws Exception {
        Attribute clusterNameAttr = config.getAttribute("clusterName");
        if (clusterNameAttr != null) {
            this.clusterName = "k8s-" + clusterNameAttr.getValues().get(0);
        } else {
            logger.warn("No clusterName attribute found");
            this.clusterName = "none";
        }
    }
}

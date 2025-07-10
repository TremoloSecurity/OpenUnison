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

package com.tremolosecurity.proxy.auth;

import com.google.common.collect.ComparisonChain;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.k8s.util.PortalGroupMapper;
import com.tremolosecurity.myvd.dataObj.RoleInfo;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningTarget;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.log4j.Logger;
import org.json.simple.JSONArray;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.*;

public class AddPortalRolesToUserData implements AuthMechanism{
    public static final String SESSION_ATTR_NAME = "portalGroups";
    public static final String NS_SESSION_NAME = "trmeolo.io/nsessions";

    static Logger logger = Logger.getLogger(AddPortalRolesToUserData.class.getName());



    @Override
    public void init(ServletContext ctx, HashMap<String, Attribute> init) {
        PortalGroupMapper.initialize(init.get("extSuffix").getValues().get(0),init.get("intSuffix").getValues().get(0),init.get("k8sTargetName").getValues().get(0),init.get("role2label").getValues().get(0));
    }

    @Override
    public String getFinalURL(HttpServletRequest request, HttpServletResponse response) {
        return "";
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response, AuthStep as) throws IOException, ServletException {

        HttpSession session = request.getSession();
        UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
        RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
        AuthInfo user = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
        ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);

        List<String> groups = user.getAttribs().get("groups").getValues();
        HashMap<String,Map<String,Map<String,Integer>>> clusterAz = new HashMap<String,Map<String,Map<String,Integer>>>();

        JSONArray portalGroupVals = PortalGroupMapper.getInstance().generateMappings(groups,clusterAz);


        Attribute attr = new Attribute(AddPortalRolesToUserData.SESSION_ATTR_NAME,portalGroupVals.toString());
        user.getAttribs().put(AddPortalRolesToUserData.SESSION_ATTR_NAME, attr);

        session.setAttribute(AddPortalRolesToUserData.NS_SESSION_NAME,clusterAz);

        as.setExecuted(true);
        as.setSuccess(true);
        cfg.getAuthManager().nextAuth(request, response,request.getSession(),false);
    }



    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response, AuthStep as) throws IOException, ServletException {
        this.doGet(request, response, as);
    }

    @Override
    public void doPut(HttpServletRequest request, HttpServletResponse response, AuthStep as) throws IOException, ServletException {
        this.doGet(request, response, as);
    }

    @Override
    public void doHead(HttpServletRequest request, HttpServletResponse response, AuthStep as) throws IOException, ServletException {
        this.doGet(request, response, as);
    }

    @Override
    public void doOptions(HttpServletRequest request, HttpServletResponse response, AuthStep as) throws IOException, ServletException {
        this.doGet(request, response, as);
    }

    @Override
    public void doDelete(HttpServletRequest request, HttpServletResponse response, AuthStep as) throws IOException, ServletException {
        this.doGet(request, response, as);
    }


}

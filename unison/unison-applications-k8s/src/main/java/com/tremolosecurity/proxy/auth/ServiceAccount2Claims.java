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

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.util.HashMap;

public class ServiceAccount2Claims implements AuthMechanism {
    @Override
    public void init(ServletContext ctx, HashMap<String, Attribute> init) {

    }

    @Override
    public String getFinalURL(HttpServletRequest request, HttpServletResponse response) {
        return null;
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response, AuthStep as) throws IOException, ServletException {
        HttpSession session = request.getSession();
        UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
        RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
        AuthInfo user = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
        ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
        HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);

        String cluster = authParams.get("cluster").getValues().get(0);
        String uid = user.getAttribs().get("sub").getValues().get(0);
        String removeSystem = uid.substring("system:serviceaccount:".length());
        String namespace = removeSystem.substring(0,removeSystem.indexOf(':'));
        String name = removeSystem.substring(removeSystem.indexOf(':') + 1);

        user.getAttribs().put("token_sub",new Attribute("token_sub",String.format("%s:%s:%s",cluster,namespace,name)));
        user.getAttribs().put("cluster",new Attribute("cluster",cluster));
        user.getAttribs().put("namespace",new Attribute("namespace",namespace));
        user.getAttribs().put("saname",new Attribute("saname",name));
        as.setSuccess(true);
        as.setExecuted(true);

        holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response, AuthStep as) throws IOException, ServletException {
        doGet(request, response, as);
    }

    @Override
    public void doPut(HttpServletRequest request, HttpServletResponse response, AuthStep as) throws IOException, ServletException {
        doGet(request, response, as);
    }

    @Override
    public void doHead(HttpServletRequest request, HttpServletResponse response, AuthStep as) throws IOException, ServletException {
        doGet(request, response, as);
    }

    @Override
    public void doOptions(HttpServletRequest request, HttpServletResponse response, AuthStep as) throws IOException, ServletException {
        doGet(request, response, as);
    }

    @Override
    public void doDelete(HttpServletRequest request, HttpServletResponse response, AuthStep as) throws IOException, ServletException {
        doGet(request, response, as);
    }
}

/*******************************************************************************
 * Copyright 2019 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/

package com.tremolosecurity.proxy.auth;

import java.io.IOException;
import java.util.HashMap;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.duosecurity.duoweb.DuoWeb;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;



/**
 * DuoSecLogin
 */
public class DuoSecLogin implements AuthMechanism {

    private static final String RESPONSE_PARAM = "sig_response";
    static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(DuoSecLogin.class);

    @Override
    public void doDelete(HttpServletRequest request, HttpServletResponse response, AuthStep as)
            throws IOException, ServletException {
        this.doGet(request, response, as);

        

    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response, AuthStep as)
            throws IOException, ServletException {

        HttpSession session = ((HttpServletRequest) request).getSession();
        HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
        ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
        String integrationKey = authParams.get("duoIntegrationKey").getValues().get(0);
        String secretKey = authParams.get("duoSecretKey").getValues().get(0);
        String apiHostName = authParams.get("duoApiHostName").getValues().get(0);
        String userNameAttribute = authParams.get("userNameAttribute").getValues().get(0);
        String akey = authParams.get("duoAKey").getValues().get(0).trim();
        
        AuthInfo authInfo = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
        logger.info("authInfo " + authInfo.getAuthChain());
        String userName = authInfo.getAttribs().get(userNameAttribute).getValues().get(0);

        
        String signedRequest = DuoWeb.signRequest(integrationKey, secretKey, akey, userName);
        if (signedRequest.startsWith("ERR|")) {
            throw new ServletException(signedRequest);
        }

        request.setAttribute("duo.apihost", apiHostName);
        request.setAttribute("duo.sigreq", signedRequest);
        
        request.getRequestDispatcher("/auth/forms/duo/duoauth.jsp").forward(request, response);

    }

    @Override
    public void doHead(HttpServletRequest request, HttpServletResponse response, AuthStep as)
            throws IOException, ServletException {
                this.doGet(request, response, as);
    }

    @Override
    public void doOptions(HttpServletRequest request, HttpServletResponse response, AuthStep as)
            throws IOException, ServletException {
                this.doGet(request, response, as);

    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response, AuthStep as)
            throws IOException, ServletException {

        logger.info("In post");
        String duoResponse = request.getParameter(RESPONSE_PARAM);

        if (duoResponse == null) {
            logger.info("No response, initializing");
            this.doGet(request, response, as);
        }  else {
            logger.info("Processing the response");
            HttpSession session = ((HttpServletRequest) request).getSession();
            HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
            ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
            String integrationKey = authParams.get("duoIntegrationKey").getValues().get(0);
            String secretKey = authParams.get("duoSecretKey").getValues().get(0);
            String apiHostName = authParams.get("duoApiHostName").getValues().get(0);
            String userNameAttribute = authParams.get("userNameAttribute").getValues().get(0);
            String akey = authParams.get("duoAKey").getValues().get(0).trim();
            RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();

            AuthInfo authInfo = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
            String userName = authInfo.getAttribs().get(userNameAttribute).getValues().get(0);

            try {
                String userFromDuo = DuoWeb.verifyResponse(integrationKey, secretKey, akey, duoResponse);
                as.setSuccess(userFromDuo.equalsIgnoreCase(userName));
                
                String redirectToURL = request.getParameter("target");
                if (redirectToURL != null && ! redirectToURL.isEmpty()) {
                    reqHolder.setURL(redirectToURL);
                }
                
                cfg.getAuthManager().nextAuth(request, response,session,false);
                
            } catch (Exception e) {
                throw new ServletException("Could not validate duo id",e);
            }
        }


    }

    @Override
    public void doPut(HttpServletRequest request, HttpServletResponse response, AuthStep as)
            throws IOException, ServletException {
                this.doGet(request, response, as);

    }

    @Override
    public String getFinalURL(HttpServletRequest request, HttpServletResponse response) {
        return null;
    }

    @Override
    public void init(ServletContext ctx, HashMap<String, Attribute> config) {

    }

    
}
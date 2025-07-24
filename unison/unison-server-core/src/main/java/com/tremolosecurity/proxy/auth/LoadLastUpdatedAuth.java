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

import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.providers.BasicDB;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;

public class LoadLastUpdatedAuth implements AuthMechanism{
    @Override
    public void init(ServletContext ctx, HashMap<String, Attribute> init) {

    }

    @Override
    public String getFinalURL(HttpServletRequest request, HttpServletResponse response) {
        return "";
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response, AuthStep as) throws IOException, ServletException {
        HttpSession session = ((HttpServletRequest) request).getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
        UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);

        RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();

        HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);


        String lastAccessedForUser = authParams.get("lastUpdatedForUser").getValues().get(0);
        String sql = authParams.get("sql").getValues().get(0);
        String uidAttributeName = authParams.get("uidAttributeName").getValues().get(0);
        String target = authParams.get("target").getValues().get(0);

        AuthInfo authInfo = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();

        Attribute uid = authInfo.getAttribs().get(uidAttributeName);
        if (uid == null) {
            throw new ServletException(String.format("Unable to find attribute %s on user %s",uidAttributeName,authInfo.getUserDN()));
        }

        Connection con = null;

        try {
            BasicDB db = (BasicDB) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(target).getProvider();
            con = db.getDS().getConnection();
            PreparedStatement ps = con.prepareStatement(sql);
            ps.setString(1, uid.getValues().get(0));
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                String value = rs.getString(1);
                if (value != null) {
                    authInfo.getAttribs().put(lastAccessedForUser,new Attribute(lastAccessedForUser,value));
                }
            }
            rs.close();
            ps.close();
        } catch (SQLException | ProvisioningException e) {
            throw new ServletException(String.format("Could not load last accessed for user %s",authInfo.getUserDN()), e);
        } finally {
            if (con != null) {
                try {
                    con.close();
                } catch (SQLException e) {

                }
            }
        }

        as.setSuccess(true);
        holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
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

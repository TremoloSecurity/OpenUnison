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

import com.novell.ldap.LDAPException;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.auth.GenerateOIDCTokens;
import com.tremolosecurity.proxy.auth.util.OpenIDConnectToken;
import com.tremolosecurity.proxy.filter.*;
import com.tremolosecurity.proxy.util.ProxyTools;
import com.tremolosecurity.saml.Attribute;
import jakarta.servlet.ServletException;
import org.apache.log4j.Logger;
import org.checkerframework.checker.units.qual.A;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.lang.JoseException;

import java.net.MalformedURLException;

public class InjectOidcToken implements HttpFilter {
    String sessionAttributeName;

    static Logger logger = Logger.getLogger(InjectOidcToken.class.getName());

    @Override
    public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain) throws Exception {
        Attribute azHeader = request.getHeader("Authorization");
        if (azHeader != null) {
            azHeader.getValues().clear();
        } else {
            azHeader = new Attribute("Authorization");
            request.addHeader(azHeader);
        }

        StringBuffer b = new StringBuffer();
        b.append("Bearer ");

        OpenIDConnectToken token = (OpenIDConnectToken) request.getSession().getAttribute(this.sessionAttributeName);
        if (token == null) {
            b.append("NONE");
            logger.warn("No token found in session attribute " + this.sessionAttributeName);

        } else {
            synchronized(token) {
                if (token.isExpired()) {
                    try {
                        request.setAttribute(ProxyTools.OVERRIDE_HOST, System.getProperty("OU_HOST"));
                        token.refreshProxyToken(request.getServletRequest());
                    } catch (MalformedURLException | MalformedClaimException | JoseException | LDAPException
                             | ProvisioningException e) {
                        throw new ServletException("Could not generate id_token",e);
                    }
                }

                b.append(token.getEncodedIdJSON());
                azHeader.getValues().add(b.toString());


            }
        }

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
        this.sessionAttributeName = config.getAttribute("sessionAttributeName").getValues().get(0);
    }
}

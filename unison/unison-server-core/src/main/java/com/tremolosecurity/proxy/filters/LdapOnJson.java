/*
 * Copyright 2017 Tremolo Security, Inc.
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

import com.google.gson.Gson;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.ldapJson.LdapJsonBindRequest;
import com.tremolosecurity.ldapJson.LdapJsonEntry;
import com.tremolosecurity.ldapJson.LdapJsonError;
import com.tremolosecurity.proxy.ProxySys;
import com.tremolosecurity.proxy.filter.*;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URL;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class LdapOnJson implements HttpFilter {
    static Gson gson = new Gson();
    @Override
    public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain) throws Exception {
        response.setContentType("application/json");
        try {
            URL reqURL;
            reqURL = new URL(request.getRequestURL().toString());
            String[] parts = reqURL.getPath().split("[/]");


            if (request.getServletRequest().getMethod().equalsIgnoreCase("get")) {
                ldapSearh(request, response, parts);
            } else if (request.getServletRequest().getMethod().equalsIgnoreCase("post")) {
                String dn = URLDecoder.decode(parts[parts.length - 1], "UTF-8");
                LdapJsonBindRequest bindReq = gson.fromJson(new String( (byte[]) request.getAttribute(ProxySys.MSG_BODY)),LdapJsonBindRequest.class);
                GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().bind(dn,bindReq.getPassword());
                //no errors so we're good
                response.setContentType("application/json");

                response.getWriter().println(gson.toJson(new LdapJsonError()));
            } else {
                throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),LDAPException.OPERATIONS_ERROR,"Invalid operation : '" + request.getMethod() + "'");
            }
        } catch(LDAPException e){
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            e.printStackTrace(new PrintStream(baos));
            LdapJsonError err = new LdapJsonError();
            err.setResponseCode(e.getResultCode());
            err.setErrorMessage(new String(baos.toByteArray()));
            response.setStatus(500);
            response.getWriter().println(gson.toJson(err));
        } catch(Exception e){
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            e.printStackTrace(new PrintStream(baos));
            LdapJsonError err = new LdapJsonError();
            err.setResponseCode(LDAPException.OPERATIONS_ERROR);
            err.setErrorMessage(new String(baos.toByteArray()));
            response.setStatus(500);
            response.getWriter().println(gson.toJson(err));
        }





    }

    private void ldapSearh(HttpFilterRequest request, HttpFilterResponse response, String[] parts) throws Exception {
        Attribute attributes = request.getParameter("attributes");
        String filter = request.getParameter("filter").getValues().get(0);
        String scope = URLDecoder.decode(parts[parts.length - 1], "UTF-8");
        ;
        String dn = URLDecoder.decode(parts[parts.length - 2], "UTF-8");
        ;
        int searchScope = 0;

        switch (scope) {
            case "sub":
                searchScope = 2;
                break;
            case "one":
                searchScope = 1;
                break;
            case "base":
                searchScope = 0;
                break;
            default:
                throw new Exception("Invalid search scope : '" + scope + "'");
        }

        ArrayList<String> attrsForSearch = new ArrayList<String>();
        if (attributes != null) {
            attrsForSearch.addAll(attributes.getValues());
        }

        LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(dn, searchScope, filter, attrsForSearch);

        ArrayList<LdapJsonEntry> entries = new ArrayList<LdapJsonEntry>();
        while (res.hasMore()) {
            LDAPEntry entry = res.next();
            LdapJsonEntry jsonEntry = new LdapJsonEntry();
            jsonEntry.setDn(entry.getDN());

            for (Object o : entry.getAttributeSet()) {
                LDAPAttribute attr = (LDAPAttribute) o;
                jsonEntry.getAttrs().put(attr.getName(), Arrays.asList(attr.getStringValueArray()));
            }

            entries.add(jsonEntry);
        }

        response.getWriter().println(gson.toJson(entries));
    }

    @Override
    public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain, StringBuffer data) throws Exception {

    }

    @Override
    public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain, byte[] data, int length) throws Exception {

    }

    @Override
    public void initFilter(HttpFilterConfig config) throws Exception {

    }
}

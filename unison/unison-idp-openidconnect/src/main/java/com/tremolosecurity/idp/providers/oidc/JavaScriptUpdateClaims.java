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

package com.tremolosecurity.idp.providers.oidc;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.jose4j.jwt.JwtClaims;

import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.idp.providers.OpenIDConnectIdP;
import com.tremolosecurity.idp.providers.OpenIDConnectTrust;
import com.tremolosecurity.idp.providers.oidc.sdk.UpdateClaims;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.proxy.mappings.JavaScriptMappings;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Value;

public class JavaScriptUpdateClaims implements UpdateClaims {
    static Logger logger = Logger.getLogger(JavaScriptUpdateClaims.class.getName());
    public void updateClaimsBeforeSigning(String dn, ConfigManager cfg, URL url, OpenIDConnectTrust trust, String nonce, HashMap<String, String> extraAttribs,LDAPEntry entry,User user,JwtClaims claims) throws LDAPException, ProvisioningException {
        try {
            UrlHolder holder = cfg.findURL(url.toString());
            if (holder == null) {
                logger.warn("Could not find application for " + url.toString());
            } else {
                String appname = holder.getApp().getName();
                if (logger.isDebugEnabled()) {
                    logger.info("Found app " + appname);
                }
                ApplicationType idp = holder.getApp();

                Map<String,Attribute> idpConfig = new HashMap<String,Attribute>();

                List<ParamType> params =  idp.getUrls().getUrl().get(0).getIdp().getParams();
                params.forEach(param -> {
                    Attribute attr = idpConfig.get(param.getName());
                    if (attr == null) {
                        attr = new Attribute(param.getName());
                        idpConfig.put(param.getName(),attr);
                    }
                    attr.getValues().add(param.getValue());
                });

                Context context = Context.newBuilder("js").allowAllAccess(true).build();

                try {
                    ArrayList<String> jsToLoad = new ArrayList<String>();
                    if (idpConfig.get("includeJs") != null) {
                        jsToLoad.addAll(idpConfig.get("includeJs").getValues());
                    }

                    Attribute attr = idpConfig.get("javaScript");
                    if (attr == null) {
                        logger.error("javaScript not set");
                        return;
                    }

                    String javaScript = attr.getValues().get(0);

                    JavaScriptMappings javascripts = (JavaScriptMappings) GlobalEntries.getGlobalEntries().get("javascripts");
                    if (javascripts != null) {
                        jsToLoad.forEach(jsToInclude -> {
                            String javascript = javascripts.getMapping(jsToInclude);
                            if (javascript != null) {
                                context.eval("js", javascript);
                            } else {
                                logger.warn("JavScript " + jsToInclude + " not found");
                            }
                        });
                    }

                    Value val = context.eval("js",javaScript);
                    Value doUpdateClaimsBeforeSigning = context.getBindings("js").getMember("updateClaimsBeforeSigning");
                    doUpdateClaimsBeforeSigning.execute(dn,cfg,url,trust,nonce,extraAttribs,entry,user,claims,idpConfig);
                } finally {
                    context.close();
                }

            }
        } catch (Exception e) {
            throw new ProvisioningException("Error updating claims", e);
        }

    }
}


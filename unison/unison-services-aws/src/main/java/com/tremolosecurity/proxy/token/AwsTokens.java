/*******************************************************************************
 * Copyright (c) 2023 Tremolo Security, Inc.
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
 *******************************************************************************/
package com.tremolosecurity.proxy.token;

import java.util.HashMap;
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.apache.log4j.Logger;


import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.saml.Saml2Assertion;
import com.tremolosecurity.scalejs.token.cfg.ScaleTokenConfig;
import com.tremolosecurity.scalejs.token.sdk.TokenLoader;
import com.tremolosecurity.server.GlobalEntries;

import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleWithSamlRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleWithSamlResponse;
import software.amazon.awssdk.services.sts.model.Credentials;
import java.time.Instant;


/**
 * AwsTokens
 */
public class AwsTokens implements TokenLoader {
	
	static Logger logger = Logger.getLogger(TokenLoader.class.getName());

    String sigKeyName;
    String encKeyName;
    String uidAttribute;

    String issuer;
    String recipient;
    String audience;

    String nameIDFormat;
    String authnContextRef;

    int minAlive;

    String idpName;
    String roleName;

    @Override
    public void init(HttpFilterConfig filterConfig, ScaleTokenConfig tokenConfig) throws Exception {
        this.sigKeyName = getCfgAttr("sigKeyName", filterConfig);
        this.encKeyName = getCfgAttr("encKeyName", filterConfig);
        this.uidAttribute = getCfgAttr("uidAttribute", filterConfig);
        this.issuer = getCfgAttr("issuer", filterConfig);
        this.recipient = getCfgAttr("recipient", filterConfig);
        this.audience = getCfgAttr("audience", filterConfig);
        this.nameIDFormat = getCfgAttr("nameIDFormat", filterConfig);
        if (nameIDFormat == null) {
            this.nameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
        }

        this.authnContextRef = getCfgAttr("authnContextRef", filterConfig);
        if (this.authnContextRef == null) {
            this.authnContextRef = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
        }

        this.minAlive = Integer.parseInt(getCfgAttr("minAlive", filterConfig));
        
        this.idpName = getCfgAttr("idpName", filterConfig);
        this.roleName = getCfgAttr("roleName", filterConfig);

    }

    private String getCfgAttr(String name,HttpFilterConfig cfg) {
        Attribute attr = cfg.getAttribute(name);
        if (attr != null) {
            return attr.getValues().get(0);
        } else {
            return null;
        }
    }

    @Override
    public Object loadToken(AuthInfo user, HttpSession session,HttpServletRequest arg2) throws Exception {
        
        Attribute uid = user.getAttribs().get(this.uidAttribute);

        boolean encAssertion = this.encKeyName != null;
        boolean signAssertion = this.sigKeyName != null;

        Saml2Assertion assertion = new Saml2Assertion(
                                        uid.getValues().get(0),
                                        signAssertion ? GlobalEntries.getGlobalEntries().getConfigManager().getPrivateKey(this.sigKeyName) : null,
                                        signAssertion ? GlobalEntries.getGlobalEntries().getConfigManager().getCertificate(this.sigKeyName) : null,
                                        encAssertion ? GlobalEntries.getGlobalEntries().getConfigManager().getCertificate(this.encKeyName) : null,
                                        this.issuer,
                                        this.recipient,
                                        this.audience,
                                        signAssertion,
                                        false,
                                        false,
                                        this.nameIDFormat,
                                        this.authnContextRef,
                                        5
                                    );
        
        //add attributes
        String sessionName = UUID.randomUUID().toString();
        logger.info(String.format("Session %s for user %s", sessionName,uid));
        assertion.getAttribs().add(new Attribute("https://aws.amazon.com/SAML/Attributes/RoleSessionName",sessionName));
        assertion.getAttribs().add(new Attribute("https://aws.amazon.com/SAML/Attributes/Role",new StringBuilder().append(this.roleName).append(",").append(this.idpName).toString()));

        String samlResp = assertion.generateSaml2Response();
        String base64SamlResp = java.util.Base64.getEncoder().encodeToString(samlResp.getBytes("UTF-8"));
        
        StsClient stsClient = StsClient.builder().build();
        
        // Create AssumeRoleWithSAML request
        AssumeRoleWithSamlRequest assumeRoleWithSamlRequest = AssumeRoleWithSamlRequest.builder()
                .roleArn(this.roleName)
                .principalArn(this.idpName)
                .samlAssertion(base64SamlResp)
                .durationSeconds(3600) // Set session duration (in seconds)
                .build();
        
        AssumeRoleWithSamlResponse response = stsClient.assumeRoleWithSAML(assumeRoleWithSamlRequest);
        Credentials credentials = response.credentials();
       
        
        HashMap<String,String> resp = new HashMap<String,String>();

        resp.put("AWS Key", credentials.accessKeyId());
        resp.put("AWS Secret", credentials.secretAccessKey());
        resp.put("AWS Session", credentials.sessionToken());
        resp.put("Set Environment Variables",
                                                new StringBuilder().append("export AWS_ACCESS_KEY_ID='").append(credentials.accessKeyId()).append("';")
                                                                   .append("export AWS_SECRET_ACCESS_KEY='").append(credentials.secretAccessKey()).append("';")
                                                                   .append("export AWS_SESSION_TOKEN='").append(credentials.sessionToken()).append("'").toString()
        );

        return resp;
    }

    
}
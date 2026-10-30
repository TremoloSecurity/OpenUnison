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

package com.tremolosecurity.idp.providers.oidc.clientcredentialgrants;

import com.tremolosecurity.idp.providers.oidc.sdk.ClientCredentialGrant;
import com.tremolosecurity.proxy.ProxyRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;

public class JwtBearerClientCredential implements ClientCredentialGrant {
    static Logger logger = Logger.getLogger(JwtBearerClientCredential.class.getName());

    static JwtConsumer consumer = new JwtConsumerBuilder()
            .setSkipSignatureVerification()
            .setSkipAllValidators()
            .build();

    @Override
    public String extractClientId(HttpServletRequest request, HttpServletResponse response) {
        // get the assertion
        String clientAssertion = request.getParameter("client_assertion");
        if (clientAssertion == null) {
            return null;
        }

        // need to determine the client_id based on the sub
        // while not validated, this is no different then setting the client id by the client_id parameter


        JwtClaims claims = null;
        try {
            claims = consumer.processToClaims(clientAssertion);
        } catch (InvalidJwtException  e) {
            logger.warn("Could not parse JWT assertion", e);
            return null;
        }

        String clientid = null;

        try {
            clientid = claims.getSubject();
        } catch (MalformedClaimException e) {
            logger.warn("Could not load sub", e);
            return null;
        }

        request.setAttribute("tremolo.io/oauth2/token",clientAssertion);

        return clientid;
    }
}

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

package com.tremolosecurity.scalejs.token.sts;

import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.scalejs.token.cfg.ScaleTokenConfig;
import com.tremolosecurity.scalejs.token.sdk.TokenLoader;
import com.tremolosecurity.server.GlobalEntries;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;

public class StsToken implements TokenLoader {
    String keyName;
    String issuer;
    String audience;
    int minutes;

    List<String> additionalClaims;

    @Override
    public void init(HttpFilterConfig config, ScaleTokenConfig scaleTokenConfig) throws Exception {

        this.keyName = config.getAttribute("keyName").getValues().get(0);
        this.issuer = config.getAttribute("issuer").getValues().get(0);
        this.audience = config.getAttribute("audience").getValues().get(0);
        this.minutes = Integer.parseInt(config.getAttribute("minutesTTL").getValues().get(0));

        if (config.getAttribute("additionalClaims") != null) {
            this.additionalClaims = config.getAttribute("additionalClaims").getValues();
        }





    }

    @Override
    public Object loadToken(AuthInfo user, HttpSession session, HttpServletRequest request) throws Exception {
        HashMap<String,String> tokenResponse = new HashMap<>();

        // generate claims
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(this.issuer);  // who creates the token and signs it
        claims.setAudience(this.audience); // to whom the token is intended to be sent
        claims.setExpirationTimeMinutesInTheFuture(this.minutes); // time when the token will expire (15 minutes from now)
        claims.setNotBeforeMinutesInThePast(1);
        claims.setGeneratedJwtId(); // a unique identifier for the token
        claims.setIssuedAtToNow();  // when the
        claims.setSubject(user.getAttribs().get("token_sub").getValues().get(0));

        if (this.additionalClaims != null) {
            for (String claim : this.additionalClaims) {
                Attribute attr = user.getAttribs().get(claim);
                if (attr != null) {
                    if (attr.getValues().size() == 1) {
                        claims.setStringClaim(claim, attr.getValues().get(0));
                    } else {
                        claims.setStringListClaim(claim, attr.getValues());
                    }
                }
            }
        }

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(GlobalEntries.getGlobalEntries().getConfigManager().getPrivateKey(keyName));
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

        String jwt = jws.getCompactSerialization();

        tokenResponse.put("expires",Instant.ofEpochMilli(claims.getExpirationTime().getValueInMillis()).atZone(ZoneOffset.UTC).format(DateTimeFormatter.ISO_INSTANT));
        tokenResponse.put("jwt", jwt);

        return tokenResponse;
    }
}

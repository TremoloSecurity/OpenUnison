/*
 * Copyright 2017, 2020 Tremolo Security, Inc.
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

package com.tremolosecurity.idp.providers.oidc.scalejs;

import com.tremolosecurity.idp.providers.OpenIDConnectIdP;
import com.tremolosecurity.idp.providers.oidc.model.OidcSessionState;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.GenerateOIDCTokens;
import com.tremolosecurity.proxy.auth.util.OpenIDConnectToken;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.scalejs.token.cfg.ScaleTokenConfig;
import com.tremolosecurity.scalejs.token.sdk.TokenLoader;
import com.tremolosecurity.server.GlobalEntries;

import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.Logger;
import org.stringtemplate.v4.ST;

import jakarta.servlet.http.HttpSession;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import jakarta.servlet.http.HttpServletRequest;

public class IdTokenLoader implements TokenLoader {
    static Logger logger = org.apache.logging.log4j.LogManager.getLogger(IdTokenLoader.class);

    String uidAttributeName;
    

    @Override
    public void init(HttpFilterConfig config, ScaleTokenConfig scaleTokenConfig) throws Exception {
        this.uidAttributeName = config.getAttribute("uidAttributeName").getValues().get(0);
        

        
    }


    public String renderTemplate(String val,Map<String,Object> request) {


        val = val.replaceAll("[$][{]", "___");

        ST st = new ST(val,'$','$');
        for (String key : request.keySet()) {
            st.add(key.replaceAll("[.]", "_"), request.get(key));
        }

        String tmp = st.render();


        tmp = tmp.replaceAll("___", "\\${");

        return tmp;
    }


    @Override
    public Object loadToken(AuthInfo user, HttpSession session,HttpServletRequest request) throws Exception {
        OpenIDConnectToken token = (OpenIDConnectToken) session.getAttribute(GenerateOIDCTokens.UNISON_SESSION_OIDC_ID_TOKEN);
        
        token.replaceState();
        
        
        
        if (token == null) {
            logger.warn("No id token found");
            return new HashMap<String,String>();
        } else {

        	HashMap<String,String> tokens = new HashMap<String,String>();
        	
        	
            HashMap<String,Object> templateObjects = new HashMap<String,Object>();
            templateObjects.put("user",user);
            templateObjects.put("token",token);
            templateObjects.put("user_id",user.getAttribs().get(this.uidAttributeName).getValues().get(0));
            
            
                        
            tokens.put("id_token", token.getEncodedIdJSON());
            
            try {
            	tokens.put("refresh_token", token.getRefreshToken());
            } catch (Exception e) {
            	logger.warn("Could not get refresh token",e);
            }
            

            return tokens;

        }

        
    }

}

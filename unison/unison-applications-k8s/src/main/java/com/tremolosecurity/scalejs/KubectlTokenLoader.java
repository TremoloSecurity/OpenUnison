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

package com.tremolosecurity.scalejs;

import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.GenerateOIDCTokens;
import com.tremolosecurity.proxy.auth.util.OpenIDConnectToken;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.scalejs.token.cfg.ScaleTokenConfig;
import com.tremolosecurity.scalejs.token.sdk.TokenLoader;
import org.apache.logging.log4j.Logger;
import org.stringtemplate.v4.ST;

import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;

public class KubectlTokenLoader implements TokenLoader {
    static Logger logger = org.apache.logging.log4j.LogManager.getLogger(KubectlTokenLoader.class);

    String uidAttributeName;
    String caCertificateURL;
    String k8sMasterCaCertificateURL;
    String kubectlTemplate;
    private String kubectlUsage;

    @Override
    public void init(HttpFilterConfig config, ScaleTokenConfig scaleTokenConfig) throws Exception {
        this.uidAttributeName = config.getAttribute("uidAttributeName").getValues().get(0);
        this.caCertificateURL = config.getAttribute("caCertificateURL").getValues().get(0);
        this.k8sMasterCaCertificateURL = config.getAttribute("k8sMasterCaCertificateURL").getValues().get(0);
        this.kubectlTemplate = config.getAttribute("kubectlTemplate").getValues().get(0);
        this.kubectlUsage = config.getAttribute("kubectlUsage").getValues().get(0);
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
    public Object loadToken(AuthInfo user, HttpSession session) throws Exception {
        OpenIDConnectToken token = (OpenIDConnectToken) session.getAttribute(GenerateOIDCTokens.UNISON_SESSION_OIDC_ID_TOKEN);

        if (token == null) {
            logger.warn("No id token found");
            return new HashMap<String,String>();
        } else {

            synchronized (token) {

                token.loadFromDB(session);

                if (token.isExpired()) {
                    token.generateToken(session);
                }
            }

            /*String kubectlTemplate = "kubectl config set-credentials " + user.getAttribs().get(this.uidAttributeName).getValues().get(0) + "  \\\n" +
                    "        --auth-provider=oidc  \\\n" +
                    "        --auth-provider-arg=idp-issuer-url=" + token.getClaims().getIssuer() + "  \\\n" +
                    "        --auth-provider-arg=client-id=" + token.getTrustName() + "  \\\n" +
                    "        --auth-provider-arg=client-secret=" + token.getDecryptedClientSecret() + "  \\\n" +
                    "        --auth-provider-arg=refresh-token=" + token.getRefreshToken() + " \\\n" +
                    "        --auth-provider-arg=idp-certificate-authority=" + caCertificatePath + " \\\n" +
                    "        --auth-provider-arg=id-token=" + token.getEncodedIdJSON();*/

            HashMap<String,Object> templateObjects = new HashMap<String,Object>();
            templateObjects.put("user",user);
            templateObjects.put("token",token);
            templateObjects.put("user_id",user.getAttribs().get(this.uidAttributeName).getValues().get(0));



            HashMap<String,String> tokens = new HashMap<String,String>();
            tokens.put("kubectl Command",this.renderTemplate(this.kubectlTemplate,templateObjects));
            tokens.put("Usage",this.kubectlUsage);
            if (! this.k8sMasterCaCertificateURL.isEmpty()) {
                tokens.put("API Server Certificate Authority URL",this.k8sMasterCaCertificateURL);
            }

            if (! this.caCertificateURL.isEmpty()) {
                tokens.put("OpenUnison Certificate Authority URL",this.caCertificateURL);
            }

            return tokens;

        }
    }
}

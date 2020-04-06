/*
 * Copyright 2017, 2018 Tremolo Security, Inc.
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

import javax.servlet.http.HttpSession;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class KubectlTokenLoader implements TokenLoader {
    static Logger logger = org.apache.logging.log4j.LogManager.getLogger(KubectlTokenLoader.class);

    String uidAttributeName;
    String kubectlTemplate;
    String k8sCaCertName;
    String unisonCaCertName;
    private String kubectlUsage;
    private String kubectlWinUsage;

    @Override
    public void init(HttpFilterConfig config, ScaleTokenConfig scaleTokenConfig) throws Exception {
        this.uidAttributeName = config.getAttribute("uidAttributeName").getValues().get(0);
        
        
        this.kubectlTemplate = config.getAttribute("kubectlTemplate").getValues().get(0);
        this.kubectlUsage = config.getAttribute("kubectlUsage").getValues().get(0);
        this.k8sCaCertName = config.getAttribute("k8sCaCertName").getValues().get(0);
        this.unisonCaCertName = config.getAttribute("unisonCaCertName").getValues().get(0);
        
        if (config.getAttribute("kubectlWinUsage") != null) {
        	this.kubectlWinUsage = config.getAttribute("kubectlWinUsage").getValues().get(0);
        } else {
        	this.kubectlWinUsage = null;
        }

        
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
        
        token.replaceState();
        
        
        
        if (token == null) {
            logger.warn("No id token found");
            return new HashMap<String,String>();
        } else {

        	HashMap<String,String> tokens = new HashMap<String,String>();
        	
        	String k8sCert = this.cert2pem(this.k8sCaCertName);
            if (k8sCert != null) {
                tokens.put("Kubernetes API Server CA Certificate", k8sCert);
            }

            String ouCert = this.cert2pem(this.unisonCaCertName);
            if (ouCert != null) {
                tokens.put("OpenUnison Server CA Certificate",ouCert);
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
            if (k8sCert != null) {
            	templateObjects.put("k8s_b64_cert", new String(Base64.encodeBase64(k8sCert.getBytes("UTF-8"))));
            	templateObjects.put("k8s_newline_cert",k8sCert.replace("\n", "\\n"));
            	templateObjects.put("k8s_newline_cert_win",k8sCert.replace("\n", "`n"));
            }
            
            if (ouCert != null) {
            	templateObjects.put("ou_b64_cert",new String(Base64.encodeBase64(ouCert.getBytes("UTF-8"))));
            }
            

            
            
            

            
            tokens.put("kubectl Command",this.renderTemplate(this.kubectlTemplate,templateObjects));
            
            if (this.kubectlWinUsage != null) {
            	tokens.put("kubectl Windows Command",this.renderTemplate(this.kubectlWinUsage,templateObjects));
            }
            
            tokens.put("Usage",this.kubectlUsage);
            
            tokens.put("id_token", token.getEncodedIdJSON());
            tokens.put("refresh_token", token.getRefreshToken());
            

            return tokens;

        }

        
    }

    private String cert2pem(String certificateName) {
        X509Certificate cert = GlobalEntries.getGlobalEntries().getConfigManager().getCertificate(certificateName);
        if (cert == null) {
            return null;
        } else {
            Base64 encoder = new Base64(64);
            StringBuffer b = new StringBuffer();
            b.append("-----BEGIN CERTIFICATE-----\n");
            try {
				b.append(encoder.encodeAsString(cert.getEncoded()));
			} catch (CertificateEncodingException e) {
                logger.warn("Could not decode certificate",e);
                return null;
			}
            b.append("-----END CERTIFICATE-----");
            return b.toString();
        }
        
    }
}

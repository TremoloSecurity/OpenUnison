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

package com.tremolosecurity.proxy.secretversions;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.k8s.watch.K8sWatchTarget;
import com.tremolosecurity.k8s.watch.K8sWatcher;
import com.tremolosecurity.provisioning.core.ProvisioningEngine;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;
import org.apache.log4j.Logger;
import org.cryptacular.util.CertUtil;
import org.cryptacular.util.KeyPairUtil;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class SecretVersionsWatch implements K8sWatchTarget {
    static Logger logger = Logger.getLogger(SecretVersionsWatch.class.getName());
    String target;

    private TremoloType tremolo;
    private ConfigManager cfgMgr;
    private K8sWatcher k8sWatch;

    public SecretVersionsWatch(ConfigManager cfgMgr, ProvisioningEngine provisioningEngine, String k8sTarget, String namespace) throws ProvisioningException {
        this.target = k8sTarget;
        this.cfgMgr = cfgMgr;

        String uri = "/apis/openunison.tremolo.io/v1/namespaces/" + namespace + "/secretversions";

        this.k8sWatch = new K8sWatcher(k8sTarget,namespace,"secretversions","openunison.tremolo.io",this,cfgMgr,provisioningEngine);
        this.k8sWatch.initalRun();
    }

    @Override
    public void addObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
        updateSecret(cfg, item);
    }

    @Override
    public void modifyObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
        updateSecret(cfg, item);
    }

    @Override
    public void deleteObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
        // do nothing
    }

    private void updateSecret(TremoloType cfg, JSONObject item) throws ProvisioningException {
        JSONObject spec = (JSONObject) item.get("spec");
        JSONObject metadata = (JSONObject) item.get("metadata");
        String name = (String) metadata.get("name");
        String namespace = (String) metadata.get("namespace");
        String keyName = (String) spec.get("key_name");
        int version = Math.toIntExact((long) spec.get("version"));

        X509Certificate certFromSecret = null;
        PrivateKey keyFromSecret = null;

        String secretUri = String.format("/api/v1/namespaces/%s/secrets/%s",namespace,name);
        OpenShiftTarget k8s = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(target).getProvider();
        HttpCon http = null;
        try {
            http = k8s.createClient();
            String secretJson = k8s.callWS(k8s.getAuthToken(),http,secretUri);
            JSONObject secret = (JSONObject) new JSONParser().parse(secretJson);
            String kind = (String) secret.get("kind");
            if (kind.equalsIgnoreCase("Secret")) {
                JSONObject data = (JSONObject) secret.get("data");
                String certB64 = (String) data.get("tls.crt");
                String pemCert = new String(Base64.getDecoder().decode(certB64));
                certFromSecret = CertUtil.decodeCertificate(pemCert.getBytes(StandardCharsets.UTF_8));

                String key64 = (String) data.get("tls.key");
                String pemKey = new String(Base64.getDecoder().decode(key64));
                keyFromSecret = KeyPairUtil.decodePrivateKey(pemKey.getBytes(StandardCharsets.UTF_8));

                logger.info(String.format("Replacing %s",name));
                try {
                    GlobalEntries.getGlobalEntries().getConfigManager().addPrivateKey(keyName,certFromSecret,keyFromSecret);
                } catch (KeyStoreException e) {
                    logger.warn("Could not add private key " + name,e);
                }

                GlobalEntries.getGlobalEntries().getConfigManager().setKeyVersion(keyName,version);
            } else {
                throw new ProvisioningException(String.format("Secret %s does not exist",secretUri));
            }
        } catch (Exception e) {
            throw new ProvisioningException("Could not load secret " + secretUri,e);
        } finally {
            if (http != null) {
                try {
                    http.getHttp().close();
                } catch (IOException e) {

                }

                http.getBcm().close();

            }
        }



    }
}

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

package com.tremolosecurity.proxy.tls;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.server.StopableThread;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;
import org.apache.log4j.Logger;
import org.cryptacular.util.CertUtil;
import org.cryptacular.util.KeyPairUtil;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

public class CheckForKeys implements StopableThread {
    static Logger logger = Logger.getLogger(CheckForKeys.class.getName());

    String target;
    String ns;
    String version;
    String name;

    int milliSecondsBetweenRuns;

    boolean keepRunning = true;

    public CheckForKeys(String target, String ns, String version, String name, int secondsBetweenRuns) {
        this.target = target;
        this.ns = ns;
        this.version = version;
        this.name = name;
        this.keepRunning = true;
        this.milliSecondsBetweenRuns = (secondsBetweenRuns * 1000);

    }

    public void loadOpenUnison() {
        String uri = String.format("/apis/openunison.tremolo.io/%s/namespaces/%s/openunisons/%s",version,ns,name);
        HttpCon http = null;
        try {
            OpenShiftTarget k8s = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.target).getProvider();
            http = k8s.createClient();
            String json = k8s.callWS(k8s.getAuthToken(),http,uri);
            JSONObject root = (JSONObject) new JSONParser().parse(json);
            JSONObject spec = (JSONObject) root.get("spec");
            if (spec == null) {
                logger.warn("No spec");
                return;
            }

            JSONObject ks = (JSONObject) spec.get("key_store");
            if (ks == null) {
                logger.warn("No spec.key_store");
                return;
            }

            JSONObject keyPairs = (JSONObject) ks.get("key_pairs");
            if (keyPairs == null) {
                logger.warn("No spec.key_store.key_pairs");
                return;
            }

            JSONArray keys = (JSONArray) keyPairs.get("keys");
            if (keys == null) {
                logger.warn("No spec.key_store.key_pairs.keys");
                return;
            }

            final HttpCon http2 = http;
            keys.forEach(keyObj -> {
                JSONObject key = (JSONObject) keyObj;
                String name = (String) key.get("name");
                String importIntoKs = (String) key.get("import_into_ks");
                String tlsSecretName = (String) key.get("tls_secret_name");

                if (tlsSecretName == null) {
                    tlsSecretName = name;
                }
                X509Certificate certFromSecret = null;
                PrivateKey keyFromSecret = null;

                String secretUri = String.format("/api/v1/namespaces/%s/secrets/%s",ns,tlsSecretName);
                try {
                    String secretJson = k8s.callWS(k8s.getAuthToken(),http2,secretUri);
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

                    } else {
                        logger.warn(String.format("Secret %s does not exist",secretUri));
                    }
                } catch (Exception e) {
                   logger.warn("Could not load secret " + secretUri,e);
                }

                X509Certificate cert = GlobalEntries.getGlobalEntries().getConfigManager().getCertificate(name);
                try {
                    boolean replace = false;



                    if (cert == null) {
                        replace = true;
                    } else {
                        if (certFromSecret != null && ! Arrays.equals(cert.getEncoded(),certFromSecret.getEncoded())) {
                            replace = true;
                        }
                    }

                    if (replace) {
                        logger.info(String.format("Replacing %s",name));
                        try {
                            GlobalEntries.getGlobalEntries().getConfigManager().addPrivateKey(name,certFromSecret,keyFromSecret);
                        } catch (KeyStoreException e) {
                            logger.warn("Could not add private key " + name,e);
                        }
                    }
                } catch (CertificateEncodingException e) {
                    logger.warn("Could not compare certificate " + name,e);
                }

            });
        } catch (Exception e) {
            logger.warn("Could not load openunisons",e);
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

    @Override
    public void stop() {
        this.keepRunning = false;
    }

    @Override
    public void run() {
         long startTime = System.currentTimeMillis();
        while (keepRunning) {
            if (System.currentTimeMillis() - milliSecondsBetweenRuns > startTime) {
                this.loadOpenUnison();
                startTime = System.currentTimeMillis();
            }
            try {
                Thread.sleep(10000);
            } catch (InterruptedException e) {
                // do nothing
            }
        }
    }
}

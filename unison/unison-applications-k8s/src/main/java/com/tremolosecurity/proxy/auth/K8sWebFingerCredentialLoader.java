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

package com.tremolosecurity.proxy.auth;

import com.oracle.truffle.js.builtins.GlobalBuiltins;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningTarget;
import com.tremolosecurity.proxy.auth.oauth2.WebFingerCredentialLoader;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.log4j.Logger;

import java.util.HashMap;
import java.util.ServiceConfigurationError;

public class K8sWebFingerCredentialLoader implements WebFingerCredentialLoader {
    static Logger logger = Logger.getLogger(K8sWebFingerCredentialLoader.class.getName());
    @Override
    public String loadBearerToken(HttpServletRequest request, HttpServletResponse response, AuthStep as, HttpSession session, HashMap<String, Attribute> authParams) throws ServletException {
        Attribute targetattr = authParams.get("target");
        if (targetattr == null) {
            logger.warn("No target configuration");
            return null;
        }
        String target = targetattr.getValues().get(0);
        try {
            ProvisioningTarget provTarget = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(target);
            if (provTarget == null) {
                logger.warn(String.format("No provisioning target found : %s",target));
                return null;
            }
            OpenShiftTarget k8s = (OpenShiftTarget) provTarget.getProvider();
            return k8s.getAuthToken();
        } catch (Exception e) {
            throw new ServletException("Could not load token",e);
        }
    }
}

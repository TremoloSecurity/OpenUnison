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

package com.tremolosecurity.oidc.k8s;

import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.idp.providers.OpenIDConnectTrust;
import com.tremolosecurity.idp.providers.oidc.sdk.UpdateClaims;
import com.tremolosecurity.k8s.util.PortalGroupMapper;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import org.jose4j.jwt.JwtClaims;

import java.net.URL;
import java.util.HashMap;
import java.util.List;

public class AddClusterGroupsToClaims implements UpdateClaims {
    @Override
    public void updateClaimsBeforeSigning(String dn, ConfigManager cfg, URL url, OpenIDConnectTrust trust, String nonce, HashMap<String, String> extraAttribs, LDAPEntry entry, User user, JwtClaims claims) throws LDAPException, ProvisioningException {
        String cluster = user.getAttribs().get("cluster").getValues().get(0);
        List<String> clusterGroups = PortalGroupMapper.getInstance().getClusterGroups(entry.getAttribute("groups").getAllValues(),cluster);
        claims.setStringListClaim("groups", clusterGroups);
    }
}

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

package com.tremolosecurity.mappers;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.provisioning.UserStoreProviderLookups;
import com.tremolosecurity.provisioning.core.Group;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.mapping.CustomMapping;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import org.apache.log4j.Logger;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

public class GenerateGroups implements CustomMapping  {
    static Logger logger = Logger.getLogger(GenerateGroups.class);
    boolean fromLdap;
    String baseURL;
    String memberOfAttribute;
    String groupIdAttribute;

    String targetName;

    @Override
    public Attribute doMapping(User user, String name) {
        Attribute attr = new Attribute(name);
        StringBuffer val = new StringBuffer();
        if (fromLdap) {
            Attribute memberof = user.getAttribs().get(memberOfAttribute);
            if (memberof != null) {

                memberof.getValues().forEach(groupdn -> {
                    try {
                        LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(groupdn,0,"(objectClass=*)",new ArrayList<>());
                        if (res.hasMore()) {
                            LDAPEntry entry = res.next();
                            LDAPAttribute id = entry.getAttribute(groupIdAttribute);
                            if (id != null) {
                                String group = new String(id.getByteValue(), StandardCharsets.UTF_8);
                                val.append(String.format("{\"value\":\"%s\",\"$ref\":\"%s/Groups/%s\"}",group,baseURL,group)).append(",");

                            }
                        }
                    } catch (LDAPException e) {
                        if (e.getResultCode() != LDAPException.NO_SUCH_OBJECT) {
                            logger.warn("Could not run search", e);
                        }
                    }
                });


            }

        } else {


            try {
                final UserStoreProviderLookups target = (UserStoreProviderLookups) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.targetName).getProvider();

                user.getGroups().forEach(group -> {
                    if (target.isGroupIdUniqueId()) {
                        val.append(String.format("{\"value\":\"%s\",\"$ref\":\"%s/Groups/%s\"}", group, baseURL, group)).append(",");
                    } else {
                        try {
                            Group g = target.lookupGroupByName(group);
                            val.append(String.format("{\"value\":\"%s\",\"$ref\":\"%s/Groups/%s\"}", g.getId(), baseURL, g.getId())).append(",");
                        } catch (ProvisioningException e) {
                            throw new RuntimeException(e);
                        }
                    }
                });
            } catch (ProvisioningException e) {
                throw new RuntimeException(e);
            }
        }

        if (val.length() > 0 && val.charAt(val.length()-1) == ',') {
            val.deleteCharAt(val.length()-1);
        }


        attr.getValues().add("[" + val.toString() + "]");

        return attr;
    }

    @Override
    public void setParams(String... params) {
        fromLdap = params[0].equalsIgnoreCase("true");
        baseURL = params[1];

        if (fromLdap) {
            memberOfAttribute = params[2];
            groupIdAttribute = params[3];
        } else {
            targetName = params[2];
        }
    }
}

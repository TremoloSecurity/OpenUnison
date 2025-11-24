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

package com.tremolosecurity.proxy.filters.scim;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.scim20.UserMapper;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.saml.Attribute;

import java.util.HashMap;
import java.util.Map;

public class SimpleUserMapper {

    Map<String,String> attr2path;

    public void init(HttpFilterConfig config) {
        this.attr2path = new HashMap<>();


    }

    public User scim2openunison(ObjectNode scimUser, String userIdAttributeName) throws ProvisioningException, JsonProcessingException {

        Object document = Configuration.defaultConfiguration().jsonProvider().parse(new ObjectMapper().writeValueAsString(scimUser));

        Map<String, Attribute> attributes = new HashMap<String, Attribute>();
        for (String attribute : attr2path.keySet()) {
            String jsonPath = attr2path.get(attribute);

            var vals = JsonPath.read(document, jsonPath);
            if (vals != null) {
                if (vals instanceof ArrayNode) {
                    Attribute attr = attributes.get(attribute);
                    ((ArrayNode) vals).forEach(val -> attr.getValues().add(val.asText()));
                    if (attr.getValues().size() > 0) {
                        attributes.put(attribute, attr);
                    }
                } else if (vals instanceof ObjectNode) {
                    attributes.put(attribute, new Attribute(vals.toString()));
                }
            }


        }




        if (scimUser.get(userIdAttributeName) == null) {
            throw new ProvisioningException("User does not have " + userIdAttributeName + " attribute");
        }
        String userId = scimUser.get(userIdAttributeName).asText();
        User user = new User(userId);
        user.getAttribs().putAll(attributes);




        return user;

    }
}

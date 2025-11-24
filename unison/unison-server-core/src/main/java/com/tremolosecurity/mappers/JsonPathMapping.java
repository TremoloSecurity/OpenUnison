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

package com.tremolosecurity.mappers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.mapping.CustomMapping;
import com.tremolosecurity.saml.Attribute;

public class JsonPathMapping implements CustomMapping {
    String path;
    String source;

    @Override
    public Attribute doMapping(User user, String name) {

        try {
            Attribute attrToReturn = new Attribute(name);
            Attribute attr = user.getAttribs().get(source);
            if (attr == null) {
                return null;
            }

            Object document = Configuration.defaultConfiguration().jsonProvider().parse(attr.getValues().get(0));

            var vals = JsonPath.read(document, this.path);

            if (vals != null) {
                if (vals instanceof net.minidev.json.JSONArray) {
                    ((net.minidev.json.JSONArray) vals).forEach(val -> attrToReturn.getValues().add(val.toString()));
                } else {
                    attrToReturn.getValues().add(vals.toString());
                }
            } else {
                return null;
            }


            return attrToReturn;
        } catch (PathNotFoundException e) {
            return null;
        }

    }

    @Override
    public void setParams(String... params) {
        source = params[0];
        path = params[1];
    }
}

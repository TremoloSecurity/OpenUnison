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

import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.mapping.CustomMapping;
import com.tremolosecurity.saml.Attribute;

import java.util.UUID;

public class UUIDGenerator implements CustomMapping {
    @Override
    public Attribute doMapping(User user, String name) {
        Attribute uuidAttr = new Attribute(name,UUID.randomUUID().toString());
        return uuidAttr;
    }

    @Override
    public void setParams(String... params) {

    }
}

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

package com.tremolosecurity.provisioning.scim20;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;

public interface UserMapper {

    /**
     * Converts a SCIM 2.0 user to an OpenUnison user
     * @param scimUser JSON of a user object
     * @param userIdAttributeName The name of the userid attribute
     * @return
     * @throws ProvisioningException
     */
    public User scim2openunison(ObjectNode scimUser,String userIdAttributeName) throws ProvisioningException;
}

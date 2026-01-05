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

package com.tremolosecurity.provisioning;

import com.tremolosecurity.provisioning.core.Group;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;

import java.util.List;

public interface UserStoreProviderLookups {
    /**
     * Looks up the user by the human known login id
     * @param login
     * @return
     * @throws ProvisioningException
     */
    public User lookupUserByLogin(String login) throws ProvisioningException;

    /**
     * Looks up a user based on their unique id, generally machine generated and not known to the user
     * @param id
     * @return
     * @throws ProvisioningException
     */
    public User lookupUserById(String id) throws ProvisioningException;

    /**
     * Lookup a group by its unique id, generally machine generated and not known to the user
     * @param id
     * @return
     * @throws ProvisioningException
     */
    public Group lookupGroupById(String id) throws ProvisioningException;

    /**
     * Lookup a group by its descriptive name, generally known by the user
     * @param groupName
     * @return
     * @throws ProvisioningException
     */
    public Group lookupGroupByName(String groupName) throws ProvisioningException;

    /**
     * If true, then group members are unique ids, not login ids.  If false, then the group members have
     * @return
     */
    public boolean isGroupMembersUniqueIds();

    /**
     * If true, then the tremolo object's ID is the unique id.  If not, load it from an attribute
     * @return
     */
    public boolean isUniqueIdTremoloId();

    /**
     * If true, the group id is the same as the name.  if false, then the group name needs to be looked up by the id.
     * @return
     */
    public boolean isGroupIdUniqueId();


    /**
     * Search for users based on an LDAP filter
     * @param ldapFilter
     * @return
     * @throws ProvisioningException
     */
    public List<User> searchUsers(String ldapFilter) throws ProvisioningException;

    /**
     * Search for groups based on an LDAP filter
     * @param ldapFilter
     * @return
     * @throws ProvisioningException
     */
    public List<Group> searchGroups(String ldapFilter) throws ProvisioningException;
}

/*******************************************************************************
 * Copyright 2017 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.provisioning.core;

import java.util.Map;

public interface UserStoreProviderWithAddGroup extends UserStoreProvider {
	public abstract void addGroup(String name,Map<String,String> additionalAttributes,User user,Map<String, Object> request) throws ProvisioningException;
	
	public abstract void deleteGroup(String name,User user, Map<String, Object> request) throws ProvisioningException;
	
	public abstract boolean isGroupExists(String name,User user, Map<String, Object> request) throws ProvisioningException;
}

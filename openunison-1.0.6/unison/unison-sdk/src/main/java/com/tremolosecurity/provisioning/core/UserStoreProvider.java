/*
Copyright 2015 Tremolo Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


package com.tremolosecurity.provisioning.core;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.saml.Attribute;



public interface UserStoreProvider {
	
	
	
	

	public void createUser(User user,Set<String> attributes,Map<String,Object> request) throws ProvisioningException;
	
	public void setUserPassword(User user,Map<String,Object> request) throws ProvisioningException;
	
	public void syncUser(User user,boolean addOnly,Set<String> attributes,Map<String,Object> request) throws ProvisioningException;
	
	public void deleteUser(User user,Map<String,Object> request) throws ProvisioningException;
	
	public User findUser(String userID,Set<String> attributes,Map<String,Object> request) throws ProvisioningException;
	
	public void init(Map<String,Attribute> cfg,ConfigManager cfgMgr,String name) throws ProvisioningException;
}

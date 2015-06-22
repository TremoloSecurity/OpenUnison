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

import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.saml.Attribute;

public class ProvisioningTargetImpl implements ProvisioningTarget  {
	String name;
	UserStoreProvider provider;
	MapIdentity mapper;
	
	public ProvisioningTargetImpl(String name,UserStoreProvider provider,MapIdentity mapper) {
		this.name = name;
		this.provider = provider;
		this.mapper = mapper;
		
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningTarget#createUser(com.tremolosecurity.provisioning.core.User, java.util.HashMap)
	 */
	@Override
	public void createUser(User user,Map<String,Object> request) throws ProvisioningException {
		User localUser = mapper.mapUser(user,false);
		this.provider.createUser(localUser, mapper.getAttributes(),request);
		
	}
	
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningTarget#syncUser(com.tremolosecurity.provisioning.core.User, boolean, java.util.HashMap)
	 */
	@Override
	public void syncUser(User user, boolean addOnly,Map<String,Object> request)
			throws ProvisioningException {
		
		//System.out.print("pre-map\n" + user.toString());
		
		User localUser = mapper.mapUser(user,false);
		
		//System.out.print("post-map\n" + localUser.toString());
		
		this.provider.syncUser(localUser, addOnly, mapper.getAttributes(),request);
		
		
	}
	
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningTarget#deleteUser(com.tremolosecurity.provisioning.core.User, java.util.HashMap)
	 */
	@Override
	public void deleteUser(User user,Map<String,Object> request) throws ProvisioningException {
		User localUser = mapper.mapUser(user,false);
		this.provider.deleteUser(localUser,request);
		
	}
	
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningTarget#findUser(java.lang.String, java.util.HashMap)
	 */
	@Override
	public User findUser(String userID,Map<String,Object> request)
			throws ProvisioningException {
		
		return this.provider.findUser(userID, mapper.getAttributes(),request);
		
		
	}
	
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningTarget#setPassword(com.tremolosecurity.provisioning.core.User, java.util.HashMap)
	 */
	@Override
	public void setPassword(User user,Map<String,Object> request) throws ProvisioningException {
		this.provider.setUserPassword(user,request);
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningTarget#getProvider()
	 */
	@Override
	public UserStoreProvider getProvider() {
		return this.provider;
	}
}

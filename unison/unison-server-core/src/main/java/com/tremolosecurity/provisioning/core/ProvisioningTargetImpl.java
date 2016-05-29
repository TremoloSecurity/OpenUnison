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

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.saml.Attribute;

public class ProvisioningTargetImpl implements ProvisioningTarget  {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(ProvisioningTargetImpl.class.getName());
	
	String name;
	UserStoreProvider provider;
	MapIdentity mapper;
	
	public ProvisioningTargetImpl(String name,UserStoreProvider provider,MapIdentity mapper) {
		this.name = name;
		this.provider = provider;
		this.mapper = mapper;
		
	}
	
	
	private Set<String> buildAttributeList(User user,Map<String,Object> request) {
		boolean userAttrsOnly = request.get(ProvisioningParams.UNISON_USER_ATTRS_ONLY) != null && ((Boolean) request.get(ProvisioningParams.UNISON_USER_ATTRS_ONLY)).booleanValue();
		HashSet<String> explicitAttrs = (HashSet<String>) request.get(ProvisioningParams.UNISON_PROV_ATTRS);
		
		return buildAttributeList(userAttrsOnly,explicitAttrs,user);
	}
	
	private Set<String> buildAttributeList(boolean userAttrsOnly,HashSet<String> explicitAttrs,User user) {
		HashSet<String> attrNames = new HashSet<String>();
		
		if (userAttrsOnly) {
			for (String attrName : user.getAttribs().keySet()) {
				if (this.mapper.getAttributes().contains(attrName)) {
					attrNames.add(attrName);
				} else {
					if (logger.isDebugEnabled()) {
						logger.debug("Attribute '" + attrName + "' is not in the target");
					}
				}
			}
		} else if (explicitAttrs != null) {
			for (String attrName : explicitAttrs) {
				if (this.mapper.getAttributes().contains(attrName)) {
					attrNames.add(attrName);
				} else {
					if (logger.isDebugEnabled()) {
						logger.debug("Attribute '" + attrName + "' is not in the target");
					}
				}
			}
		} else {
			attrNames.addAll(mapper.getAttributes());
		}
		
		return attrNames;
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningTarget#createUser(com.tremolosecurity.provisioning.core.User, java.util.HashMap)
	 */
	@Override
	public void createUser(User user,Map<String,Object> request) throws ProvisioningException {
		User localUser = mapper.mapUser(user,false);
		this.provider.createUser(localUser, this.buildAttributeList(localUser, request),request);
		
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
		
		this.provider.syncUser(localUser, addOnly, this.buildAttributeList(localUser, request),request);
		
		
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

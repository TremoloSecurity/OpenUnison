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


package com.tremolosecurity.provisioning.core.providers.db;

import java.sql.Connection;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.saml.Attribute;

public interface CustomDB {

	public int createUser(Connection con,User user,Map<String,Attribute> attributes) throws ProvisioningException;
	
	public void addGroup(Connection con,int id,String name) throws ProvisioningException;
	
	public void deleteGroup(Connection con,int id,String name) throws ProvisioningException;
	
	public void deleteUser(Connection con, int id) throws ProvisioningException;
	
	public void beginUpdate(Connection con, int id, Map<String,Object> request) throws ProvisioningException;
	
	public void updateField(Connection con,int id,Map<String,Object> request,String attributeName,String oldValue,String newValue) throws ProvisioningException;;
	
	public void clearField(Connection con,int id,Map<String,Object> request,String attributeName, String oldValue) throws ProvisioningException;
	
	public void completeUpdate(Connection con, int id, Map<String,Object> request) throws ProvisioningException;
	
	public boolean listCustomGroups();
	
	public List<String> findGroups(Connection con, int id, Map<String,Object> request) throws ProvisioningException;
	
}

/*******************************************************************************
 * Copyright 2015 Tremolo Security, Inc.
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
 *******************************************************************************/
package com.tremolosecurity.provisioning.az;

import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.az.AzException;
import com.tremolosecurity.proxy.az.CustomAuthorization;
import com.tremolosecurity.saml.Attribute;

public class ManagerAuthorization implements CustomAuthorization {

	static Logger logger = Logger.getLogger(ManagerAuthorization.class.getName());
	
	String subjectAttributeName;
	ConfigManager cfgMgr;
	
	long createdDateMillis;
	DateTime createdDate;
	
	int numberOfEscalations;
	
	long timeBetweenEscalationsInMillis;
	
	boolean ifNoManagerFailAz;
	
	boolean ifMaxEscalationsFailAz;
	
	String autoFailSubjectName;
	
	boolean isManagerDN;
	
	String managerID;
	
	String subject;
	
	@Override
	public void init(String subjectAttributeName, Map<String, Attribute> config)
			throws AzException {
		throw new AzException("Rule not supported in this use case");

	}

	@Override
	public void init(String subjectAttributeName, String subjectAttributeValue,
			Map<String, Attribute> config) throws AzException {
		logger.debug("Initializing Manager Authorization");
		
		this.subjectAttributeName = subjectAttributeName;
		this.setCreatedDateMillis(System.currentTimeMillis());

		
	}

	@Override
	public void loadConfigManager(ConfigManager cfg) throws AzException {
		this.cfgMgr = cfg;

	}

	@Override
	public boolean isAuthorized(AuthInfo subject) throws AzException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public List<String> listPossibleApprovers() {
		// TODO Auto-generated method stub
		return null;
	}

	public String getSubjectAttributeName() {
		return subjectAttributeName;
	}

	public void setSubjectAttributeName(String subjectAttributeName) {
		this.subjectAttributeName = subjectAttributeName;
	}

	public long getCreatedDateMillis() {
		return createdDateMillis;
	}

	public void setCreatedDateMillis(long createdDateMillis) {
		this.createdDateMillis = createdDateMillis;
		this.createdDate = new DateTime(this.createdDateMillis);
	}

	public int getNumberOfEscalations() {
		return numberOfEscalations;
	}

	public void setNumberOfEscalations(int numberOfEscalations) {
		this.numberOfEscalations = numberOfEscalations;
	}

	public long getTimeBetweenEscalationsInMillis() {
		return timeBetweenEscalationsInMillis;
	}

	public void setTimeBetweenEscalationsInMillis(
			long timeBetweenEscalationsInMillis) {
		this.timeBetweenEscalationsInMillis = timeBetweenEscalationsInMillis;
	}

	public boolean isIfNoManagerFailAz() {
		return ifNoManagerFailAz;
	}

	public void setIfNoManagerFailAz(boolean ifNoManagerFailAz) {
		this.ifNoManagerFailAz = ifNoManagerFailAz;
	}

	public boolean isIfMaxEscalationsFailAz() {
		return ifMaxEscalationsFailAz;
	}

	public void setIfMaxEscalationsFailAz(boolean ifMaxEscalationsFailAz) {
		this.ifMaxEscalationsFailAz = ifMaxEscalationsFailAz;
	}

	public String getAutoFailSubjectName() {
		return autoFailSubjectName;
	}

	public void setAutoFailSubjectName(String autoFailSubjectName) {
		this.autoFailSubjectName = autoFailSubjectName;
	}

	public boolean isManagerDN() {
		return isManagerDN;
	}

	public void setManagerDN(boolean isManagerDN) {
		this.isManagerDN = isManagerDN;
	}

	public String getManagerID() {
		return managerID;
	}

	public void setManagerID(String managerID) {
		this.managerID = managerID;
	}

	public String getSubject() {
		return subject;
	}

	public void setSubject(String subject) {
		this.subject = subject;
	}
	
	

}

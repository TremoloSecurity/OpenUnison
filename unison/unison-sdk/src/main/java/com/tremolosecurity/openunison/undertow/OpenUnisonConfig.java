/*******************************************************************************
 * Copyright 2017, 2018 Tremolo Security, Inc.
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
package com.tremolosecurity.openunison.undertow;

import java.util.List;

import com.tremolosecurity.openunison.myvd.ListenerConfig;

public class OpenUnisonConfig extends ListenerConfig {
	
	
	int ldapPort;
	int ldapsPort;
	String ldapsKeyName;
	
	int openExternalPort;
	
	int secureExternalPort;
	boolean forceToSecure;
	String activemqDir;
	
	
	String quartzDir;
	
	

	String contextRoot;

	boolean disableHttp2;
	boolean allowUnEscapedChars;

	boolean forceToLowerCase;

	List<String> welcomePages;

	List<ErrorPageConfig> errorPages;

	boolean redirectToContextRoot;
	
	QueueConfig queueConfiguration;

	/**
	 * @return the forceToLowerCase
	 */
	public boolean isForceToLowerCase() {
		return forceToLowerCase;
	}

	/**
	 * @param forceToLowerCase the forceToLowerCase to set
	 */
	public void setForceToLowerCase(boolean forceToLowerCase) {
		this.forceToLowerCase = forceToLowerCase;
	}
	
	
	public int getOpenExternalPort() {
		return openExternalPort;
	}
	public void setOpenExternalPort(int openExternalPort) {
		this.openExternalPort = openExternalPort;
	}
	
	public int getSecureExternalPort() {
		return secureExternalPort;
	}
	public void setSecureExternalPort(int secureExternalPort) {
		this.secureExternalPort = secureExternalPort;
	}
	public boolean isForceToSecure() {
		return forceToSecure;
	}
	public void setForceToSecure(boolean forceToSecure) {
		this.forceToSecure = forceToSecure;
	}
	public String getActivemqDir() {
		return activemqDir;
	}
	public void setActivemqDir(String activemqDir) {
		this.activemqDir = activemqDir;
	}
	
	public String getQuartzDir() {
		return quartzDir;
	}
	public void setQuartzDir(String quartzDir) {
		this.quartzDir = quartzDir;
	}
	

	public String getContextRoot() {
		return contextRoot;
	}

	public void setContextRoot(String contextRoot) {
		this.contextRoot = contextRoot;
	}

	/**
	 * @return the disableHttp2
	 */
	public boolean isDisableHttp2() {
		return disableHttp2;
	}

	/**
	 * @param disableHttp2 the disableHttp2 to set
	 */
	public void setDisableHttp2(boolean disableHttp2) {
		this.disableHttp2 = disableHttp2;
	}

	/**
	 * @return the allowUnEscapedChars
	 */
	public boolean isAllowUnEscapedChars() {
		return allowUnEscapedChars;
	}

	/**
	 * @param allowUnEscapedChars the allowUnEscapedChars to set
	 */
	public void setAllowUnEscapedChars(boolean allowUnEscapedChars) {
		this.allowUnEscapedChars = allowUnEscapedChars;
	}

	
	/**
	 * @return the welcomePages
	 */
	public List<String> getWelcomePages() {
		return welcomePages;
	}

	/**
	 * @param welcomePages the welcomePages to set
	 */
	public void setWelcomePages(List<String> welcomePages) {
		this.welcomePages = welcomePages;
	}

	/**
	 * @return the errorPages
	 */
	public List<ErrorPageConfig> getErrorPages() {
		return errorPages;
	}

	/**
	 * @param errorPages the errorPages to set
	 */
	public void setErrorPages(List<ErrorPageConfig> errorPages) {
		this.errorPages = errorPages;
	}

	/**
	 * @return the redirectToContextRoot
	 */
	public boolean isRedirectToContextRoot() {
		return redirectToContextRoot;
	}

	/**
	 * @param redirectToContextRoot the redirectToContextRoot to set
	 */
	public void setRedirectToContextRoot(boolean redirectToContextRoot) {
		this.redirectToContextRoot = redirectToContextRoot;
	}

	public int getLdapPort() {
		return ldapPort;
	}

	public void setLdapPort(int ldapPort) {
		this.ldapPort = ldapPort;
	}

	public int getLdapsPort() {
		return ldapsPort;
	}

	public void setLdapsPort(int ldapsPort) {
		this.ldapsPort = ldapsPort;
	}

	public String getLdapsKeyName() {
		return ldapsKeyName;
	}

	public void setLdapsKeyName(String ldapsKeyName) {
		this.ldapsKeyName = ldapsKeyName;
	}

	public QueueConfig getQueueConfiguration() {
		return queueConfiguration;
	}

	public void setQueueConfiguration(QueueConfig queueConfiguration) {
		this.queueConfiguration = queueConfiguration;
	}
	
	
	
	
}

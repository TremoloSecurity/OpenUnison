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
package com.tremolosecurity.openunison.undertow;

import java.util.List;

public class OpenUnisonConfig {
	
	
	
	int openPort;
	int openExternalPort;
	int securePort;
	int secureExternalPort;
	boolean forceToSecure;
	String activemqDir;
	String secureKeyAlias;
	
	String clientAuth;
	List<String> allowedClientNames;
	List<String> ciphers;
	
	String pathToDeployment;
	String pathToEnvFile;
	
	List<String> allowedTlsProtocols;
	
	String quartzDir;
	
	boolean socketShutdownListener;
	String socketShutdownHost;
	int socketShutdownPort;
	String socketShutdownCommand;

	String contextRoot;

	boolean disableHttp2;
	boolean allowUnEscapedChars;

	boolean forceToLowerCase;

	List<String> welcomePages;

	List<ErrorPageConfig> errorPages;

	boolean redirectToContextRoot;

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
	
	public int getOpenPort() {
		return openPort;
	}
	public void setOpenPort(int openPort) {
		this.openPort = openPort;
	}
	public int getOpenExternalPort() {
		return openExternalPort;
	}
	public void setOpenExternalPort(int openExternalPort) {
		this.openExternalPort = openExternalPort;
	}
	public int getSecurePort() {
		return securePort;
	}
	public void setSecurePort(int securePort) {
		this.securePort = securePort;
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
	public String getClientAuth() {
		return clientAuth;
	}
	public void setClientAuth(String clientAuth) {
		this.clientAuth = clientAuth;
	}
	public List<String> getAllowedClientNames() {
		return allowedClientNames;
	}
	public void setAllowedClientNames(List<String> allowedClientNames) {
		this.allowedClientNames = allowedClientNames;
	}
	public List<String> getCiphers() {
		return ciphers;
	}
	public void setCiphers(List<String> ciphers) {
		this.ciphers = ciphers;
	}
	public String getPathToDeployment() {
		return pathToDeployment;
	}
	public void setPathToDeployment(String pathToDeployment) {
		this.pathToDeployment = pathToDeployment;
	}
	public String getPathToEnvFile() {
		return pathToEnvFile;
	}
	public void setPathToEnvFile(String pathToEnvFile) {
		this.pathToEnvFile = pathToEnvFile;
	}
	public String getSecureKeyAlias() {
		return secureKeyAlias;
	}
	public void setSecureKeyAlias(String secureKeyAlias) {
		this.secureKeyAlias = secureKeyAlias;
	}
	public List<String> getAllowedTlsProtocols() {
		return allowedTlsProtocols;
	}
	public void setAllowedTlsProtocols(List<String> allowedTlsProtocols) {
		this.allowedTlsProtocols = allowedTlsProtocols;
	}
	public String getQuartzDir() {
		return quartzDir;
	}
	public void setQuartzDir(String quartzDir) {
		this.quartzDir = quartzDir;
	}
	public boolean isSocketShutdownListener() {
		return socketShutdownListener;
	}
	public void setSocketShutdownListener(boolean socketShutdownListener) {
		this.socketShutdownListener = socketShutdownListener;
	}
	public String getSocketShutdownHost() {
		return socketShutdownHost;
	}
	public void setSocketShutdownHost(String socketShutdownHost) {
		this.socketShutdownHost = socketShutdownHost;
	}
	public int getSocketShutdownPort() {
		return socketShutdownPort;
	}
	public void setSocketShutdownPort(int socketShutdownPort) {
		this.socketShutdownPort = socketShutdownPort;
	}
	public String getSocketShutdownCommand() {
		return socketShutdownCommand;
	}
	public void setSocketShutdownCommand(String socketShutdownCommand) {
		this.socketShutdownCommand = socketShutdownCommand;
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
}

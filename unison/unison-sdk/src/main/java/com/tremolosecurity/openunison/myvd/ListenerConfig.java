/*******************************************************************************
 * Copyright 2019 Tremolo Security, Inc.
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
package com.tremolosecurity.openunison.myvd;

import java.util.List;

public class ListenerConfig {
	int openPort;
	int securePort;
	
	String secureKeyAlias;
	
	String clientAuth;
	List<String> allowedClientNames;
	List<String> ciphers;
	
	String pathToDeployment;
	String pathToEnvFile;
	
	List<String> allowedTlsProtocols;
	
	boolean socketShutdownListener;
	String socketShutdownHost;
	int socketShutdownPort;
	String socketShutdownCommand;
	
	public int getOpenPort() {
		return openPort;
	}
	public void setOpenPort(int openPort) {
		this.openPort = openPort;
	}
	
	public int getSecurePort() {
		return securePort;
	}
	public void setSecurePort(int securePort) {
		this.securePort = securePort;
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
	
	
}

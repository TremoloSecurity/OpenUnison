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

package com.tremolosecurity.k8s.model;

import java.util.ArrayList;
import java.util.List;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.apache.commons.lang.builder.ToStringBuilder;

public class OpenunisonNetworkConfiguration {

    @SerializedName("force_to_lower_case")
    @Expose
    private boolean forceToLowerCase;
    @SerializedName("open_port")
    @Expose
    private long openPort;
    @SerializedName("open_external_port")
    @Expose
    private long openExternalPort;
    @SerializedName("secure_port")
    @Expose
    private long securePort;
    @SerializedName("secure_external_port")
    @Expose
    private long secureExternalPort;
    @SerializedName("force_to_secure")
    @Expose
    private boolean forceToSecure;
    @SerializedName("activemq_dir")
    @Expose
    private String activemqDir;
    @SerializedName("client_auth")
    @Expose
    private String clientAuth;
    @SerializedName("allowed_client_names")
    @Expose
    private List<String> allowedClientNames = new ArrayList<String>();
    @SerializedName("ciphers")
    @Expose
    private List<String> ciphers = new ArrayList<String>();
    @SerializedName("path_to_deployment")
    @Expose
    private String pathToDeployment;
    @SerializedName("path_to_env_file")
    @Expose
    private String pathToEnvFile;
    @SerializedName("secure_key_alias")
    @Expose
    private String secureKeyAlias;
    @SerializedName("allowed_tls_protocols")
    @Expose
    private List<String> allowedTlsProtocols = new ArrayList<String>();
    @SerializedName("quartz_dir")
    @Expose
    private String quartzDir;
    @SerializedName("context_root")
    @Expose
    private String contextRoot;
    @SerializedName("disable_http2")
    @Expose
    private boolean disableHttp2;
    @SerializedName("allow_un_escaped_chars")
    @Expose
    private String allowUnEscapedChars;
    @SerializedName("welecome_pages")
    @Expose
    private List<String> welecomePages = new ArrayList<String>();
    @SerializedName("error_pages")
    @Expose
    private List<ErrorPage> errorPages = new ArrayList<ErrorPage>();
    @SerializedName("redirect_to_context_root")
    @Expose
    private boolean redirectToContextRoot;

    /**
     * No args constructor for use in serialization
     * 
     */
    public OpenunisonNetworkConfiguration() {
    }

    /**
     * 
     * @param securePort
     * @param pathToEnvFile
     * @param secureExternalPort
     * @param openPort
     * @param activemqDir
     * @param forceToLowerCase
     * @param pathToDeployment
     * @param errorPages
     * @param quartzDir
     * @param disableHttp2
     * @param allowedClientNames
     * @param ciphers
     * @param allowUnEscapedChars
     * @param forceToSecure
     * @param contextRoot
     * @param welecomePages
     * @param allowedTlsProtocols
     * @param secureKeyAlias
     * @param redirectToContextRoot
     * @param openExternalPort
     * @param clientAuth
     */
    public OpenunisonNetworkConfiguration(boolean forceToLowerCase, long openPort, long openExternalPort, long securePort, long secureExternalPort, boolean forceToSecure, String activemqDir, String clientAuth, List<String> allowedClientNames, List<String> ciphers, String pathToDeployment, String pathToEnvFile, String secureKeyAlias, List<String> allowedTlsProtocols, String quartzDir, String contextRoot, boolean disableHttp2, String allowUnEscapedChars, List<String> welecomePages, List<ErrorPage> errorPages, boolean redirectToContextRoot) {
        super();
        this.forceToLowerCase = forceToLowerCase;
        this.openPort = openPort;
        this.openExternalPort = openExternalPort;
        this.securePort = securePort;
        this.secureExternalPort = secureExternalPort;
        this.forceToSecure = forceToSecure;
        this.activemqDir = activemqDir;
        this.clientAuth = clientAuth;
        this.allowedClientNames = allowedClientNames;
        this.ciphers = ciphers;
        this.pathToDeployment = pathToDeployment;
        this.pathToEnvFile = pathToEnvFile;
        this.secureKeyAlias = secureKeyAlias;
        this.allowedTlsProtocols = allowedTlsProtocols;
        this.quartzDir = quartzDir;
        this.contextRoot = contextRoot;
        this.disableHttp2 = disableHttp2;
        this.allowUnEscapedChars = allowUnEscapedChars;
        this.welecomePages = welecomePages;
        this.errorPages = errorPages;
        this.redirectToContextRoot = redirectToContextRoot;
    }

    public boolean isForceToLowerCase() {
        return forceToLowerCase;
    }

    public void setForceToLowerCase(boolean forceToLowerCase) {
        this.forceToLowerCase = forceToLowerCase;
    }

    public OpenunisonNetworkConfiguration withForceToLowerCase(boolean forceToLowerCase) {
        this.forceToLowerCase = forceToLowerCase;
        return this;
    }

    public long getOpenPort() {
        return openPort;
    }

    public void setOpenPort(long openPort) {
        this.openPort = openPort;
    }

    public OpenunisonNetworkConfiguration withOpenPort(long openPort) {
        this.openPort = openPort;
        return this;
    }

    public long getOpenExternalPort() {
        return openExternalPort;
    }

    public void setOpenExternalPort(long openExternalPort) {
        this.openExternalPort = openExternalPort;
    }

    public OpenunisonNetworkConfiguration withOpenExternalPort(long openExternalPort) {
        this.openExternalPort = openExternalPort;
        return this;
    }

    public long getSecurePort() {
        return securePort;
    }

    public void setSecurePort(long securePort) {
        this.securePort = securePort;
    }

    public OpenunisonNetworkConfiguration withSecurePort(long securePort) {
        this.securePort = securePort;
        return this;
    }

    public long getSecureExternalPort() {
        return secureExternalPort;
    }

    public void setSecureExternalPort(long secureExternalPort) {
        this.secureExternalPort = secureExternalPort;
    }

    public OpenunisonNetworkConfiguration withSecureExternalPort(long secureExternalPort) {
        this.secureExternalPort = secureExternalPort;
        return this;
    }

    public boolean isForceToSecure() {
        return forceToSecure;
    }

    public void setForceToSecure(boolean forceToSecure) {
        this.forceToSecure = forceToSecure;
    }

    public OpenunisonNetworkConfiguration withForceToSecure(boolean forceToSecure) {
        this.forceToSecure = forceToSecure;
        return this;
    }

    public String getActivemqDir() {
        return activemqDir;
    }

    public void setActivemqDir(String activemqDir) {
        this.activemqDir = activemqDir;
    }

    public OpenunisonNetworkConfiguration withActivemqDir(String activemqDir) {
        this.activemqDir = activemqDir;
        return this;
    }

    public String getClientAuth() {
        return clientAuth;
    }

    public void setClientAuth(String clientAuth) {
        this.clientAuth = clientAuth;
    }

    public OpenunisonNetworkConfiguration withClientAuth(String clientAuth) {
        this.clientAuth = clientAuth;
        return this;
    }

    public List<String> getAllowedClientNames() {
        return allowedClientNames;
    }

    public void setAllowedClientNames(List<String> allowedClientNames) {
        this.allowedClientNames = allowedClientNames;
    }

    public OpenunisonNetworkConfiguration withAllowedClientNames(List<String> allowedClientNames) {
        this.allowedClientNames = allowedClientNames;
        return this;
    }

    public List<String> getCiphers() {
        return ciphers;
    }

    public void setCiphers(List<String> ciphers) {
        this.ciphers = ciphers;
    }

    public OpenunisonNetworkConfiguration withCiphers(List<String> ciphers) {
        this.ciphers = ciphers;
        return this;
    }

    public String getPathToDeployment() {
        return pathToDeployment;
    }

    public void setPathToDeployment(String pathToDeployment) {
        this.pathToDeployment = pathToDeployment;
    }

    public OpenunisonNetworkConfiguration withPathToDeployment(String pathToDeployment) {
        this.pathToDeployment = pathToDeployment;
        return this;
    }

    public String getPathToEnvFile() {
        return pathToEnvFile;
    }

    public void setPathToEnvFile(String pathToEnvFile) {
        this.pathToEnvFile = pathToEnvFile;
    }

    public OpenunisonNetworkConfiguration withPathToEnvFile(String pathToEnvFile) {
        this.pathToEnvFile = pathToEnvFile;
        return this;
    }

    public String getSecureKeyAlias() {
        return secureKeyAlias;
    }

    public void setSecureKeyAlias(String secureKeyAlias) {
        this.secureKeyAlias = secureKeyAlias;
    }

    public OpenunisonNetworkConfiguration withSecureKeyAlias(String secureKeyAlias) {
        this.secureKeyAlias = secureKeyAlias;
        return this;
    }

    public List<String> getAllowedTlsProtocols() {
        return allowedTlsProtocols;
    }

    public void setAllowedTlsProtocols(List<String> allowedTlsProtocols) {
        this.allowedTlsProtocols = allowedTlsProtocols;
    }

    public OpenunisonNetworkConfiguration withAllowedTlsProtocols(List<String> allowedTlsProtocols) {
        this.allowedTlsProtocols = allowedTlsProtocols;
        return this;
    }

    public String getQuartzDir() {
        return quartzDir;
    }

    public void setQuartzDir(String quartzDir) {
        this.quartzDir = quartzDir;
    }

    public OpenunisonNetworkConfiguration withQuartzDir(String quartzDir) {
        this.quartzDir = quartzDir;
        return this;
    }

    public String getContextRoot() {
        return contextRoot;
    }

    public void setContextRoot(String contextRoot) {
        this.contextRoot = contextRoot;
    }

    public OpenunisonNetworkConfiguration withContextRoot(String contextRoot) {
        this.contextRoot = contextRoot;
        return this;
    }

    public boolean isDisableHttp2() {
        return disableHttp2;
    }

    public void setDisableHttp2(boolean disableHttp2) {
        this.disableHttp2 = disableHttp2;
    }

    public OpenunisonNetworkConfiguration withDisableHttp2(boolean disableHttp2) {
        this.disableHttp2 = disableHttp2;
        return this;
    }

    public String getAllowUnEscapedChars() {
        return allowUnEscapedChars;
    }

    public void setAllowUnEscapedChars(String allowUnEscapedChars) {
        this.allowUnEscapedChars = allowUnEscapedChars;
    }

    public OpenunisonNetworkConfiguration withAllowUnEscapedChars(String allowUnEscapedChars) {
        this.allowUnEscapedChars = allowUnEscapedChars;
        return this;
    }

    public List<String> getWelecomePages() {
        return welecomePages;
    }

    public void setWelecomePages(List<String> welecomePages) {
        this.welecomePages = welecomePages;
    }

    public OpenunisonNetworkConfiguration withWelecomePages(List<String> welecomePages) {
        this.welecomePages = welecomePages;
        return this;
    }

    public List<ErrorPage> getErrorPages() {
        return errorPages;
    }

    public void setErrorPages(List<ErrorPage> errorPages) {
        this.errorPages = errorPages;
    }

    public OpenunisonNetworkConfiguration withErrorPages(List<ErrorPage> errorPages) {
        this.errorPages = errorPages;
        return this;
    }

    public boolean isRedirectToContextRoot() {
        return redirectToContextRoot;
    }

    public void setRedirectToContextRoot(boolean redirectToContextRoot) {
        this.redirectToContextRoot = redirectToContextRoot;
    }

    public OpenunisonNetworkConfiguration withRedirectToContextRoot(boolean redirectToContextRoot) {
        this.redirectToContextRoot = redirectToContextRoot;
        return this;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("forceToLowerCase", forceToLowerCase).append("openPort", openPort).append("openExternalPort", openExternalPort).append("securePort", securePort).append("secureExternalPort", secureExternalPort).append("forceToSecure", forceToSecure).append("activemqDir", activemqDir).append("clientAuth", clientAuth).append("allowedClientNames", allowedClientNames).append("ciphers", ciphers).append("pathToDeployment", pathToDeployment).append("pathToEnvFile", pathToEnvFile).append("secureKeyAlias", secureKeyAlias).append("allowedTlsProtocols", allowedTlsProtocols).append("quartzDir", quartzDir).append("contextRoot", contextRoot).append("disableHttp2", disableHttp2).append("allowUnEscapedChars", allowUnEscapedChars).append("welecomePages", welecomePages).append("errorPages", errorPages).append("redirectToContextRoot", redirectToContextRoot).toString();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(pathToEnvFile).append(securePort).append(secureExternalPort).append(activemqDir).append(openPort).append(forceToLowerCase).append(pathToDeployment).append(errorPages).append(quartzDir).append(disableHttp2).append(ciphers).append(allowedClientNames).append(allowUnEscapedChars).append(forceToSecure).append(contextRoot).append(welecomePages).append(allowedTlsProtocols).append(secureKeyAlias).append(redirectToContextRoot).append(openExternalPort).append(clientAuth).toHashCode();
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof OpenunisonNetworkConfiguration) == false) {
            return false;
        }
        OpenunisonNetworkConfiguration rhs = ((OpenunisonNetworkConfiguration) other);
        return new EqualsBuilder().append(pathToEnvFile, rhs.pathToEnvFile).append(securePort, rhs.securePort).append(secureExternalPort, rhs.secureExternalPort).append(activemqDir, rhs.activemqDir).append(openPort, rhs.openPort).append(forceToLowerCase, rhs.forceToLowerCase).append(pathToDeployment, rhs.pathToDeployment).append(errorPages, rhs.errorPages).append(quartzDir, rhs.quartzDir).append(disableHttp2, rhs.disableHttp2).append(ciphers, rhs.ciphers).append(allowedClientNames, rhs.allowedClientNames).append(allowUnEscapedChars, rhs.allowUnEscapedChars).append(forceToSecure, rhs.forceToSecure).append(contextRoot, rhs.contextRoot).append(welecomePages, rhs.welecomePages).append(allowedTlsProtocols, rhs.allowedTlsProtocols).append(secureKeyAlias, rhs.secureKeyAlias).append(redirectToContextRoot, rhs.redirectToContextRoot).append(openExternalPort, rhs.openExternalPort).append(clientAuth, rhs.clientAuth).isEquals();
    }

}

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

public class CreateData {

    @SerializedName("sign_by_k8s_ca")
    @Expose
    private boolean signByK8sCa;
    @SerializedName("server_name")
    @Expose
    private String serverName;
    @SerializedName("subject_alternative_names")
    @Expose
    private List<String> subjectAlternativeNames = new ArrayList<String>();
    @SerializedName("key_size")
    @Expose
    private long keySize;
    @SerializedName("ca_cert")
    @Expose
    private boolean caCert;
    @SerializedName("delete_pods_labels")
    @Expose
    private List<String> deletePodsLabels = new ArrayList<String>();
    @SerializedName("secret_info")
    @Expose
    private SecretInfo secretInfo;
    
    @SerializedName("target_namespace")
    @Expose
    private String targetNamespace;

    /**
     * No args constructor for use in serialization
     * 
     */
    public CreateData() {
    }

    /**
     * 
     * @param secretInfo
     * @param caCert
     * @param keySize
     * @param subjectAlternativeNames
     * @param signByK8sCa
     * @param deletePodsLabels
     * @param serverName
     * @param targetNamespace
     */
    public CreateData(boolean signByK8sCa, String serverName, List<String> subjectAlternativeNames, long keySize, boolean caCert, List<String> deletePodsLabels, SecretInfo secretInfo,String targetNamespace) {
        super();
        this.signByK8sCa = signByK8sCa;
        this.serverName = serverName;
        this.subjectAlternativeNames = subjectAlternativeNames;
        this.keySize = keySize;
        this.caCert = caCert;
        this.deletePodsLabels = deletePodsLabels;
        this.secretInfo = secretInfo;
        this.targetNamespace = targetNamespace;
    }

    public boolean isSignByK8sCa() {
        return signByK8sCa;
    }

    public void setSignByK8sCa(boolean signByK8sCa) {
        this.signByK8sCa = signByK8sCa;
    }

    public CreateData withSignByK8sCa(boolean signByK8sCa) {
        this.signByK8sCa = signByK8sCa;
        return this;
    }

    public String getServerName() {
        return serverName;
    }

    public void setServerName(String serverName) {
        this.serverName = serverName;
    }

    public CreateData withServerName(String serverName) {
        this.serverName = serverName;
        return this;
    }

    public List<String> getSubjectAlternativeNames() {
        return subjectAlternativeNames;
    }

    public void setSubjectAlternativeNames(List<String> subjectAlternativeNames) {
        this.subjectAlternativeNames = subjectAlternativeNames;
    }

    public CreateData withSubjectAlternativeNames(List<String> subjectAlternativeNames) {
        this.subjectAlternativeNames = subjectAlternativeNames;
        return this;
    }

    public long getKeySize() {
        return keySize;
    }

    public void setKeySize(long keySize) {
        this.keySize = keySize;
    }

    public CreateData withKeySize(long keySize) {
        this.keySize = keySize;
        return this;
    }

    public boolean isCaCert() {
        return caCert;
    }

    public void setCaCert(boolean caCert) {
        this.caCert = caCert;
    }

    public CreateData withCaCert(boolean caCert) {
        this.caCert = caCert;
        return this;
    }

    public List<String> getDeletePodsLabels() {
        return deletePodsLabels;
    }

    public void setDeletePodsLabels(List<String> deletePodsLabels) {
        this.deletePodsLabels = deletePodsLabels;
    }

    public CreateData withDeletePodsLabels(List<String> deletePodsLabels) {
        this.deletePodsLabels = deletePodsLabels;
        return this;
    }

    public SecretInfo getSecretInfo() {
        return secretInfo;
    }

    public void setSecretInfo(SecretInfo secretInfo) {
        this.secretInfo = secretInfo;
    }

    public CreateData withSecretInfo(SecretInfo secretInfo) {
        this.secretInfo = secretInfo;
        return this;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("signByK8sCa", signByK8sCa).append("serverName", serverName).append("subjectAlternativeNames", subjectAlternativeNames).append("keySize", keySize).append("caCert", caCert).append("deletePodsLabels", deletePodsLabels).append("secretInfo", secretInfo).append("targetNamespace",targetNamespace).toString();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(secretInfo).append(caCert).append(keySize).append(subjectAlternativeNames).append(signByK8sCa).append(deletePodsLabels).append(serverName).toHashCode();
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof CreateData) == false) {
            return false;
        }
        CreateData rhs = ((CreateData) other);
        return new EqualsBuilder().append(secretInfo, rhs.secretInfo).append(caCert, rhs.caCert).append(keySize, rhs.keySize).append(subjectAlternativeNames, rhs.subjectAlternativeNames).append(signByK8sCa, rhs.signByK8sCa).append(deletePodsLabels, rhs.deletePodsLabels).append(serverName, rhs.serverName).append(targetNamespace, rhs.targetNamespace).isEquals();
    }

	public String getTargetNamespace() {
		return targetNamespace;
	}

	public void setTargetNamespace(String targetNamespace) {
		this.targetNamespace = targetNamespace;
	}
    
    

}

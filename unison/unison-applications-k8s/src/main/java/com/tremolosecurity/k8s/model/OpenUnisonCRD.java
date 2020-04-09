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

public class OpenUnisonCRD {

    @SerializedName("image")
    @Expose
    private String image;
    @SerializedName("replicas")
    @Expose
    private long replicas;
    @SerializedName("enable_activemq")
    @Expose
    private boolean enableActivemq;
    @SerializedName("activemq_image")
    @Expose
    private String activemqImage;
    @SerializedName("dest_secret")
    @Expose
    private String destSecret;
    @SerializedName("source_secret")
    @Expose
    private String sourceSecret;
    @SerializedName("secret_data")
    @Expose
    private List<String> secretData = new ArrayList<String>();
    @SerializedName("openshift")
    @Expose
    private Openshift openshift;
    @SerializedName("hosts")
    @Expose
    private List<Host> hosts = new ArrayList<Host>();
    @SerializedName("non_secret_data")
    @Expose
    private List<NonSecretDatum> nonSecretData = new ArrayList<NonSecretDatum>();
    @SerializedName("openunison_network_configuration")
    @Expose
    private OpenunisonNetworkConfiguration openunisonNetworkConfiguration;
    @SerializedName("saml_remote_idp")
    @Expose
    private List<SamlRemoteIdp> samlRemoteIdp = new ArrayList<SamlRemoteIdp>();
    @SerializedName("run_sql")
    @Expose
    private String runSql;
    @SerializedName("key_store")
    @Expose
    private KeyStore keyStore;

    /**
     * No args constructor for use in serialization
     * 
     */
    public OpenUnisonCRD() {
    }

    /**
     * 
     * @param openshift
     * @param replicas
     * @param activemqImage
     * @param keyStore
     * @param secretData
     * @param nonSecretData
     * @param destSecret
     * @param hosts
     * @param enableActivemq
     * @param image
     * @param sourceSecret
     * @param samlRemoteIdp
     * @param runSql
     * @param openunisonNetworkConfiguration
     */
    public OpenUnisonCRD(String image, long replicas, boolean enableActivemq, String activemqImage, String destSecret, String sourceSecret, List<String> secretData, Openshift openshift, List<Host> hosts, List<NonSecretDatum> nonSecretData, OpenunisonNetworkConfiguration openunisonNetworkConfiguration, List<SamlRemoteIdp> samlRemoteIdp, String runSql, KeyStore keyStore) {
        super();
        this.image = image;
        this.replicas = replicas;
        this.enableActivemq = enableActivemq;
        this.activemqImage = activemqImage;
        this.destSecret = destSecret;
        this.sourceSecret = sourceSecret;
        this.secretData = secretData;
        this.openshift = openshift;
        this.hosts = hosts;
        this.nonSecretData = nonSecretData;
        this.openunisonNetworkConfiguration = openunisonNetworkConfiguration;
        this.samlRemoteIdp = samlRemoteIdp;
        this.runSql = runSql;
        this.keyStore = keyStore;
    }

    public String getImage() {
        return image;
    }

    public void setImage(String image) {
        this.image = image;
    }

    public OpenUnisonCRD withImage(String image) {
        this.image = image;
        return this;
    }

    public long getReplicas() {
        return replicas;
    }

    public void setReplicas(long replicas) {
        this.replicas = replicas;
    }

    public OpenUnisonCRD withReplicas(long replicas) {
        this.replicas = replicas;
        return this;
    }

    public boolean isEnableActivemq() {
        return enableActivemq;
    }

    public void setEnableActivemq(boolean enableActivemq) {
        this.enableActivemq = enableActivemq;
    }

    public OpenUnisonCRD withEnableActivemq(boolean enableActivemq) {
        this.enableActivemq = enableActivemq;
        return this;
    }

    public String getActivemqImage() {
        return activemqImage;
    }

    public void setActivemqImage(String activemqImage) {
        this.activemqImage = activemqImage;
    }

    public OpenUnisonCRD withActivemqImage(String activemqImage) {
        this.activemqImage = activemqImage;
        return this;
    }

    public String getDestSecret() {
        return destSecret;
    }

    public void setDestSecret(String destSecret) {
        this.destSecret = destSecret;
    }

    public OpenUnisonCRD withDestSecret(String destSecret) {
        this.destSecret = destSecret;
        return this;
    }

    public String getSourceSecret() {
        return sourceSecret;
    }

    public void setSourceSecret(String sourceSecret) {
        this.sourceSecret = sourceSecret;
    }

    public OpenUnisonCRD withSourceSecret(String sourceSecret) {
        this.sourceSecret = sourceSecret;
        return this;
    }

    public List<String> getSecretData() {
        return secretData;
    }

    public void setSecretData(List<String> secretData) {
        this.secretData = secretData;
    }

    public OpenUnisonCRD withSecretData(List<String> secretData) {
        this.secretData = secretData;
        return this;
    }

    public Openshift getOpenshift() {
        return openshift;
    }

    public void setOpenshift(Openshift openshift) {
        this.openshift = openshift;
    }

    public OpenUnisonCRD withOpenshift(Openshift openshift) {
        this.openshift = openshift;
        return this;
    }

    public List<Host> getHosts() {
        return hosts;
    }

    public void setHosts(List<Host> hosts) {
        this.hosts = hosts;
    }

    public OpenUnisonCRD withHosts(List<Host> hosts) {
        this.hosts = hosts;
        return this;
    }

    public List<NonSecretDatum> getNonSecretData() {
        return nonSecretData;
    }

    public void setNonSecretData(List<NonSecretDatum> nonSecretData) {
        this.nonSecretData = nonSecretData;
    }

    public OpenUnisonCRD withNonSecretData(List<NonSecretDatum> nonSecretData) {
        this.nonSecretData = nonSecretData;
        return this;
    }

    public OpenunisonNetworkConfiguration getOpenunisonNetworkConfiguration() {
        return openunisonNetworkConfiguration;
    }

    public void setOpenunisonNetworkConfiguration(OpenunisonNetworkConfiguration openunisonNetworkConfiguration) {
        this.openunisonNetworkConfiguration = openunisonNetworkConfiguration;
    }

    public OpenUnisonCRD withOpenunisonNetworkConfiguration(OpenunisonNetworkConfiguration openunisonNetworkConfiguration) {
        this.openunisonNetworkConfiguration = openunisonNetworkConfiguration;
        return this;
    }

    public List<SamlRemoteIdp> getSamlRemoteIdp() {
        return samlRemoteIdp;
    }

    public void setSamlRemoteIdp(List<SamlRemoteIdp> samlRemoteIdp) {
        this.samlRemoteIdp = samlRemoteIdp;
    }

    public OpenUnisonCRD withSamlRemoteIdp(List<SamlRemoteIdp> samlRemoteIdp) {
        this.samlRemoteIdp = samlRemoteIdp;
        return this;
    }

    public String getRunSql() {
        return runSql;
    }

    public void setRunSql(String runSql) {
        this.runSql = runSql;
    }

    public OpenUnisonCRD withRunSql(String runSql) {
        this.runSql = runSql;
        return this;
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public void setKeyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    public OpenUnisonCRD withKeyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
        return this;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("image", image).append("replicas", replicas).append("enableActivemq", enableActivemq).append("activemqImage", activemqImage).append("destSecret", destSecret).append("sourceSecret", sourceSecret).append("secretData", secretData).append("openshift", openshift).append("hosts", hosts).append("nonSecretData", nonSecretData).append("openunisonNetworkConfiguration", openunisonNetworkConfiguration).append("samlRemoteIdp", samlRemoteIdp).append("runSql", runSql).append("keyStore", keyStore).toString();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(replicas).append(keyStore).append(destSecret).append(image).append(sourceSecret).append(runSql).append(openshift).append(activemqImage).append(secretData).append(nonSecretData).append(hosts).append(enableActivemq).append(samlRemoteIdp).append(openunisonNetworkConfiguration).toHashCode();
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof OpenUnisonCRD) == false) {
            return false;
        }
        OpenUnisonCRD rhs = ((OpenUnisonCRD) other);
        return new EqualsBuilder().append(replicas, rhs.replicas).append(keyStore, rhs.keyStore).append(destSecret, rhs.destSecret).append(image, rhs.image).append(sourceSecret, rhs.sourceSecret).append(runSql, rhs.runSql).append(openshift, rhs.openshift).append(activemqImage, rhs.activemqImage).append(secretData, rhs.secretData).append(nonSecretData, rhs.nonSecretData).append(hosts, rhs.hosts).append(enableActivemq, rhs.enableActivemq).append(samlRemoteIdp, rhs.samlRemoteIdp).append(openunisonNetworkConfiguration, rhs.openunisonNetworkConfiguration).isEquals();
    }

}

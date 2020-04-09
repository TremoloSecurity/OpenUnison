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

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.apache.commons.lang.builder.ToStringBuilder;

public class Mapping {

    @SerializedName("entity_id")
    @Expose
    private String entityId;
    @SerializedName("post_url")
    @Expose
    private String postUrl;
    @SerializedName("redirect_url")
    @Expose
    private String redirectUrl;
    @SerializedName("logout_url")
    @Expose
    private String logoutUrl;
    @SerializedName("signing_cert_alis")
    @Expose
    private String signingCertAlis;
    @SerializedName("encryption_cert_alias")
    @Expose
    private String encryptionCertAlias;

    /**
     * No args constructor for use in serialization
     * 
     */
    public Mapping() {
    }

    /**
     * 
     * @param logoutUrl
     * @param encryptionCertAlias
     * @param signingCertAlis
     * @param postUrl
     * @param entityId
     * @param redirectUrl
     */
    public Mapping(String entityId, String postUrl, String redirectUrl, String logoutUrl, String signingCertAlis, String encryptionCertAlias) {
        super();
        this.entityId = entityId;
        this.postUrl = postUrl;
        this.redirectUrl = redirectUrl;
        this.logoutUrl = logoutUrl;
        this.signingCertAlis = signingCertAlis;
        this.encryptionCertAlias = encryptionCertAlias;
    }

    public String getEntityId() {
        return entityId;
    }

    public void setEntityId(String entityId) {
        this.entityId = entityId;
    }

    public Mapping withEntityId(String entityId) {
        this.entityId = entityId;
        return this;
    }

    public String getPostUrl() {
        return postUrl;
    }

    public void setPostUrl(String postUrl) {
        this.postUrl = postUrl;
    }

    public Mapping withPostUrl(String postUrl) {
        this.postUrl = postUrl;
        return this;
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }

    public void setRedirectUrl(String redirectUrl) {
        this.redirectUrl = redirectUrl;
    }

    public Mapping withRedirectUrl(String redirectUrl) {
        this.redirectUrl = redirectUrl;
        return this;
    }

    public String getLogoutUrl() {
        return logoutUrl;
    }

    public void setLogoutUrl(String logoutUrl) {
        this.logoutUrl = logoutUrl;
    }

    public Mapping withLogoutUrl(String logoutUrl) {
        this.logoutUrl = logoutUrl;
        return this;
    }

    public String getSigningCertAlis() {
        return signingCertAlis;
    }

    public void setSigningCertAlis(String signingCertAlis) {
        this.signingCertAlis = signingCertAlis;
    }

    public Mapping withSigningCertAlis(String signingCertAlis) {
        this.signingCertAlis = signingCertAlis;
        return this;
    }

    public String getEncryptionCertAlias() {
        return encryptionCertAlias;
    }

    public void setEncryptionCertAlias(String encryptionCertAlias) {
        this.encryptionCertAlias = encryptionCertAlias;
    }

    public Mapping withEncryptionCertAlias(String encryptionCertAlias) {
        this.encryptionCertAlias = encryptionCertAlias;
        return this;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("entityId", entityId).append("postUrl", postUrl).append("redirectUrl", redirectUrl).append("logoutUrl", logoutUrl).append("signingCertAlis", signingCertAlis).append("encryptionCertAlias", encryptionCertAlias).toString();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(logoutUrl).append(encryptionCertAlias).append(signingCertAlis).append(postUrl).append(entityId).append(redirectUrl).toHashCode();
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof Mapping) == false) {
            return false;
        }
        Mapping rhs = ((Mapping) other);
        return new EqualsBuilder().append(logoutUrl, rhs.logoutUrl).append(encryptionCertAlias, rhs.encryptionCertAlias).append(signingCertAlis, rhs.signingCertAlis).append(postUrl, rhs.postUrl).append(entityId, rhs.entityId).append(redirectUrl, rhs.redirectUrl).isEquals();
    }

}

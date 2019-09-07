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

public class SecretInfo {

    @SerializedName("type_of_secret")
    @Expose
    private String typeOfSecret;
    @SerializedName("cert_name")
    @Expose
    private String certName;
    @SerializedName("key_name")
    @Expose
    private String keyName;

    /**
     * No args constructor for use in serialization
     * 
     */
    public SecretInfo() {
    }

    /**
     * 
     * @param certName
     * @param keyName
     * @param typeOfSecret
     */
    public SecretInfo(String typeOfSecret, String certName, String keyName) {
        super();
        this.typeOfSecret = typeOfSecret;
        this.certName = certName;
        this.keyName = keyName;
    }

    public String getTypeOfSecret() {
        return typeOfSecret;
    }

    public void setTypeOfSecret(String typeOfSecret) {
        this.typeOfSecret = typeOfSecret;
    }

    public SecretInfo withTypeOfSecret(String typeOfSecret) {
        this.typeOfSecret = typeOfSecret;
        return this;
    }

    public String getCertName() {
        return certName;
    }

    public void setCertName(String certName) {
        this.certName = certName;
    }

    public SecretInfo withCertName(String certName) {
        this.certName = certName;
        return this;
    }

    public String getKeyName() {
        return keyName;
    }

    public void setKeyName(String keyName) {
        this.keyName = keyName;
    }

    public SecretInfo withKeyName(String keyName) {
        this.keyName = keyName;
        return this;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("typeOfSecret", typeOfSecret).append("certName", certName).append("keyName", keyName).toString();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(certName).append(keyName).append(typeOfSecret).toHashCode();
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof SecretInfo) == false) {
            return false;
        }
        SecretInfo rhs = ((SecretInfo) other);
        return new EqualsBuilder().append(certName, rhs.certName).append(keyName, rhs.keyName).append(typeOfSecret, rhs.typeOfSecret).isEquals();
    }

}

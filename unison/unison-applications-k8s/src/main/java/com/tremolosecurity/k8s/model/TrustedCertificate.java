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

public class TrustedCertificate {

    @SerializedName("name")
    @Expose
    private String name;
    @SerializedName("pem_data")
    @Expose
    private String pemData;

    /**
     * No args constructor for use in serialization
     * 
     */
    public TrustedCertificate() {
    }

    /**
     * 
     * @param name
     * @param pemData
     */
    public TrustedCertificate(String name, String pemData) {
        super();
        this.name = name;
        this.pemData = pemData;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public TrustedCertificate withName(String name) {
        this.name = name;
        return this;
    }

    public String getPemData() {
        return pemData;
    }

    public void setPemData(String pemData) {
        this.pemData = pemData;
    }

    public TrustedCertificate withPemData(String pemData) {
        this.pemData = pemData;
        return this;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("name", name).append("pemData", pemData).toString();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(name).append(pemData).toHashCode();
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof TrustedCertificate) == false) {
            return false;
        }
        TrustedCertificate rhs = ((TrustedCertificate) other);
        return new EqualsBuilder().append(name, rhs.name).append(pemData, rhs.pemData).isEquals();
    }

}

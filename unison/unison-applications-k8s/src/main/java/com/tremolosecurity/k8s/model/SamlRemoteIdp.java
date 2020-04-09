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

public class SamlRemoteIdp {

    @SerializedName("source")
    @Expose
    private Source source;
    @SerializedName("mapping")
    @Expose
    private Mapping mapping;

    /**
     * No args constructor for use in serialization
     * 
     */
    public SamlRemoteIdp() {
    }

    /**
     * 
     * @param source
     * @param mapping
     */
    public SamlRemoteIdp(Source source, Mapping mapping) {
        super();
        this.source = source;
        this.mapping = mapping;
    }

    public Source getSource() {
        return source;
    }

    public void setSource(Source source) {
        this.source = source;
    }

    public SamlRemoteIdp withSource(Source source) {
        this.source = source;
        return this;
    }

    public Mapping getMapping() {
        return mapping;
    }

    public void setMapping(Mapping mapping) {
        this.mapping = mapping;
    }

    public SamlRemoteIdp withMapping(Mapping mapping) {
        this.mapping = mapping;
        return this;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("source", source).append("mapping", mapping).toString();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(source).append(mapping).toHashCode();
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof SamlRemoteIdp) == false) {
            return false;
        }
        SamlRemoteIdp rhs = ((SamlRemoteIdp) other);
        return new EqualsBuilder().append(source, rhs.source).append(mapping, rhs.mapping).isEquals();
    }

}

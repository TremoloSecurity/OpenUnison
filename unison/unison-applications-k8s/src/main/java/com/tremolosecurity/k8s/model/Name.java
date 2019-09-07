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

public class Name {

    @SerializedName("name")
    @Expose
    private String name;
    @SerializedName("env_var")
    @Expose
    private String envVar;

    /**
     * No args constructor for use in serialization
     * 
     */
    public Name() {
    }

    /**
     * 
     * @param name
     * @param envVar
     */
    public Name(String name, String envVar) {
        super();
        this.name = name;
        this.envVar = envVar;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Name withName(String name) {
        this.name = name;
        return this;
    }

    public String getEnvVar() {
        return envVar;
    }

    public void setEnvVar(String envVar) {
        this.envVar = envVar;
    }

    public Name withEnvVar(String envVar) {
        this.envVar = envVar;
        return this;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("name", name).append("envVar", envVar).toString();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(name).append(envVar).toHashCode();
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof Name) == false) {
            return false;
        }
        Name rhs = ((Name) other);
        return new EqualsBuilder().append(name, rhs.name).append(envVar, rhs.envVar).isEquals();
    }

}

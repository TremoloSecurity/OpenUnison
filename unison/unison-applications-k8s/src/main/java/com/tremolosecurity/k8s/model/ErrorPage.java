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

public class ErrorPage {

    @SerializedName("code")
    @Expose
    private long code;
    @SerializedName("location")
    @Expose
    private String location;

    /**
     * No args constructor for use in serialization
     * 
     */
    public ErrorPage() {
    }

    /**
     * 
     * @param location
     * @param code
     */
    public ErrorPage(long code, String location) {
        super();
        this.code = code;
        this.location = location;
    }

    public long getCode() {
        return code;
    }

    public void setCode(long code) {
        this.code = code;
    }

    public ErrorPage withCode(long code) {
        this.code = code;
        return this;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public ErrorPage withLocation(String location) {
        this.location = location;
        return this;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("code", code).append("location", location).toString();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(location).append(code).toHashCode();
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof ErrorPage) == false) {
            return false;
        }
        ErrorPage rhs = ((ErrorPage) other);
        return new EqualsBuilder().append(location, rhs.location).append(code, rhs.code).isEquals();
    }

}

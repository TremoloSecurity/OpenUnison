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

public class Openshift {

    @SerializedName("git")
    @Expose
    private Git git;
    @SerializedName("builder_image")
    @Expose
    private String builderImage;

    /**
     * No args constructor for use in serialization
     * 
     */
    public Openshift() {
    }

    /**
     * 
     * @param builderImage
     * @param git
     */
    public Openshift(Git git, String builderImage) {
        super();
        this.git = git;
        this.builderImage = builderImage;
    }

    public Git getGit() {
        return git;
    }

    public void setGit(Git git) {
        this.git = git;
    }

    public Openshift withGit(Git git) {
        this.git = git;
        return this;
    }

    public String getBuilderImage() {
        return builderImage;
    }

    public void setBuilderImage(String builderImage) {
        this.builderImage = builderImage;
    }

    public Openshift withBuilderImage(String builderImage) {
        this.builderImage = builderImage;
        return this;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("git", git).append("builderImage", builderImage).toString();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(builderImage).append(git).toHashCode();
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof Openshift) == false) {
            return false;
        }
        Openshift rhs = ((Openshift) other);
        return new EqualsBuilder().append(builderImage, rhs.builderImage).append(git, rhs.git).isEquals();
    }

}

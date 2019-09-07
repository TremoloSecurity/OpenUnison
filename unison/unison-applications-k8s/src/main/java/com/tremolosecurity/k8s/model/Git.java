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

public class Git {

    @SerializedName("repo")
    @Expose
    private String repo;
    @SerializedName("branch")
    @Expose
    private String branch;
    @SerializedName("dir")
    @Expose
    private String dir;

    /**
     * No args constructor for use in serialization
     * 
     */
    public Git() {
    }

    /**
     * 
     * @param dir
     * @param repo
     * @param branch
     */
    public Git(String repo, String branch, String dir) {
        super();
        this.repo = repo;
        this.branch = branch;
        this.dir = dir;
    }

    public String getRepo() {
        return repo;
    }

    public void setRepo(String repo) {
        this.repo = repo;
    }

    public Git withRepo(String repo) {
        this.repo = repo;
        return this;
    }

    public String getBranch() {
        return branch;
    }

    public void setBranch(String branch) {
        this.branch = branch;
    }

    public Git withBranch(String branch) {
        this.branch = branch;
        return this;
    }

    public String getDir() {
        return dir;
    }

    public void setDir(String dir) {
        this.dir = dir;
    }

    public Git withDir(String dir) {
        this.dir = dir;
        return this;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("repo", repo).append("branch", branch).append("dir", dir).toString();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(dir).append(repo).append(branch).toHashCode();
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof Git) == false) {
            return false;
        }
        Git rhs = ((Git) other);
        return new EqualsBuilder().append(dir, rhs.dir).append(repo, rhs.repo).append(branch, rhs.branch).isEquals();
    }

}

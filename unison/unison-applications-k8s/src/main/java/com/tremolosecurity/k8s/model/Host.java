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

public class Host {

    @SerializedName("names")
    @Expose
    private List<Name> names = new ArrayList<Name>();
    @SerializedName("ingress_name")
    @Expose
    private String ingressName;
    @SerializedName("secret_name")
    @Expose
    private String secretName;
    @SerializedName("node_selectors")
    @Expose
    private List<NodeSelector> nodeSelectors = new ArrayList<NodeSelector>();

    /**
     * No args constructor for use in serialization
     * 
     */
    public Host() {
    }

    /**
     * 
     * @param nodeSelectors
     * @param names
     * @param ingressName
     * @param secretName
     */
    public Host(List<Name> names, String ingressName, String secretName, List<NodeSelector> nodeSelectors) {
        super();
        this.names = names;
        this.ingressName = ingressName;
        this.secretName = secretName;
        this.nodeSelectors = nodeSelectors;
    }

    public List<Name> getNames() {
        return names;
    }

    public void setNames(List<Name> names) {
        this.names = names;
    }

    public Host withNames(List<Name> names) {
        this.names = names;
        return this;
    }

    public String getIngressName() {
        return ingressName;
    }

    public void setIngressName(String ingressName) {
        this.ingressName = ingressName;
    }

    public Host withIngressName(String ingressName) {
        this.ingressName = ingressName;
        return this;
    }

    public String getSecretName() {
        return secretName;
    }

    public void setSecretName(String secretName) {
        this.secretName = secretName;
    }

    public Host withSecretName(String secretName) {
        this.secretName = secretName;
        return this;
    }

    public List<NodeSelector> getNodeSelectors() {
        return nodeSelectors;
    }

    public void setNodeSelectors(List<NodeSelector> nodeSelectors) {
        this.nodeSelectors = nodeSelectors;
    }

    public Host withNodeSelectors(List<NodeSelector> nodeSelectors) {
        this.nodeSelectors = nodeSelectors;
        return this;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("names", names).append("ingressName", ingressName).append("secretName", secretName).append("nodeSelectors", nodeSelectors).toString();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(nodeSelectors).append(names).append(ingressName).append(secretName).toHashCode();
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof Host) == false) {
            return false;
        }
        Host rhs = ((Host) other);
        return new EqualsBuilder().append(nodeSelectors, rhs.nodeSelectors).append(names, rhs.names).append(ingressName, rhs.ingressName).append(secretName, rhs.secretName).isEquals();
    }

}

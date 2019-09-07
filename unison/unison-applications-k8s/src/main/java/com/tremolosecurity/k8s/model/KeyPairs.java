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

public class KeyPairs {

    @SerializedName("create_keypair_template")
    @Expose
    private List<CreateKeypairTemplate> createKeypairTemplate = new ArrayList<CreateKeypairTemplate>();
    @SerializedName("keys")
    @Expose
    private List<Key> keys = new ArrayList<Key>();

    /**
     * No args constructor for use in serialization
     * 
     */
    public KeyPairs() {
    }

    /**
     * 
     * @param keys
     * @param createKeypairTemplate
     */
    public KeyPairs(List<CreateKeypairTemplate> createKeypairTemplate, List<Key> keys) {
        super();
        this.createKeypairTemplate = createKeypairTemplate;
        this.keys = keys;
    }

    public List<CreateKeypairTemplate> getCreateKeypairTemplate() {
        return createKeypairTemplate;
    }

    public void setCreateKeypairTemplate(List<CreateKeypairTemplate> createKeypairTemplate) {
        this.createKeypairTemplate = createKeypairTemplate;
    }

    public KeyPairs withCreateKeypairTemplate(List<CreateKeypairTemplate> createKeypairTemplate) {
        this.createKeypairTemplate = createKeypairTemplate;
        return this;
    }

    public List<Key> getKeys() {
        return keys;
    }

    public void setKeys(List<Key> keys) {
        this.keys = keys;
    }

    public KeyPairs withKeys(List<Key> keys) {
        this.keys = keys;
        return this;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("createKeypairTemplate", createKeypairTemplate).append("keys", keys).toString();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(keys).append(createKeypairTemplate).toHashCode();
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof KeyPairs) == false) {
            return false;
        }
        KeyPairs rhs = ((KeyPairs) other);
        return new EqualsBuilder().append(keys, rhs.keys).append(createKeypairTemplate, rhs.createKeypairTemplate).isEquals();
    }

}

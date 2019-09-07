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

import java.util.HashMap;
import java.util.Map;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.apache.commons.lang.builder.ToStringBuilder;

public class Key {

    @SerializedName("name")
    @Expose
    private String name;
    @SerializedName("tls_secret_name")
    @Expose
    private String tlsSecretName;
    @SerializedName("import_into_ks")
    @Expose
    private Key.ImportIntoKs importIntoKs;
    @SerializedName("replace_if_exists")
    @Expose
    private boolean replaceIfExists;
    @SerializedName("create_data")
    @Expose
    private CreateData createData;

    /**
     * No args constructor for use in serialization
     * 
     */
    public Key() {
    }

    /**
     * 
     * @param createData
     * @param name
     * @param tlsSecretName
     * @param replaceIfExists
     * @param importIntoKs
     */
    public Key(String name, String tlsSecretName, Key.ImportIntoKs importIntoKs, boolean replaceIfExists, CreateData createData) {
        super();
        this.name = name;
        this.tlsSecretName = tlsSecretName;
        this.importIntoKs = importIntoKs;
        this.replaceIfExists = replaceIfExists;
        this.createData = createData;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Key withName(String name) {
        this.name = name;
        return this;
    }

    public String getTlsSecretName() {
        return tlsSecretName;
    }

    public void setTlsSecretName(String tlsSecretName) {
        this.tlsSecretName = tlsSecretName;
    }

    public Key withTlsSecretName(String tlsSecretName) {
        this.tlsSecretName = tlsSecretName;
        return this;
    }

    public Key.ImportIntoKs getImportIntoKs() {
        return importIntoKs;
    }

    public void setImportIntoKs(Key.ImportIntoKs importIntoKs) {
        this.importIntoKs = importIntoKs;
    }

    public Key withImportIntoKs(Key.ImportIntoKs importIntoKs) {
        this.importIntoKs = importIntoKs;
        return this;
    }

    public boolean isReplaceIfExists() {
        return replaceIfExists;
    }

    public void setReplaceIfExists(boolean replaceIfExists) {
        this.replaceIfExists = replaceIfExists;
    }

    public Key withReplaceIfExists(boolean replaceIfExists) {
        this.replaceIfExists = replaceIfExists;
        return this;
    }

    public CreateData getCreateData() {
        return createData;
    }

    public void setCreateData(CreateData createData) {
        this.createData = createData;
    }

    public Key withCreateData(CreateData createData) {
        this.createData = createData;
        return this;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("name", name).append("tlsSecretName", tlsSecretName).append("importIntoKs", importIntoKs).append("replaceIfExists", replaceIfExists).append("createData", createData).toString();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(createData).append(name).append(tlsSecretName).append(replaceIfExists).append(importIntoKs).toHashCode();
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof Key) == false) {
            return false;
        }
        Key rhs = ((Key) other);
        return new EqualsBuilder().append(createData, rhs.createData).append(name, rhs.name).append(tlsSecretName, rhs.tlsSecretName).append(replaceIfExists, rhs.replaceIfExists).append(importIntoKs, rhs.importIntoKs).isEquals();
    }

    public enum ImportIntoKs {

        @SerializedName("keypair")
        KEYPAIR("keypair"),
        @SerializedName("certificate")
        CERTIFICATE("certificate"),
        @SerializedName("none")
        NONE("none");
        private final String value;
        private final static Map<String, Key.ImportIntoKs> CONSTANTS = new HashMap<String, Key.ImportIntoKs>();

        static {
            for (Key.ImportIntoKs c: values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private ImportIntoKs(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return this.value;
        }

        public String value() {
            return this.value;
        }

        public static Key.ImportIntoKs fromValue(String value) {
            Key.ImportIntoKs constant = CONSTANTS.get(value);
            if (constant == null) {
                throw new IllegalArgumentException(value);
            } else {
                return constant;
            }
        }

    }

}

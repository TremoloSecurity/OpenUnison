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

public class KeyStore {

    @SerializedName("update_controller")
    @Expose
    private UpdateController updateController;
    @SerializedName("static_keys")
    @Expose
    private List<StaticKey> staticKeys = new ArrayList<StaticKey>();
    @SerializedName("trusted_certificates")
    @Expose
    private List<TrustedCertificate> trustedCertificates = new ArrayList<TrustedCertificate>();
    @SerializedName("key_pairs")
    @Expose
    private KeyPairs keyPairs;

    /**
     * No args constructor for use in serialization
     * 
     */
    public KeyStore() {
    }

    /**
     * 
     * @param staticKeys
     * @param trustedCertificates
     * @param keyPairs
     * @param updateController
     */
    public KeyStore(UpdateController updateController, List<StaticKey> staticKeys, List<TrustedCertificate> trustedCertificates, KeyPairs keyPairs) {
        super();
        this.updateController = updateController;
        this.staticKeys = staticKeys;
        this.trustedCertificates = trustedCertificates;
        this.keyPairs = keyPairs;
    }

    public UpdateController getUpdateController() {
        return updateController;
    }

    public void setUpdateController(UpdateController updateController) {
        this.updateController = updateController;
    }

    public KeyStore withUpdateController(UpdateController updateController) {
        this.updateController = updateController;
        return this;
    }

    public List<StaticKey> getStaticKeys() {
        return staticKeys;
    }

    public void setStaticKeys(List<StaticKey> staticKeys) {
        this.staticKeys = staticKeys;
    }

    public KeyStore withStaticKeys(List<StaticKey> staticKeys) {
        this.staticKeys = staticKeys;
        return this;
    }

    public List<TrustedCertificate> getTrustedCertificates() {
        return trustedCertificates;
    }

    public void setTrustedCertificates(List<TrustedCertificate> trustedCertificates) {
        this.trustedCertificates = trustedCertificates;
    }

    public KeyStore withTrustedCertificates(List<TrustedCertificate> trustedCertificates) {
        this.trustedCertificates = trustedCertificates;
        return this;
    }

    public KeyPairs getKeyPairs() {
        return keyPairs;
    }

    public void setKeyPairs(KeyPairs keyPairs) {
        this.keyPairs = keyPairs;
    }

    public KeyStore withKeyPairs(KeyPairs keyPairs) {
        this.keyPairs = keyPairs;
        return this;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("updateController", updateController).append("staticKeys", staticKeys).append("trustedCertificates", trustedCertificates).append("keyPairs", keyPairs).toString();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(staticKeys).append(trustedCertificates).append(keyPairs).append(updateController).toHashCode();
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof KeyStore) == false) {
            return false;
        }
        KeyStore rhs = ((KeyStore) other);
        return new EqualsBuilder().append(staticKeys, rhs.staticKeys).append(trustedCertificates, rhs.trustedCertificates).append(keyPairs, rhs.keyPairs).append(updateController, rhs.updateController).isEquals();
    }

}

/*
 * Copyright 2025 Tremolo Security, Inc.
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
 */

package com.tremolosecurity.proxy.auth.webauthn;

import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.server.ServerProperty;

import java.util.Set;

public class ServerPropertyHolder {
    Set<Origin> origins;
    byte[] tokenBindingId;
    String rpId;
    Challenge challenge;

    public ServerPropertyHolder() {

    }

    public void loadFromServerProperty(ServerProperty serverProperty) {
        origins = serverProperty.getOrigins();
        tokenBindingId = serverProperty.getTokenBindingId();
        rpId = serverProperty.getRpId();
        challenge = serverProperty.getChallenge();
    }

    public ServerProperty getServerProperty() {
        return new ServerProperty(origins,rpId,challenge,tokenBindingId);
    }

    public Set<Origin> getOrigins() {
        return origins;
    }

    public void setOrigins(Set<Origin> origins) {
        this.origins = origins;
    }

    public byte[] getTokenBindingId() {
        return tokenBindingId;
    }

    public void setTokenBindingId(byte[] tokenBindingId) {
        this.tokenBindingId = tokenBindingId;
    }

    public String getRpId() {
        return rpId;
    }

    public void setRpId(String rpId) {
        this.rpId = rpId;
    }

    public Challenge getChallenge() {
        return challenge;
    }

    public void setChallenge(Challenge challenge) {
        this.challenge = challenge;
    }
}

/*******************************************************************************
 * Copyright (c) 2024 Tremolo Security, Inc.
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
package com.tremolosecurity.unison.openshiftv3.cache;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class K8sApiGroupVersion {
    String version;
    Map<String,K8sApi> apis;
    boolean v1;
    

    public K8sApiGroupVersion(String version) {
        this.version = version;
        this.apis = new HashMap<String,K8sApi>();
        this.v1 = false;
    }

    public K8sApiGroupVersion() {
        this.version = "";
        this.v1 = true;
        this.apis = new HashMap<String,K8sApi>();
    }

    public boolean isV1() {
        return v1;
    }
    

    public Map<String,K8sApi> getApis() {
        return apis;
    }

    public String getVersion() {
        return version;
    }

}

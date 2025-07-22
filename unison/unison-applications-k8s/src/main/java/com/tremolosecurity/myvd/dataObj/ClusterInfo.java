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

package com.tremolosecurity.myvd.dataObj;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ClusterInfo {
    String name;
    List<String> groups;
    Map<String,Map<String,Integer>> namespaces;

    public ClusterInfo(String name) {
        this.name = name;
        this.groups = new ArrayList<String>();
        this.namespaces = new HashMap<String, Map<String, Integer>>();
    }

    public List<String> getGroups() {
        return groups;
    }

    public Map<String,Map<String,Integer>> getNamespaces() {
        return namespaces;
    }
}

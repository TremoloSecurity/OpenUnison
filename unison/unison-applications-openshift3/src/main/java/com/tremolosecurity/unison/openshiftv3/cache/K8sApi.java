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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpClient.Version;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class K8sApi {
    String name;
    String singularName;
    String kind;
    boolean namespaced;

    K8sApiGroupVersion version;

    public K8sApi(String name, String singularName, String kind, boolean namespaced,K8sApiGroupVersion version) {
        this.name = name;
        this.singularName = singularName;
        this.kind = kind;
        this.namespaced = namespaced;
        this.version = version;
    }

    public String getName() {
        return name;
    }

    public String getKind() {
        return kind;
    }

    public String getSingularName() {
        return singularName;
    }

    public boolean isNamespaced() {
        return namespaced;
    }

    public void loadObjectsForNamespace(String namespace,String url,Map<String,Map<String,JSONObject>> objects) throws URISyntaxException, IOException, InterruptedException, ParseException {
        String path;

        if (this.version.isV1()) {
            path = "/api/v1/namespaces/" + namespace + "/" + this.name;
        } else {
            path = "/apis/" + version.getVersion() + "/namespaces/" + namespace + "/" + this.name;
        }

        System.out.println(path);

        HttpRequest req = HttpRequest.newBuilder()
         .uri(new URI(url + path))
         .GET()
         .version(Version.HTTP_1_1)
         .build();

        Map<String,JSONObject> currentObjects = objects.get(this.name);

        if (currentObjects == null) {
            currentObjects = new HashMap<String,JSONObject>();
            objects.put(this.name, currentObjects);
        }

        HttpResponse<String> resp = HttpClient.newHttpClient().send(req, BodyHandlers.ofString());

        JSONArray items = (JSONArray) ((JSONObject)new JSONParser().parse(resp.body())).get("items");

        if (items != null) {
            for (Object o : items) {
                JSONObject item = (JSONObject) o;

                String name = (String) ((JSONObject) item.get("metadata")).get("name");
                if (! currentObjects.containsKey(name)) {
                    JSONObject metadata = (JSONObject) item.get("metadata");
                    metadata.remove("generation");
                    metadata.remove("uid");
                    metadata.remove("managedFields");
                    metadata.remove("resourceVersion");
                    metadata.remove("creationTimestamp");
                    
                    currentObjects.put(name, item);
                }

                if (item.get("kind") == null) {
                    item.put("kind", this.kind);
                }

                if (item.get("apiVersion") == null) {
                    if (this.version.isV1()) {
                        item.put("apiVersion","v1");
                    } else {
                        item.put("apiVersion",this.version.getVersion());
                    }
                }

                item.remove("status");
            }
        }


        String json = resp.body();
        System.out.println(json);
    }
}

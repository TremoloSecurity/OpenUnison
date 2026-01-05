/*
 * Copyright 2026 Tremolo Security, Inc.
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

package com.tremolosecurity.provisioning.testing;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.*;
import com.tremolosecurity.openunison.util.config.OpenUnisonConfigLoader;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningTargetImpl;
import com.tremolosecurity.provisioning.core.UserStoreProvider;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tremolosecurity.provisioning.core.UserStoreProviderWithMetadata;
import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.saml.Attribute;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;


public class LoadTargetFromYAML {

    public static UserStoreProvider loadFromYAML(ConfigManager cfgMgr, String yamlFile, Map<String,String> props, Map<String, Map<String,String>> secrets) throws Exception {

        props.keySet().forEach(key -> {
            System.setProperty(key, props.get(key));
        });

        String json = convertYamlToJson(Path.of(yamlFile));
        JSONObject root = (JSONObject) new JSONParser().parse(json);

        System.out.println(json);

        TargetType target = new TargetType();
        target.setName(((JSONObject)root.get("metadata")).get("name").toString());
        target.setParams(new TargetConfigType());



        JSONObject spec = (JSONObject) root.get("spec");




        StringBuffer b = new StringBuffer();
        b.setLength(0);
        OpenUnisonConfigLoader.integrateIncludes(b,  (String)spec.get("className"));

        target.setClassName(b.toString());
        JSONArray params = (JSONArray) spec.get("params");
        for (Object o : params) {
            JSONObject param = (JSONObject) o;
            ParamType pt = new ParamType();
            b.setLength(0);
            OpenUnisonConfigLoader.integrateIncludes(b,(String) param.get("name")  );
            pt.setName(b.toString());
            b.setLength(0);
            OpenUnisonConfigLoader.integrateIncludes(b,(String) param.get("value")  );
            pt.setValue(b.toString());
            target.getParams().getParam().add(pt);
        }


        JSONArray secretParams = (JSONArray) spec.get("secretParams");

        for (Object o : secretParams) {
            JSONObject secretParam = (JSONObject) o;
            String paramName = (String) secretParam.get("name");
            String secretName = (String) secretParam.get("secretName");
            String secretKey = (String) secretParam.get("secretKey");

            String secretValue = secrets.get(secretName).get(secretKey);
            ParamType pt = new ParamType();
            pt.setName(paramName);
            pt.setValue(secretValue);
            target.getParams().getParam().add(pt);

        }


        JSONArray attrs = (JSONArray) spec.get("targetAttributes");
        for (Object o : attrs) {
            JSONObject attr = (JSONObject) o;
            TargetAttributeType ta = new TargetAttributeType();
            b.setLength(0);
            OpenUnisonConfigLoader.integrateIncludes(b,(String) attr.get("name"));
            ta.setName(b.toString());
            b.setLength(0);
            OpenUnisonConfigLoader.integrateIncludes(b,(String) attr.get("source"));
            ta.setSource(b.toString());
            ta.setSourceType((String) attr.get("sourceType"));
            ta.setTargetType((String) attr.get("targetType"));
            target.getTargetAttribute().add(ta);
        }



        return createTarget(cfgMgr, target);
    }


    private static String convertYamlToJson(Path yamlPath) throws Exception {
        Yaml yaml = new Yaml();

        try (InputStream in = Files.newInputStream(yamlPath)) {
            Object yamlData = yaml.load(in);

            ObjectMapper mapper = new ObjectMapper();
            return mapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(yamlData);
        }
    }

    private static UserStoreProvider createTarget(ConfigManager cfgMgr, TargetType targetCfg) throws ProvisioningException {

        HashMap<String, Attribute> cfg = new HashMap<String,Attribute>();
        Iterator<ParamType> params =  targetCfg.getParams().getParam().iterator();
        while (params.hasNext()) {
            ParamType param = params.next();
            Attribute attr = cfg.get(param.getName());

            if (attr == null) {
                attr = new Attribute(param.getName());
                cfg.put(attr.getName(), attr);
            }

            attr.getValues().add(param.getValue());
        }


        UserStoreProvider provider = null;


        try {
            provider = (UserStoreProvider) Class.forName(targetCfg.getClassName()).newInstance();
        } catch (Exception e) {
            throw new ProvisioningException("Could not initialize target " + targetCfg.getName(),e);
        }

        MapIdentity mapper = new MapIdentity(targetCfg);


        if (provider instanceof UserStoreProviderWithMetadata) {
            UserStoreProviderWithMetadata providerWithMetaData = (UserStoreProviderWithMetadata) provider;
            if (targetCfg.getAnnotation() != null && providerWithMetaData.getAnnotations() != null) {
                for (NameValue nv : targetCfg.getAnnotation()) {
                    providerWithMetaData.getAnnotations().put(nv.getName(), nv.getValue());
                }
            }

            if (targetCfg.getLabel() != null && providerWithMetaData.getLabels() != null) {
                for (NameValue nv : targetCfg.getLabel()) {
                    providerWithMetaData.getLabels().put(nv.getName(), nv.getValue());
                }
            }
        }


        provider.init(cfg,cfgMgr,targetCfg.getName());

        return provider;

    }
}

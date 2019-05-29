/*
Copyright 2018 Tremolo Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package com.tremolosecurity.prometheus.sdk;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.prometheus.aggregate.JMSPull;
import com.tremolosecurity.prometheus.aggregate.PullListener;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.saml.Attribute;
import java.io.Writer;
import java.util.HashMap;

public interface AdditionalMetrics {
    public void init(PullListener pullListener,ConfigManager cfg,HashMap<String, Attribute> attributes);

    public void init(JMSPull pull,ConfigManager cfg,HttpFilterConfig httpCfg);

    public void addMetrics(Writer writer);
}
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

package com.tremolosecurity.prometheus.filter;

import com.tremolosecurity.prometheus.sdk.LocalMetrics;
import com.tremolosecurity.proxy.SessionManager;

import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.server.GlobalEntries;
import edu.emory.mathcs.backport.java.util.Arrays;
import io.prometheus.client.Collector;
import io.prometheus.client.Collector.MetricFamilySamples;
import io.prometheus.client.CollectorRegistry;
import io.prometheus.client.Gauge;
import io.prometheus.client.exporter.common.TextFormat;
import io.prometheus.client.hotspot.ClassLoadingExports;
import io.prometheus.client.hotspot.DefaultExports;
import io.prometheus.client.hotspot.GarbageCollectorExports;
import io.prometheus.client.hotspot.MemoryPoolsExports;
import io.prometheus.client.hotspot.StandardExports;
import io.prometheus.client.hotspot.ThreadExports;
import io.prometheus.client.hotspot.VersionInfoExports;
import java.util.Set;
import java.io.IOException;
import java.io.Writer;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

public class MetricsFilter implements HttpFilter {

  static Logger logger = Logger.getLogger(MetricsFilter.class.getName());



  CollectorRegistry registry;
  Gauge sessionsGauge;

  LocalMetrics localMetrics;
  
  @Override
  public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain) throws Exception {

    SessionManager sessionMgr = (SessionManager) GlobalEntries.getGlobalEntries().getConfigManager().getContext()
        .getAttribute(ProxyConstants.TREMOLO_SESSION_MANAGER);

    sessionsGauge.set(sessionMgr.getSessions().size());

    if (this.localMetrics != null) {
    	this.localMetrics.addMetrics(request, response, chain);
    }
    
    response.setStatus(HttpServletResponse.SC_OK);
    response.setContentType(TextFormat.CONTENT_TYPE_004);

    Enumeration<MetricFamilySamples> mfs = registry.filteredMetricFamilySamples(parse(request.getServletRequest()));

    Writer writer = response.getWriter();
    try {
      TextFormat.write004(writer, mfs);
      writer.flush();
    } finally {

    }

  }

  @Override
  public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
      byte[] arg3, int arg4) throws Exception {

  }

  @Override
  public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
      StringBuffer arg3) throws Exception {

  }

  @Override
  public void initFilter(HttpFilterConfig config) throws Exception {
    
    registry = new CollectorRegistry();
    sessionsGauge = Gauge.build().name("active_sessions").help("The number of active sessions").register(registry);
    new StandardExports().register(registry);
    new MemoryPoolsExports().register(registry);
    new GarbageCollectorExports().register(registry);
    new ThreadExports().register(registry);
    new ClassLoadingExports().register(registry);
    new VersionInfoExports().register(registry);

    
    if (config.getAttribute("localMetricsClassName") != null) {
    	this.localMetrics = (LocalMetrics) Class.forName(config.getAttribute("localMetricsClassName").getValues().get(0)).newInstance();
    	this.localMetrics.registerMetrics(registry,config);
    } else {
    	this.localMetrics = null;
    }
    


    
    
  }

  private Set<String> parse(HttpServletRequest req) {
    String[] includedParam = req.getParameterValues("name[]");
    if (includedParam == null) {
      return Collections.emptySet();
    } else {
      return new HashSet<String>(Arrays.asList(includedParam));
    }
  }

  private static void writeEscapedHelp(Writer writer, String s) throws IOException {
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
      case '\\':
        writer.append("\\\\");
        break;
      case '\n':
        writer.append("\\n");
        break;
      default:
        writer.append(c);
      }
    }
  }

  

  private static void writeEscapedLabelValue(Writer writer, String s) throws IOException {
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
      case '\\':
        writer.append("\\\\");
        break;
      case '\"':
        writer.append("\\\"");
        break;
      case '\n':
        writer.append("\\n");
        break;
      default:
        writer.append(c);
      }
    }
  }

  private static String typeString(Collector.Type t) {
    switch (t) {
    case GAUGE:
      return "gauge";
    case COUNTER:
      return "counter";
    case SUMMARY:
      return "summary";
    case HISTOGRAM:
      return "histogram";
    default:
      return "untyped";
    }
  }

}
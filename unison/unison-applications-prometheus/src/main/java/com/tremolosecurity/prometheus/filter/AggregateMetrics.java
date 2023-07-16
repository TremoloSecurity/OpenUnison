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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Writer;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.util.EntityUtils;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.prometheus.aggregate.PullMetrics;
import com.tremolosecurity.prometheus.data.AggregateURL;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import io.prometheus.client.exporter.common.TextFormat;

public class AggregateMetrics implements HttpFilter {

    PullMetrics pull;
	private ConfigManager cfg;

	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain) throws Exception {
		response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(TextFormat.CONTENT_TYPE_004);

        PrintWriter writer = response.getWriter();

        

        //writer.flush();
	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain, byte[] arg3,
			int arg4) throws Exception {
		
	}

	@Override
	public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer arg3) throws Exception {
		
	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
        Gson gson = new Gson();
        Type listType = new TypeToken<ArrayList<AggregateURL>>(){}.getType();
        
        String urlList = config.getAttribute("urls").getValues().get(0);
        this.pull = new PullMetrics((List<AggregateURL>)gson.fromJson(urlList, listType),config.getConfigManager());

        this.cfg = config.getConfigManager();
    }
    
    

}
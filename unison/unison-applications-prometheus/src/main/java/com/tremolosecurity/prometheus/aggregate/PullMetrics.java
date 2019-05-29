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

package com.tremolosecurity.prometheus.aggregate;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.prometheus.data.AggregateURL;
import com.tremolosecurity.saml.Attribute;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Writer;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;

public class PullMetrics {
    static Logger logger = org.apache.logging.log4j.LogManager.getLogger(PullMetrics.class.getName());

    List<AggregateURL> urls;
    ConfigManager cfg;

    public PullMetrics(List<AggregateURL> urls,ConfigManager cfg) {
        this.urls = urls;
        this.cfg = cfg;
    }

    public void writeMetrics(Writer writer) throws ClientProtocolException, IOException {
        BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(cfg.getHttpClientSocketRegistry());
        CloseableHttpClient httpclient = HttpClients.custom().setConnectionManager(bhcm).setDefaultRequestConfig(cfg.getGlobalHttpClientConfig()).build();
        try {
            
            
            for (AggregateURL url : this.urls) {
                HttpGet method = new HttpGet(url.getUrl());

                if (url.getTimeout() > 0) {
                    RequestConfig requestConfig = RequestConfig.custom()
                    .setSocketTimeout(url.getTimeout())
                    .setConnectTimeout(url.getTimeout())
                    .setConnectionRequestTimeout(url.getTimeout())
                    .build();

                    method.setConfig(requestConfig);
                }

                if (url.isLastMileAuhentication()) {
                    DateTime notBefore = new DateTime();
                    notBefore = notBefore.minusSeconds(url.getLastMileTimeSkewSeconds());
                    DateTime notAfter = new DateTime();
                    notAfter = notAfter.plusSeconds(url.getLastMileTimeSkewSeconds());
                    
                    com.tremolosecurity.lastmile.LastMile lastmile = null;
                    
                    try {
                        lastmile = new com.tremolosecurity.lastmile.LastMile(new URL(url.getUrl()).getPath(),notBefore,notAfter,0,"oauth2");
                        
                    } catch (URISyntaxException e) {
                        logger.warn("Could not generate lastmile",e);
                        writeFailure(writer, url);
                        continue;
                    }
                    
                    Attribute attrib = new Attribute(url.getLastMileUidAttributeName(),url.getLastMileUid());
                    lastmile.getAttributes().add(attrib);
                    String encryptedXML = null;
                    
                    try {
                        encryptedXML = lastmile.generateLastMileToken(cfg.getSecretKey(url.getLastMileKeyName()));
                    } catch (Exception e) {
                        logger.warn("Could not generate lastmile",e);
                        writeFailure(writer, url);
                        continue;
                    }
                    
                    StringBuffer header = new StringBuffer();
                    header.append("Bearer " ).append(encryptedXML);
                    method.addHeader("Authorization", header.toString());
                }

                long beginTime=0;
                long endTime = 0;
                HttpResponse resp = null;
                try {
                    beginTime = System.currentTimeMillis();
                    resp = httpclient.execute(method);
                    endTime = System.currentTimeMillis();
                } catch (Throwable t) {
                    logger.error("Could not pull metrics from " + url.getUrl(),t);
                    
                }

                if (url.isInjectIpAndCluster()) {
                    
                    if (resp == null || resp.getStatusLine().getStatusCode() != 200) {
                        writeFailure(writer, url);
                    } else {
                        pullUrlResults(writer, url, resp,endTime-beginTime);
                    }


                    
                } else {
                    writer.write(EntityUtils.toString(resp.getEntity())); 
                }

                

                method.abort();
                
                writer.write('\n');
            }

            writer.flush();
            
        } finally {
            httpclient.close();
            bhcm.shutdown();
        }
    }

	private void writeFailure(Writer writer, AggregateURL url) throws IOException {
		writer.write("# HELP remote_up Determines if the system is alive or not\n");
                        writer.write("# TYPE remote_up gauge\n");
                        writer.write("remote_up");
                        writer.write("{");
                        writer.write(url.getClusterLabel());
                        writer.write("=\"");
                        writeEscapedLabelValue(writer, url.getCluster());
                        writer.write("\",");
                        writer.write(url.getIpLabel());
                        writer.write("=\"");
                        writeEscapedLabelValue(writer, url.getIpAddress());
                        writer.write("\"} ");
                        writer.write("0.0");
                        writer.write('\n');
	}

	private void pullUrlResults(Writer writer, AggregateURL url, HttpResponse resp,long runTimeMillis) throws IOException {
		BufferedReader in = new BufferedReader(new InputStreamReader(resp.getEntity().getContent()));
                    String line = null;
                    while ((line = in.readLine()) != null) {
                        if (line.charAt(0) == '#') {
                            writer.write(line);
                            writer.write('\n');
                        } else {
                            String name = line.substring(0,line.lastIndexOf(' '));
                            String value = line.substring(line.lastIndexOf(' ') + 1);
                            String newName = name.substring(0,name.length() - 1);
                            if (name.endsWith("}")) {
                                writer.write(newName);
                                if (! newName.endsWith(",")) {
                                    writer.write(',');
                                }
                                writer.write(url.getClusterLabel());
                                writer.write("=\"");
                                writeEscapedLabelValue(writer, url.getCluster());
                                writer.write("\",");
                                writer.write(url.getIpLabel());
                                writer.write("=\"");
                                writeEscapedLabelValue(writer, url.getIpAddress());
                                writer.write("\"} ");
                                writer.write(value);
                                writer.write('\n');
                            } else {
                                writer.write(name);

                                writer.write("{");
                                writer.write(url.getClusterLabel());
                                writer.write("=\"");
                                writeEscapedLabelValue(writer, url.getCluster());
                                writer.write("\",");
                                writer.write(url.getIpLabel());
                                writer.write("=\"");
                                writeEscapedLabelValue(writer, url.getIpAddress());
                                writer.write("\"} ");
                                writer.write(value);
                                writer.write('\n');
                            }
                        }
                    }
                    writer.write("# HELP remote_up Determines if the system is alive or not\n");
                    writer.write("# TYPE remote_up gauge\n");
                    writer.write("remote_up");
                    writer.write("{");
                    writer.write(url.getClusterLabel());
                    writer.write("=\"");
                    writeEscapedLabelValue(writer, url.getCluster());
                    writer.write("\",");
                    writer.write(url.getIpLabel());
                    writer.write("=\"");
                    writeEscapedLabelValue(writer, url.getIpAddress());
                    writer.write("\"} ");
                    writer.write("1.0");
                    writer.write('\n');

                    writer.write("# HELP unison_scrape_request_time Determines how long in milliseconds the probe took\n");
                    writer.write("# TYPE unison_scrape_request_time gauge\n");
                    writer.write("unison_scrape_request_time");
                    writer.write("{");
                    writer.write(url.getClusterLabel());
                    writer.write("=\"");
                    writeEscapedLabelValue(writer, url.getCluster());
                    writer.write("\",");
                    writer.write(url.getIpLabel());
                    writer.write("=\"");
                    writeEscapedLabelValue(writer, url.getIpAddress());
                    writer.write("\"} ");
                    writeEscapedLabelValue(writer, Double.toString(runTimeMillis));
                    writer.write('\n');
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
}
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

package com.tremolosecurity.prometheus.data;


public class AggregateURL {
    String url;
    String cluster;
    String ipAddress;
    String clusterLabel;
    String ipLabel;

    boolean lastMileAuthentication;
    String lastMileKeyName;
    String lastMileUid;
    String lastMileUidAttributeName;
    boolean injectIpAndCluster;

    int timeout;
    int lastMileTimeSkewSeconds;

    public int getLastMileTimeSkewSeconds() {
        return this.lastMileTimeSkewSeconds;
    }

    public void setLastMileTimeSkewSeconds(int val) {
        this.lastMileTimeSkewSeconds = val;
    }


    public void setLastMileAttributeName(String val) {
        this.lastMileUidAttributeName = val;
    }

    public String getLastMileUidAttributeName() {
        return this.lastMileUidAttributeName;
    }

    public String getLastMileUid() {
        return this.lastMileUid;
    }

    public void setLastMileUid(String uid) {
        this.lastMileUid = uid;
    }

    public String getLastMileKeyName() {
        return this.lastMileKeyName;
    }

    public void setLastMileKeyName(String name) {
        this.lastMileKeyName = name;
    }

    public boolean isLastMileAuhentication() {
        return this.lastMileAuthentication;
    }

    public void setLastMileAuthentication(boolean lm) {
        this.lastMileAuthentication = lm;
    }

    public int getTimeout() {
        return this.timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public String getIpLabel() { 
        return this.ipLabel;
    }

    public void setIpLabel(String ipLabel) {
        this.ipLabel = ipLabel;
    }

    public String getClusterLabel() {
        return this.clusterLabel;
    }

    public void setClusterLabel(String clusterLabel) {
        this.clusterLabel = clusterLabel;
    }

    public boolean isInjectIpAndCluster() {
        return this.injectIpAndCluster;
    }

    public void setIsInjectIpAndCluster(boolean injectIpAndCluster) {
        this.injectIpAndCluster = injectIpAndCluster;
    }

    public String getUrl() {
        return this.url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getCluster() {
        return this.cluster;
    }

    public void setCluster(String cluster) {
        this.cluster = cluster;
    }

    public String getIpAddress() {
        return this.ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }
}
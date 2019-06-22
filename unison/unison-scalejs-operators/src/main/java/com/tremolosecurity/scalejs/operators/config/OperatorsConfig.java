//    Copyright 2018 Tremolo Security, Inc.
// 
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
// 
//        http://www.apache.org/licenses/LICENSE-2.0
// 
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package com.tremolosecurity.scalejs.operators.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * OperatorsConfig
 */
public class OperatorsConfig {

    List<String> searchBases;
    List<AttributeConfig> searchableAttributes;
    List<AttributeConfig> resultsAttributes;
    

    transient Map<String,String> baseLabelToDN;
    

    String scaleJsMainUri;

    String homeUrl;


    public OperatorsConfig() {
        this.searchBases = new ArrayList<String>();
        this.searchableAttributes = new ArrayList<AttributeConfig>();
        this.resultsAttributes = new ArrayList<AttributeConfig>();
        this.baseLabelToDN = new HashMap<String,String>();
        
    }

    /**
     * @return the baseLabelToDN
     */
    public Map<String, String> getBaseLabelToDN() {
        return baseLabelToDN;
    }


    /**
     * @return the resultsAttributes
     */
    public List<AttributeConfig> getResultsAttributes() {
        return resultsAttributes;
    }

    /**
     * @return the scaleJsMainUri
     */
    public String getScaleJsMainUri() {
        return scaleJsMainUri;
    }
    /**
     * @return the searchableAttributes
     */
    public List<AttributeConfig> getSearchableAttributes() {
        return searchableAttributes;
    }
    /**
     * @return the searchBases
     */
    public List<String> getSearchBases() {
        return searchBases;
    }
    /**
     * @param baseLabelToDN the baseLabelToDN to set
     */
    public void setBaseLabelToDN(Map<String, String> baseLabelToDN) {
        this.baseLabelToDN = baseLabelToDN;
    }

    /**
     * @param resultsAttributes the resultsAttributes to set
     */
    public void setResultsAttributes(List<AttributeConfig> resultsAttributes) {
        this.resultsAttributes = resultsAttributes;
    }
    /**
     * @param scaleJsMainUri the scaleJsMainUri to set
     */
    public void setScaleJsMainUri(String scaleJsMainUri) {
        this.scaleJsMainUri = scaleJsMainUri;
    }
    /**
     * @param searchableAttributes the searchableAttributes to set
     */
    public void setSearchableAttributes(List<AttributeConfig> searchableAttributes) {
        this.searchableAttributes = searchableAttributes;
    }
    /**
     * @param searchBases the searchBases to set
     */
    public void setSearchBases(List<String> searchBases) {
        this.searchBases = searchBases;
    }

    /**
     * @return the homeUrl
     */
    public String getHomeUrl() {
        return homeUrl;
    }

    /**
     * @param homeUrl the homeUrl to set
     */
    public void setHomeUrl(String homeUrl) {
        this.homeUrl = homeUrl;
    }



}
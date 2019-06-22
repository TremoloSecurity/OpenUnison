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

package com.tremolosecurity.scalejs.operators.data;

import java.util.List;

import com.tremolosecurity.scalejs.operators.config.AttributeConfig;

/**
 * OpsSearch
 */
public class OpsSearch {

    String base;
    List<AttributeConfig> toSearch;

    public OpsSearch() {

    }

    /**
     * @return the base
     */
    public String getBase() {
        return base;
    }
    /**
     * @param base the base to set
     */
    public void setBase(String base) {
        this.base = base;
    }
    /**
     * @return the toSearch
     */
    public List<AttributeConfig> getToSearch() {
        return toSearch;
    }

    /**
     * @param toSearch the toSearch to set
     */
    public void setToSearch(List<AttributeConfig> toSearch) {
        this.toSearch = toSearch;
    }

}
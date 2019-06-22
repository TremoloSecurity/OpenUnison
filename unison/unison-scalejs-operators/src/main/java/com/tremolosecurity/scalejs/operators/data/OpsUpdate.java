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

import com.tremolosecurity.saml.Attribute;

/**
 * OpsUpdate
 */
public class OpsUpdate {
    String dn;
    List<Attribute> attributes;
    String reason;

    /**
     * @return the attributes
     */
    public List<Attribute> getAttributes() {
        return attributes;
    }
    /**
     * @return the dn
     */
    public String getDn() {
        return dn;
    }
    /**
     * @param attributes the attributes to set
     */
    public void setAttributes(List<Attribute> attributes) {
        this.attributes = attributes;
    }
    /**
     * @param dn the dn to set
     */
    public void setDn(String dn) {
        this.dn = dn;
    }

    /**
     * @return the reason
     */
    public String getReason() {
        return reason;
    }

    /**
     * @param reason the reason to set
     */
    public void setReason(String reason) {
        this.reason = reason;
    }
    
}
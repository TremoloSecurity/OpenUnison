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

/**
 * AttributeConfig
 */
public class AttributeConfig {

    String name;
    String label;
    boolean picked;
    String value;

    public AttributeConfig() {

    }

    public AttributeConfig(String name,String value) {
        this.name = name;
        this.value = value;
    }

    public AttributeConfig(String name,String label,String value) {
        this.name = name;
        this.label = label;
        this.value = value;
    }

    /**
     * @return the label
     */
    public String getLabel() {
        return label;
    }

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

     /**
      * @return the value
      */
     public String getValue() {
         return value;
     }

     /**
      * @return the picked
      */
     public boolean isPicked() {
         return picked;
     }

     /**
      * @param label the label to set
      */
     public void setLabel(String label) {
         this.label = label;
     }

     /**
      * @param name the name to set
      */
     public void setName(String name) {
         this.name = name;
     }

     /**
      * @param picked the picked to set
      */
     public void setPicked(boolean picked) {
         this.picked = picked;
     }

     /**
      * @param value the value to set
      */
     public void setValue(String value) {
         this.value = value;
     }
}
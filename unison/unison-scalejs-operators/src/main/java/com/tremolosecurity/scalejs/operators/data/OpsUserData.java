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

import java.util.HashMap;
import java.util.Map;

import com.tremolosecurity.scalejs.cfg.ScaleAttribute;
import com.tremolosecurity.scalejs.data.UserData;

/**
 * OpsUserData
 */
public class OpsUserData extends UserData {
    Map<String,ScaleAttribute> metaData;
    boolean canEditUser;

    public OpsUserData() {
        super();
        this.metaData = new HashMap<String,ScaleAttribute>();
    }

    /**
     * @return the metaData
     */
    public Map<String, ScaleAttribute> getMetaData() {
        return metaData;
    }
    /**
     * @param metaData the metaData to set
     */
    public void setMetaData(Map<String, ScaleAttribute> metaData) {
        this.metaData = metaData;
    }

  /**
   * @return the canEditUser
   */
  public boolean isCanEditUser() {
      return canEditUser;
  }

  /**
   * @param canEditUser the canEditUser to set
   */
  public void setCanEditUser(boolean canEditUser) {
      this.canEditUser = canEditUser;
  }
    
}
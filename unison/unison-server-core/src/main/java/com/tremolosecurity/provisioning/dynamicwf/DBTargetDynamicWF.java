/*******************************************************************************
 * Copyright 2019 Tremolo Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.provisioning.dynamicwf;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.WorkflowType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.util.DynamicWorkflow;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.provisioning.core.providers.BasicDB;

/**
 * DBTargetDynamicWF
 */
public class DBTargetDynamicWF implements DynamicWorkflow {

    @Override
    public List<Map<String, String>> generateWorkflows(WorkflowType wf, ConfigManager cfg,
            HashMap<String, Attribute> params) throws ProvisioningException {
        String target = params.get("target").getValues().get(0);
        String SQL = params.get("sql").getValues().get(0);
        Connection con = null;
        ResultSet rs = null;
        Statement s = null;
        try {
            con = ((BasicDB) cfg.getProvisioningEngine().getTarget(target).getProvider()).getDS()
                    .getConnection();

            s = con.createStatement();
            rs = s.executeQuery(SQL);

            List<Map<String,String>> wfParams = new ArrayList<Map<String,String>>();

            while (rs.next()) {
                HashMap<String,String> row = new HashMap<String,String>();
                for (int i=0;i<rs.getMetaData().getColumnCount();i++) {
                    if (rs.getObject(rs.getMetaData().getColumnLabel(i+1)) != null) {
                        row.put(rs.getMetaData().getColumnLabel(i+1), rs.getObject(rs.getMetaData().getColumnLabel(i+1)).toString());
                    }
                }

                wfParams.add(row);
            }

            return wfParams;
        } catch (SQLException e) {
            throw new ProvisioningException("Could not get workflow data",e);
        } finally {
            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException e) {
                    
                }
            }

            if (s != null) {
                try {
                    s.close();
                } catch (SQLException e) {
                    
                }
            }


            if (con != null) {
                try {
                    con.close();
                } catch (SQLException e) {
                    
                }
            }
        }

    }
  
      
  }
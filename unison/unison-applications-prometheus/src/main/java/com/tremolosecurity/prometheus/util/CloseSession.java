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

package com.tremolosecurity.prometheus.util;

import com.tremolosecurity.server.StopableThread;
import jakarta.jms.Connection;
import jakarta.jms.JMSException;
import jakarta.jms.Session;

public class CloseSession implements StopableThread {
    Connection con;
    Session session;

    public CloseSession(Connection con,Session session) {
        this.con = con;
        this.session = session;
    }



	@Override
	public void stop() {
		if (session != null) {
                
            try {
				session.close();
			} catch (JMSException e) {
				
			}
        }

        if (con != null) {
            try {
				con.close();
			} catch (JMSException e) {
				
			}
        }
	}



	@Override
	public void run() {
		
	}
}
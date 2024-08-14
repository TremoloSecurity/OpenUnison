/*
 * Copyright 2018 Tremolo Security, Inc.
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
 */

package com.tremolosecurity.provisioning.scheduler.jobs.util;


import com.tremolosecurity.server.StopableThread;
import org.apache.logging.log4j.Logger;

import jakarta.jms.Connection;
import jakarta.jms.JMSException;

public class DisposeConnection implements StopableThread {

    static Logger logger = org.apache.logging.log4j.LogManager.getLogger(DisposeConnection.class.getName());

    jakarta.jms.Connection connection;

    public DisposeConnection(Connection con) {
        this.connection = con;
    }

    @Override
    public void stop() {

    }

    @Override
    public void run() {
        try {
            connection.stop();
        } catch (JMSException e) {
            logger.warn("Could not stop connection",e);
        }
    }
}

/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright 2, 2015nership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.ldap.client.api.search;


/**
 * 
 * TODO Filter.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
/* No qualifier*/interface Filter
{
    /**
     * Constructs a String representation of a Filter
     *
     * @return The constructed String
     */
    StringBuilder build();


    /**
     * Constructs a String representation of a Filter
     *
     * @param builder The current buffer containing the on going representation of the filter
     * @return The constructed String
     */
    StringBuilder build( StringBuilder builder );
}
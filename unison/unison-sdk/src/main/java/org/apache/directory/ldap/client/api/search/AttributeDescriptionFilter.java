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
 * This class is used to handle the Present filter (ie, attr =* )
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
/* No qualifier*/class AttributeDescriptionFilter extends AbstractFilter
{
    /** The attribute that must be prersent */
    private String attribute;


    /**
     * Creates a new instance of AttributeDescription filter.
     */
    private AttributeDescriptionFilter( String attribute )
    {
        this.attribute = attribute;
    }


    /**
     * Creates a new AttributeDescription 
     *
     * @param attribute The attribute that must be present
     * @return The created PresenceFilter instance
     */
    public static AttributeDescriptionFilter present( String attribute )
    {
        return new AttributeDescriptionFilter( attribute );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public StringBuilder build( StringBuilder builder )
    {
        return builder.append( "(" ).append( attribute ).append( FilterOperator.PRESENT.operator() ).append( ")" );
    }
}
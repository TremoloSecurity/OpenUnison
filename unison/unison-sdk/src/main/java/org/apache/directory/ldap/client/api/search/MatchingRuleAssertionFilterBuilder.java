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
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class MatchingRuleAssertionFilterBuilder extends FilterBuilder
{
    /**
     * Creates a new instance of MatchingRuleAssertionFilterBuilder.
     *
     * @param attribute The attribute to test
     * @param value The value to test for
     */
    /* No qualifier*/ MatchingRuleAssertionFilterBuilder( String attribute, String value )
    {
        super( MatchingRuleAssertionFilter.extensible( attribute, value ) );
    }
    
    
    /**
     * Sets the matching rule to use.  Can be either a name or an OID string.
     *
     * @param matchingRule The matching rule to use
     * @return This filter
     */
    public MatchingRuleAssertionFilterBuilder setMatchingRule( String matchingRule )
    {
        ((MatchingRuleAssertionFilter)filter).setMatchingRule( matchingRule );
        return this;
    }
    
    
    /**
     * If set, the dn attributes will be included in the matching.
     *
     * @return This filter
     */
    public MatchingRuleAssertionFilterBuilder useDnAttributes()
    {
        ((MatchingRuleAssertionFilter)filter).useDnAttributes();
        return this;
    }
}
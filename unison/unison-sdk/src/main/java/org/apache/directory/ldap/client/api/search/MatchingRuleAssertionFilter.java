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


import org.apache.directory.api.ldap.model.filter.FilterEncoder;


/**
 * A class to represent the extensible matching filter.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
/* No qualifier*/class MatchingRuleAssertionFilter extends AbstractFilter
{
    /** The associated attribute */
    private String attribute;
    
    /** The rule to use */
    private String matchingRule;

    /** The Filter operator */
    private FilterOperator operator;
    
    /** Whether or not to include dn attributes in the matching */
    private boolean useDnAttributes = false;

    /** The filter value */
    private String value;


    /**
     * Creates a new instance of MatchingRuleAssertionFilter.
     * 
     * @param attribute The attribute to test
     * @param value The value to test for
     * @param operator The FilterOperator
     */
    MatchingRuleAssertionFilter( String attribute, String value, 
        FilterOperator operator )
    {
        this.attribute = attribute;
        this.value = value;
        this.operator = operator;
    }


    /**
     * Creates a new instance of MatchingRuleAssertionFilter without an attribute.
     * 
     * @param value The value to test for
     * @return A new MatchingRuleAssertionFilter
     */
    public static MatchingRuleAssertionFilter extensible( String value )
    {
        return new MatchingRuleAssertionFilter( null, value, 
            FilterOperator.EXTENSIBLE_EQUAL );
    }


    /**
     * Creates an extensible filter
     *
     * @param attribute The attribute to test
     * @param value The value to test for
     * @return A new MatchingRuleAssertionFilter
     */
    public static MatchingRuleAssertionFilter extensible( String attribute, String value )
    {
        return new MatchingRuleAssertionFilter( attribute, value, 
            FilterOperator.EXTENSIBLE_EQUAL );
    }


    /**
     * Sets the matching rule to use.  Can be either a name or an OID string.
     *
     * @param matchingRule The matching rule to use
     * @return This filter
     */
    public MatchingRuleAssertionFilter setMatchingRule( String matchingRule )
    {
        this.matchingRule = matchingRule;
        return this;
    }

    
    /**
     * If set, the dn attributes will be included in the matching.
     *
     * @return This filter
     */
    public MatchingRuleAssertionFilter useDnAttributes()
    {
        this.useDnAttributes = true;
        return this;
    }
    
    
    /**
     * {@inheritDoc}
     */
    @Override
    public StringBuilder build( StringBuilder builder )
    {
        builder.append( "(" );
        if ( attribute != null )
        {
            builder.append( attribute );
        }
        if ( useDnAttributes )
        {
            builder.append( ":dn" );
        }
        if ( matchingRule != null && !matchingRule.isEmpty() )
        {
            builder.append( ":" ).append( matchingRule );
        }
        return builder.append( operator.operator() )
            .append( FilterEncoder.encodeFilterValue( value ) ).append( ")" );
    }
}
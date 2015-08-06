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
 * A class to represent the various filters that take a value, like =, <=, >= or ~=.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
/* No qualifier*/class AttributeValueAssertionFilter extends AbstractFilter
{
    /** The associated attribute */
    private String attribute;

    /** The filter value */
    private String value;

    /** The Filter operator */
    private FilterOperator operator;


    /**
     * Creates a new instance of AttributeValueAssertionFilter.
     */
    private AttributeValueAssertionFilter( String attribute, String value, FilterOperator operator )
    {
        this.attribute = attribute;
        this.value = value;
        this.operator = operator;
    }


    /**
     * Creates an Approximate Filter : ( <attribute> ~= <value> )
     *
     * @param attribute The AttributeType
     * @param value The Value
     * @return An instance of the Approximate Filter
     */
    public static AttributeValueAssertionFilter approximatelyEqual( String attribute, String value )
    {
        return new AttributeValueAssertionFilter( attribute, value, FilterOperator.APPROXIMATELY_EQUAL );
    }


    /**
     * Creates an equal Filter : ( <attribute> = <value> )
     *
     * @param attribute The AttributeType
     * @param value The Value
     * @return An instance of the Equal Filter
     */
    public static AttributeValueAssertionFilter equal( String attribute, String value )
    {
        return new AttributeValueAssertionFilter( attribute, value, FilterOperator.EQUAL );
    }


    /**
     * Creates a Greater Than Or Equal Filter : ( <attribute> >= <value> )
     *
     * @param attribute The AttributeType
     * @param value The Value
     * @return An instance of the Greater Than Or Equal Filter
     */
    public static AttributeValueAssertionFilter greaterThanOrEqual( String attribute, String value )
    {
        return new AttributeValueAssertionFilter( attribute, value, FilterOperator.GREATER_THAN_OR_EQUAL );
    }


    /**
     * Creates a Less Than Or Equal Filter : ( <attribute> <= <value> )
     *
     * @param attribute The AttributeType
     * @param value The Value
     * @return An instance of the Less Than Or Equal Filter
     */
    public static AttributeValueAssertionFilter lessThanOrEqual( String attribute, String value )
    {
        return new AttributeValueAssertionFilter( attribute, value, FilterOperator.LESS_THAN_OR_EQUAL );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public StringBuilder build( StringBuilder builder )
    {
        return builder.append( "(" ).append( attribute )
            .append( operator.operator() )
            .append( FilterEncoder.encodeFilterValue( value ) ).append( ")" );
    }
}
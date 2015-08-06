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


import java.util.ArrayList;
import java.util.List;


/**
 * An implementation of the Filter interface for the AND and OR Filters
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
/* No qualifier*/class SetOfFiltersFilter extends AbstractFilter
{
    /** The operator to use with this set (AND or OR) */
    private FilterOperator operator;

    /** The list of inner filters */
    private List<Filter> filters;


    /**
     * Creates a new instance of SetOfFiltersFilter.
     */
    private SetOfFiltersFilter( FilterOperator operator )
    {
        this.operator = operator;
        this.filters = new ArrayList<Filter>();
    }


    /**
     * Adds a Filter into the set of Filters 
     *
     * @param filter The filter to add
     * @return The Set of Filters with the added filter
     */
    public SetOfFiltersFilter add( Filter filter )
    {
        filters.add( filter );
        return this;
    }


    /**
     * Injects a list of Filters into the set of Filters 
     *
     * @param filters The filters to inject
     * @return The Set of Filters with the injected filters
     */
    public SetOfFiltersFilter addAll( Filter... filters )
    {
        for ( Filter filter : filters )
        {
            this.filters.add( filter );
        }

        return this;
    }


    /**
     * Injects a list of Filters into the set of Filters 
     *
     * @param filters The filters to inject
     * @return The Set of Filters with the injected filters
     */
    public SetOfFiltersFilter addAll( List<Filter> filters )
    {
        this.filters.addAll( filters );

        return this;
    }


    /**
     * Creates an AND set of filters
     *
     * @param filters The inner filters
     * @return An AND filter
     */
    public static SetOfFiltersFilter and( Filter... filters )
    {
        return new SetOfFiltersFilter( FilterOperator.AND ).addAll( filters );
    }


    /**
     * Creates an OR set of filters
     *
     * @param filters The inner filters
     * @return An OR filter
     */
    public static SetOfFiltersFilter or( Filter... filters )
    {
        return new SetOfFiltersFilter( FilterOperator.OR ).addAll( filters );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public StringBuilder build( StringBuilder builder )
    {
        if ( filters.isEmpty() )
        {
            throw new IllegalStateException( "at least one filter required" );
        }

        builder.append( "(" ).append( operator.operator() );

        for ( Filter filter : filters )
        {
            filter.build( builder );
        }

        return builder.append( ")" );
    }
}
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

import org.apache.directory.api.ldap.model.filter.FilterEncoder;
import org.apache.directory.api.util.Strings;


/**
 * A class used to manage Substring Filters.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
class SubstringFilter extends AbstractFilter
{
    /** The AttributeType for this filter */
    private String attribute;

    /** The initial substring string. It may be null */
    private String initial;

    /** The array of any substring strings. It may be null */
    private String[] any;

    /** The final substring string. It may be null */
    private String end;


    /**
     * A private constructor that builds a SubstringFilter 
     */
    private SubstringFilter( String attribute, String initial, String[] any, String end )
    {
        this.attribute = attribute;
        this.initial = initial;

        // We have to filter the 'any' and remove every empty strings
        if ( ( any != null ) && ( any.length != 0 ) )
        {
            List<String> anyList = new ArrayList<String>();

            for ( String string : any )
            {
                if ( !Strings.isEmpty( string ) )
                {
                    anyList.add( string );
                }
            }

            if ( anyList.size() > 0 )
            {
                this.any = anyList.toArray( new String[]
                    {} );
            }
        }

        this.end = end;
    }


    /**
     * Create a SubstringFilter based on the filter elements. Such a filter
     * has a form like <b>Attribute=initial*([any]*)*</b>. We don't expect any
     * <em>final</em> String.
     *
     * @param attribute The AttributeType for this filter
     * @param parts The parts that are the initial string and zero to N any strings
     * @return An instance of a SubstringFilter
     */
    public static SubstringFilter startsWith( String attribute, String... parts )
    {
        if ( ( parts != null ) && ( parts.length > 0 ) )
        {
            if ( parts.length > 1 )
            {
                String[] any = new String[parts.length - 1];
                System.arraycopy( parts, 1, any, 0, any.length );

                return new SubstringFilter( attribute, parts[0], any, null );
            }
            else
            {
                return new SubstringFilter( attribute, parts[0], null, null );
            }
        }
        else
        {
            // This is a presence filter, kind of
            return new SubstringFilter( attribute, null, null, null );
        }
    }


    /**
     * Create a SubstringFilter based on the filter elements. Such a filter
     * has a form like <b>Attribute=*([any]*)*final</b>. We don't expect any
     * <em>initial</em> String.
     *
     * @param attribute The AttributeType for this filter
     * @param parts The parts that are zero to N any strings followed by a final string
     * @return An instance of a SubstringFilter
     */
    public static SubstringFilter endsWith( String attribute, String... parts )
    {
        if ( ( parts != null ) && ( parts.length > 0 ) )
        {
            if ( parts.length > 1 )
            {
                String[] any = new String[parts.length - 1];
                System.arraycopy( parts, 0, any, 0, any.length );

                return new SubstringFilter( attribute, null, any, parts[parts.length - 1] );
            }
            else
            {
                return new SubstringFilter( attribute, null, null, parts[0] );
            }
        }
        else
        {
            // This is a presence filter, kind of
            return new SubstringFilter( attribute, null, null, null );
        }
    }


    /**
     * Create a SubstringFilter based on the filter elements. Such a filter
     * has a form like <b>Attribute=*([any]*)*</b>. We don't expect any
     * <em>initial</em>or <em>final</em> Strings.
     *
     * @param attribute The AttributeType for this filter
     * @param parts The parts that are zero to N any strings with no initial nor final Strings
     * @return An instance of a SubstringFilter
     */
    public static SubstringFilter contains( String attribute, String... parts )
    {
        if ( ( parts != null ) && ( parts.length > 0 ) )
        {
            if ( parts.length > 1 )
            {
                String[] any = new String[parts.length];
                System.arraycopy( parts, 0, any, 0, any.length );

                return new SubstringFilter( attribute, null, any, null );
            }
            else
            {
                return new SubstringFilter( attribute, null, parts, null );
            }
        }
        else
        {
            // This is a presence filter, kind of
            return new SubstringFilter( attribute, null, null, null );
        }
    }


    /**
     * Create a SubstringFilter based on the filter elements. Such a filter
     * has a form like <b>Attribute=initial*([any]*)*final</b>.
     *
     * @param attribute The AttributeType for this filter
     * @param parts The parts that are zero to N any strings starting with an initial String and 
     * followed by a final string
     * @return An instance of a SubstringFilter
     */
    public static SubstringFilter substring( String attribute, String... parts )
    {
        if ( ( parts != null ) && ( parts.length > 0 ) )
        {
            if ( parts.length > 2 )
            {
                // We have initial, any and final
                String[] any = new String[parts.length - 2];
                System.arraycopy( parts, 1, any, 0, any.length );

                return new SubstringFilter( attribute, parts[0], any, parts[parts.length - 1] );
            }
            else if ( parts.length > 1 )
            {
                // we only have initial and final
                return new SubstringFilter( attribute, parts[0], null, parts[1] );
            }
            else
            {
                // We don't have any or final
                return new SubstringFilter( attribute, parts[0], null, null );
            }
        }
        else
        {
            // This is a presence filter, kind of
            return new SubstringFilter( attribute, null, null, null );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public StringBuilder build( StringBuilder builder )
    {
        builder.append( "(" ).append( attribute ).append( '=' );

        if ( !Strings.isEmpty( initial ) )
        {
            builder.append( FilterEncoder.encodeFilterValue( initial ) );
        }

        if ( any != null )
        {
            for ( String string : any )
            {
                builder.append( '*' ).append( FilterEncoder.encodeFilterValue( string ) );
            }
        }

        builder.append( '*' );

        if ( !Strings.isEmpty( end ) )
        {
            builder.append( FilterEncoder.encodeFilterValue( end ) );
        }

        builder.append( ")" );

        return builder;
    }
}
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
 * The operators that can be used in a Filter :
 * <ul>
 * <li>AND: the '&' operator</li>
 * <li>OR: the '|' operator</li>
 * <li>NOT: the '!' operator</li>
 * <li>EQUAL: the '=' operator</li>
 * <li>LESS_THAN_OR_EQUAL: the '<=' operator</li>
 * <li>GREATER_THAN_OR_EQUAL: the '>=' operator</li>
 * <li>PRESENT: the '=*' operator</li>
 * <li>APPROXIMATELY_EQUAL: the '~=' operator</li>
 * </ul>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
/* No Qualifier */enum FilterOperator
{
    AND("&"),
    OR("|"),
    NOT("!"),
    APPROXIMATELY_EQUAL("~="),
    EQUAL("="),
    PRESENT("=*"),
    GREATER_THAN_OR_EQUAL(">="),
    LESS_THAN_OR_EQUAL("<="),
    EXTENSIBLE_EQUAL(":=");

    /** The String representing the operator in a FIlter */
    private String operator;


    /**
     * Creates a new instance of FilterOperator.
     */
    private FilterOperator( String operator )
    {
        this.operator = operator;
    }


    /**
     * @return The String representation of the operator
     */
    public String operator()
    {
        return operator;
    }
}

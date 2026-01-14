/*
 * Copyright 2026 Tremolo Security, Inc.
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

package com.tremolosecurity.proxy.filters.scim;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ScimSchema {

    private static final ObjectMapper M = new ObjectMapper().disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    public static String JSON_LIST_RESPONSE = "{\n" +
            "  \"schemas\": [\n" +
            "    \"urn:ietf:params:scim:api:messages:2.0:ListResponse\"\n" +
            "  ],\n" +
            "  \"totalResults\": 0,\n" +
            "  \"startIndex\": 1,\n" +
            "  \"itemsPerPage\": 0,\n" +
            "  \"Resources\": [\n" +


            "  ]\n" +
            "}";

    public static String JSON_RESOURCE_TYPE_USER = "    {\n" +
            "      \"schemas\": [\n" +
            "        \"urn:ietf:params:scim:schemas:core:2.0:ResourceType\"\n" +
            "      ],\n" +
            "      \"id\": \"User\",\n" +
            "      \"name\": \"User\",\n" +
            "      \"endpoint\": \"/Users\",\n" +
            "      \"description\": \"User Account\",\n" +
            "      \"schema\": \"urn:ietf:params:scim:schemas:core:2.0:User\",\n" +
            "      \"schemaExtensions\": [\n" +
            "        {\n" +
            "          \"schema\": \"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User\",\n" +
            "          \"required\": false\n" +
            "        }\n" +
            "      ],\n" +
            "      \"meta\": {\n" +
            "        \"resourceType\": \"ResourceType\",\n" +
            "        \"location\": \"%s/User\"\n" +
            "      }\n" +
            "    }";

    public static String JSON_RESOURCE_TYPE_GROUP = "    {\n" +
            "      \"schemas\": [\n" +
            "        \"urn:ietf:params:scim:schemas:core:2.0:ResourceType\"\n" +
            "      ],\n" +
            "      \"id\": \"Group\",\n" +
            "      \"name\": \"Group\",\n" +
            "      \"endpoint\": \"/Groups\",\n" +
            "      \"description\": \"Group\",\n" +
            "      \"schema\": \"urn:ietf:params:scim:schemas:core:2.0:Group\",\n" +
            "      \"meta\": {\n" +
            "        \"resourceType\": \"ResourceType\",\n" +
            "        \"location\": \"%s/Group\"\n" +
            "      }\n" +
            "    }";
    
    public static String JSON_RESOURCE_USER_TYPE = "{\n" +
            "  \"schemas\": [\n" +
            "    \"urn:ietf:params:scim:schemas:core:2.0:ResourceType\"\n" +
            "  ],\n" +
            "  \"id\": \"User\",\n" +
            "  \"name\": \"User\",\n" +
            "  \"endpoint\": \"/Users\",\n" +
            "  \"description\": \"User Account\",\n" +
            "  \"schema\": \"urn:ietf:params:scim:schemas:core:2.0:User\",\n" +
            "  \"schemaExtensions\": [\n" +
            "    {\n" +
            "      \"schema\": \"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User\",\n" +
            "      \"required\": false\n" +
            "    }\n" +
            "  ],\n" +
            "  \"meta\": {\n" +
            "    \"resourceType\": \"ResourceType\",\n" +
            "    \"location\": \"%s/ResourceTypes/User\"\n" +
            "  }\n" +
            "}";

    public static String JSON_GROUP_SCHEMA = "{\n" +
            "  \"schemas\": [\"urn:ietf:params:scim:schemas:core:2.0:Schema\"],\n" +
            "  \"id\": \"urn:ietf:params:scim:schemas:core:2.0:Group\",\n" +
            "  \"name\": \"Group\",\n" +
            "  \"description\": \"Group\",\n" +
            "  \"attributes\": [\n" +
            "    {\n" +
            "      \"name\": \"id\",\n" +
            "      \"type\": \"string\",\n" +
            "      \"multiValued\": false,\n" +
            "      \"required\": false,\n" +
            "      \"caseExact\": false,\n" +
            "      \"mutability\": \"readOnly\",\n" +
            "      \"returned\": \"always\",\n" +
            "      \"uniqueness\": \"server\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"name\": \"externalId\",\n" +
            "      \"type\": \"string\",\n" +
            "      \"multiValued\": false,\n" +
            "      \"required\": false,\n" +
            "      \"caseExact\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"default\",\n" +
            "      \"uniqueness\": \"none\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"name\": \"displayName\",\n" +
            "      \"type\": \"string\",\n" +
            "      \"multiValued\": false,\n" +
            "      \"required\": true,\n" +
            "      \"caseExact\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"always\",\n" +
            "      \"uniqueness\": \"none\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"name\": \"members\",\n" +
            "      \"type\": \"complex\",\n" +
            "      \"multiValued\": true,\n" +
            "      \"required\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"default\",\n" +
            "      \"subAttributes\": [\n" +
            "        {\n" +
            "          \"name\": \"value\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"$ref\",\n" +
            "          \"type\": \"reference\",\n" +
            "          \"referenceTypes\": [\"User\", \"Group\", \"external\"],\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"type\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"display\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readOnly\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        }\n" +
            "      ]\n" +
            "    },\n" +
            "    {\n" +
            "      \"name\": \"meta\",\n" +
            "      \"type\": \"complex\",\n" +
            "      \"multiValued\": false,\n" +
            "      \"required\": false,\n" +
            "      \"mutability\": \"readOnly\",\n" +
            "      \"returned\": \"always\",\n" +
            "      \"subAttributes\": [\n" +
            "        {\n" +
            "          \"name\": \"resourceType\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readOnly\",\n" +
            "          \"returned\": \"always\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"created\",\n" +
            "          \"type\": \"dateTime\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"mutability\": \"readOnly\",\n" +
            "          \"returned\": \"always\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"lastModified\",\n" +
            "          \"type\": \"dateTime\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"mutability\": \"readOnly\",\n" +
            "          \"returned\": \"always\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"version\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readOnly\",\n" +
            "          \"returned\": \"always\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"location\",\n" +
            "          \"type\": \"reference\",\n" +
            "          \"referenceTypes\": [\"external\"],\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readOnly\",\n" +
            "          \"returned\": \"always\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        }\n" +
            "      ]\n" +
            "    }\n" +
            "  ],\n" +
            "  \"meta\": {\n" +
            "    \"resourceType\": \"Schema\",\n" +
            "    \"location\": \"%s/urn:ietf:params:scim:schemas:core:2.0:Group\"\n" +
            "  }\n" +
            "}";

    public static String JSON_USER_SCHEMA = "{\n" +
            "  \"schemas\": [\"urn:ietf:params:scim:schemas:core:2.0:Schema\"],\n" +
            "  \"id\": \"urn:ietf:params:scim:schemas:core:2.0:User\",\n" +
            "  \"name\": \"User\",\n" +
            "  \"description\": \"User Account\",\n" +
            "  \"attributes\": [\n" +
            "    {\n" +
            "      \"name\": \"id\",\n" +
            "      \"type\": \"string\",\n" +
            "      \"multiValued\": false,\n" +
            "      \"required\": false,\n" +
            "      \"caseExact\": false,\n" +
            "      \"mutability\": \"readOnly\",\n" +
            "      \"returned\": \"always\",\n" +
            "      \"uniqueness\": \"server\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"name\": \"externalId\",\n" +
            "      \"type\": \"string\",\n" +
            "      \"multiValued\": false,\n" +
            "      \"required\": false,\n" +
            "      \"caseExact\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"default\",\n" +
            "      \"uniqueness\": \"none\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"name\": \"userName\",\n" +
            "      \"type\": \"string\",\n" +
            "      \"multiValued\": false,\n" +
            "      \"required\": true,\n" +
            "      \"caseExact\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"always\",\n" +
            "      \"uniqueness\": \"server\"\n" +
            "    },\n" +
            "\n" +
            "    {\n" +
            "      \"name\": \"name\",\n" +
            "      \"type\": \"complex\",\n" +
            "      \"multiValued\": false,\n" +
            "      \"required\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"default\",\n" +
            "      \"subAttributes\": [\n" +
            "        {\n" +
            "          \"name\": \"formatted\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"familyName\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"givenName\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"middleName\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"honorificPrefix\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"honorificSuffix\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        }\n" +
            "      ]\n" +
            "    },\n" +
            "\n" +
            "    {\n" +
            "      \"name\": \"displayName\",\n" +
            "      \"type\": \"string\",\n" +
            "      \"multiValued\": false,\n" +
            "      \"required\": false,\n" +
            "      \"caseExact\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"default\",\n" +
            "      \"uniqueness\": \"none\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"name\": \"nickName\",\n" +
            "      \"type\": \"string\",\n" +
            "      \"multiValued\": false,\n" +
            "      \"required\": false,\n" +
            "      \"caseExact\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"default\",\n" +
            "      \"uniqueness\": \"none\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"name\": \"profileUrl\",\n" +
            "      \"type\": \"reference\",\n" +
            "      \"referenceTypes\": [\"external\"],\n" +
            "      \"multiValued\": false,\n" +
            "      \"required\": false,\n" +
            "      \"caseExact\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"default\",\n" +
            "      \"uniqueness\": \"none\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"name\": \"title\",\n" +
            "      \"type\": \"string\",\n" +
            "      \"multiValued\": false,\n" +
            "      \"required\": false,\n" +
            "      \"caseExact\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"default\",\n" +
            "      \"uniqueness\": \"none\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"name\": \"userType\",\n" +
            "      \"type\": \"string\",\n" +
            "      \"multiValued\": false,\n" +
            "      \"required\": false,\n" +
            "      \"caseExact\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"default\",\n" +
            "      \"uniqueness\": \"none\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"name\": \"preferredLanguage\",\n" +
            "      \"type\": \"string\",\n" +
            "      \"multiValued\": false,\n" +
            "      \"required\": false,\n" +
            "      \"caseExact\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"default\",\n" +
            "      \"uniqueness\": \"none\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"name\": \"locale\",\n" +
            "      \"type\": \"string\",\n" +
            "      \"multiValued\": false,\n" +
            "      \"required\": false,\n" +
            "      \"caseExact\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"default\",\n" +
            "      \"uniqueness\": \"none\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"name\": \"timezone\",\n" +
            "      \"type\": \"string\",\n" +
            "      \"multiValued\": false,\n" +
            "      \"required\": false,\n" +
            "      \"caseExact\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"default\",\n" +
            "      \"uniqueness\": \"none\"\n" +
            "    },\n" +
            "\n" +
            "    {\n" +
            "      \"name\": \"active\",\n" +
            "      \"type\": \"boolean\",\n" +
            "      \"multiValued\": false,\n" +
            "      \"required\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"default\"\n" +
            "    },\n" +
            "\n" +
            "    {\n" +
            "      \"name\": \"password\",\n" +
            "      \"type\": \"string\",\n" +
            "      \"multiValued\": false,\n" +
            "      \"required\": false,\n" +
            "      \"caseExact\": false,\n" +
            "      \"mutability\": \"writeOnly\",\n" +
            "      \"returned\": \"never\",\n" +
            "      \"uniqueness\": \"none\"\n" +
            "    },\n" +
            "\n" +
            "    {\n" +
            "      \"name\": \"emails\",\n" +
            "      \"type\": \"complex\",\n" +
            "      \"multiValued\": true,\n" +
            "      \"required\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"default\",\n" +
            "      \"subAttributes\": [\n" +
            "        {\n" +
            "          \"name\": \"value\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": true,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"display\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readOnly\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"type\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"primary\",\n" +
            "          \"type\": \"boolean\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\"\n" +
            "        }\n" +
            "      ]\n" +
            "    },\n" +
            "\n" +
            "    {\n" +
            "      \"name\": \"phoneNumbers\",\n" +
            "      \"type\": \"complex\",\n" +
            "      \"multiValued\": true,\n" +
            "      \"required\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"default\",\n" +
            "      \"subAttributes\": [\n" +
            "        {\n" +
            "          \"name\": \"value\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": true,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"display\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readOnly\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"type\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"primary\",\n" +
            "          \"type\": \"boolean\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\"\n" +
            "        }\n" +
            "      ]\n" +
            "    },\n" +
            "\n" +
            "    {\n" +
            "      \"name\": \"ims\",\n" +
            "      \"type\": \"complex\",\n" +
            "      \"multiValued\": true,\n" +
            "      \"required\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"default\",\n" +
            "      \"subAttributes\": [\n" +
            "        {\n" +
            "          \"name\": \"value\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": true,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"display\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readOnly\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"type\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"primary\",\n" +
            "          \"type\": \"boolean\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\"\n" +
            "        }\n" +
            "      ]\n" +
            "    },\n" +
            "\n" +
            "    {\n" +
            "      \"name\": \"photos\",\n" +
            "      \"type\": \"complex\",\n" +
            "      \"multiValued\": true,\n" +
            "      \"required\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"default\",\n" +
            "      \"subAttributes\": [\n" +
            "        {\n" +
            "          \"name\": \"value\",\n" +
            "          \"type\": \"reference\",\n" +
            "          \"referenceTypes\": [\"external\"],\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": true,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"display\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readOnly\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"type\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"primary\",\n" +
            "          \"type\": \"boolean\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\"\n" +
            "        }\n" +
            "      ]\n" +
            "    },\n" +
            "\n" +
            "    {\n" +
            "      \"name\": \"addresses\",\n" +
            "      \"type\": \"complex\",\n" +
            "      \"multiValued\": true,\n" +
            "      \"required\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"default\",\n" +
            "      \"subAttributes\": [\n" +
            "        {\n" +
            "          \"name\": \"formatted\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"streetAddress\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"locality\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"region\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"postalCode\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"country\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"type\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"primary\",\n" +
            "          \"type\": \"boolean\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\"\n" +
            "        }\n" +
            "      ]\n" +
            "    },\n" +
            "\n" +
            "    {\n" +
            "      \"name\": \"groups\",\n" +
            "      \"type\": \"complex\",\n" +
            "      \"multiValued\": true,\n" +
            "      \"required\": false,\n" +
            "      \"mutability\": \"readOnly\",\n" +
            "      \"returned\": \"default\",\n" +
            "      \"subAttributes\": [\n" +
            "        {\n" +
            "          \"name\": \"value\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readOnly\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"$ref\",\n" +
            "          \"type\": \"reference\",\n" +
            "          \"referenceTypes\": [\"Group\"],\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readOnly\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"display\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readOnly\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        }\n" +
            "      ]\n" +
            "    },\n" +
            "\n" +
            "    {\n" +
            "      \"name\": \"entitlements\",\n" +
            "      \"type\": \"complex\",\n" +
            "      \"multiValued\": true,\n" +
            "      \"required\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"default\",\n" +
            "      \"subAttributes\": [\n" +
            "        {\n" +
            "          \"name\": \"value\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": true,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"display\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readOnly\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"type\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"primary\",\n" +
            "          \"type\": \"boolean\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\"\n" +
            "        }\n" +
            "      ]\n" +
            "    },\n" +
            "\n" +
            "    {\n" +
            "      \"name\": \"roles\",\n" +
            "      \"type\": \"complex\",\n" +
            "      \"multiValued\": true,\n" +
            "      \"required\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"default\",\n" +
            "      \"subAttributes\": [\n" +
            "        {\n" +
            "          \"name\": \"value\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": true,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"display\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readOnly\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"type\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"primary\",\n" +
            "          \"type\": \"boolean\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\"\n" +
            "        }\n" +
            "      ]\n" +
            "    },\n" +
            "\n" +
            "    {\n" +
            "      \"name\": \"x509Certificates\",\n" +
            "      \"type\": \"complex\",\n" +
            "      \"multiValued\": true,\n" +
            "      \"required\": false,\n" +
            "      \"mutability\": \"readWrite\",\n" +
            "      \"returned\": \"default\",\n" +
            "      \"subAttributes\": [\n" +
            "        {\n" +
            "          \"name\": \"value\",\n" +
            "          \"type\": \"binary\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": true,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"display\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readOnly\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"type\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"primary\",\n" +
            "          \"type\": \"boolean\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"mutability\": \"readWrite\",\n" +
            "          \"returned\": \"default\"\n" +
            "        }\n" +
            "      ]\n" +
            "    },\n" +
            "\n" +
            "    {\n" +
            "      \"name\": \"meta\",\n" +
            "      \"type\": \"complex\",\n" +
            "      \"multiValued\": false,\n" +
            "      \"required\": false,\n" +
            "      \"mutability\": \"readOnly\",\n" +
            "      \"returned\": \"always\",\n" +
            "      \"subAttributes\": [\n" +
            "        {\n" +
            "          \"name\": \"resourceType\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readOnly\",\n" +
            "          \"returned\": \"always\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"created\",\n" +
            "          \"type\": \"dateTime\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"mutability\": \"readOnly\",\n" +
            "          \"returned\": \"always\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"lastModified\",\n" +
            "          \"type\": \"dateTime\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"mutability\": \"readOnly\",\n" +
            "          \"returned\": \"always\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"version\",\n" +
            "          \"type\": \"string\",\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readOnly\",\n" +
            "          \"returned\": \"always\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"location\",\n" +
            "          \"type\": \"reference\",\n" +
            "          \"referenceTypes\": [\"external\"],\n" +
            "          \"multiValued\": false,\n" +
            "          \"required\": false,\n" +
            "          \"caseExact\": false,\n" +
            "          \"mutability\": \"readOnly\",\n" +
            "          \"returned\": \"always\",\n" +
            "          \"uniqueness\": \"none\"\n" +
            "        }\n" +
            "      ]\n" +
            "    }\n" +
            "  ],\n" +
            "  \"meta\": {\n" +
            "    \"resourceType\": \"Schema\",\n" +
            "    \"location\": \"%s/urn:ietf:params:scim:schemas:core:2.0:User\"\n" +
            "  }\n" +
            "}";


    static Map<String,AttributeInfo> attributeData;

    static {
        attributeData = new HashMap<String,AttributeInfo>();

        String schema = String.format(JSON_USER_SCHEMA,"");
        ByteArrayInputStream bais = new ByteArrayInputStream(schema.getBytes(StandardCharsets.UTF_8));

        ObjectNode json = null;
        try {
            json = (ObjectNode) M.readTree(bais);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        ArrayNode attributesArray = (ArrayNode) json.get("attributes");
        attributesArray.forEach(attribute -> {
            AttributeInfo attributeInfo = new AttributeInfo();
            attributeInfo.name = attribute.get("name").asText();
            attributeInfo.multiValued = attribute.get("multiValued").asBoolean();
            attributeData.put(attributeInfo.name, attributeInfo);
        });
    }

    public static ObjectNode resourceTypes(String url) throws JsonProcessingException {
        String schema = String.format(ScimSchema.JSON_LIST_RESPONSE,url);
        ByteArrayInputStream bais = new ByteArrayInputStream(schema.getBytes(StandardCharsets.UTF_8));

        ObjectNode json = (ObjectNode) M.readTree(schema);

        // for now hard code to two resource types
        json.put("totalResults",2);
        json.put("itemsPerPage",2);

        // add the resource types
        ObjectNode rt = loadJsonNode(url,ScimSchema.JSON_RESOURCE_TYPE_USER);
        ((ArrayNode) json.get("Resources")).add(rt);

        rt = loadJsonNode(url,ScimSchema.JSON_RESOURCE_TYPE_GROUP);
        ((ArrayNode) json.get("Resources")).add(rt);

        return json;


    }

    public static ObjectNode resourceType(String url,String name) throws JsonProcessingException {
        if (name.equalsIgnoreCase("User")) {
            return loadJsonNode(url,ScimSchema.JSON_RESOURCE_TYPE_USER);
        } else if (name.equalsIgnoreCase("Group")) {
            return loadJsonNode(url,ScimSchema.JSON_RESOURCE_TYPE_GROUP);
        } else {
            return null;
        }
    }

    private static ObjectNode loadJsonNode(String url,String jsonData) throws JsonProcessingException {
        String schema;
        ByteArrayInputStream bais;
        schema = String.format(jsonData, url);
        bais = new ByteArrayInputStream(schema.getBytes(StandardCharsets.UTF_8));
        ObjectNode rt = (ObjectNode) M.readTree(schema);
        return rt;
    }

    public static ObjectNode userSchema(String url, Set<String> attributes) throws IOException {
        String schema = String.format(JSON_USER_SCHEMA,url);
        ByteArrayInputStream bais = new ByteArrayInputStream(schema.getBytes(StandardCharsets.UTF_8));

        ObjectNode json = (ObjectNode) M.readTree(bais);
        ArrayNode attributesArray = (ArrayNode) json.get("attributes");
        List<ObjectNode> attributesToUser = new ArrayList<ObjectNode>();
        attributesArray.forEach(attribute -> {
            if (attributes.contains(attribute.get("name").asText())) {
                attributesToUser.add((ObjectNode) attribute);
            }
        });

        attributesArray.removeAll();
        attributesArray.addAll(attributesToUser);

        return json;


    }

    public static ObjectNode schemas(String url,Set<String> attributes) throws IOException {
        String schema = String.format(ScimSchema.JSON_LIST_RESPONSE,url);
        ByteArrayInputStream bais = new ByteArrayInputStream(schema.getBytes(StandardCharsets.UTF_8));

        ObjectNode json = (ObjectNode) M.readTree(schema);

        // for now hard code to two resource types
        json.put("totalResults",2);
        json.put("itemsPerPage",2);

        // add the resource types
        ObjectNode rt = userSchema(url,attributes);
        ((ArrayNode) json.get("Resources")).add(rt);

        rt = loadJsonNode(url,ScimSchema.JSON_GROUP_SCHEMA);
        ((ArrayNode) json.get("Resources")).add(rt);

        return json;
    }

    public static ObjectNode schema(String url,String name,Set<String> attributes) throws IOException {
        if (name.equalsIgnoreCase("urn:ietf:params:scim:schemas:core:2.0:User")) {
            return userSchema(url,attributes);
        } else if (name.equalsIgnoreCase("urn:ietf:params:scim:schemas:core:2.0:Group")) {
            return loadJsonNode(url,ScimSchema.JSON_GROUP_SCHEMA);
        } else {
            return null;
        }
    }

    public static boolean isMultiValued(String attribute) {
        AttributeInfo attributeInfo = attributeData.get(attribute);
        if (attributeInfo != null) {
            return attributeInfo.multiValued;
        } else {
            return false;
        }
    }
}

class AttributeInfo {
    String name;
    boolean multiValued;
}

/*
 * Copyright 2025 Tremolo Security, Inc.
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
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.util.ByteArray;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.provisioning.UserStoreProviderLookups;
import com.tremolosecurity.provisioning.core.*;
import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.provisioning.service.util.TremoloUser;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.provisioning.tasks.Provision;
import com.tremolosecurity.proxy.ProxyResponse;
import com.tremolosecurity.proxy.ProxySys;
import com.tremolosecurity.proxy.filter.*;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.proxy.util.ProxyTools;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.apache.log4j.Logger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Scim implements HttpFilter {
    private static final Pattern FILTER_PATTERN = Pattern.compile(
            "^value\\s+(eq|ne|co|sw|ew|gt|lt|ge|le)\\s+(\"([^\"]*)\"|'([^']*)'|(\\S+))$",
            Pattern.CASE_INSENSITIVE);

    static Logger logger = Logger.getLogger(Scim.class.getName());
    String rootUri;
    private static final String CT = "application/scim+json";
    private static final ObjectMapper M = new ObjectMapper().disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    MapIdentity scim2tremolo;
    MapIdentity tremolo2scim;

    String uidAttributeName;
    String idAttributeName;
    String workflowName;
    String deleteUserWorkflowName;
    String lookupAttributeName;
    String searchBase;
    private String groupWorkflow;
    private String groupLookupAttributeName;
    private String groupIdName;
    private String groupMemberAttributeName;
    private String groupDeleteWorkflow;

    private Map<String,String> scimFilterAttrib2Ldap;
    private HashMap<Object, String> scimGroupFilterAttrib2Ldap;

    Set<String> allowedAttributes;

    boolean lookupFromLDAP;
    String lookupTarget;

    // splits the requested URI
    private String[] split(HttpFilterRequest req) {

        String path = Optional.ofNullable(req.getServletRequest().getRequestURI()).orElse("/");
        if (! path.startsWith(this.rootUri)) {
            return null;
        }

        path = path.substring(this.rootUri.length());

        if (path.startsWith("/")) {
            path = path.substring(1);
        }
        return path.isEmpty()? new String[0] : path.split("/");
    }

    private static void write(HttpFilterRequest request,HttpFilterResponse resp, int status, Object body) throws IOException {
        resp.setStatus(status);
        UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
        ((ProxyResponse) resp.getServletResponse()).pushHeadersAndCookies(holder);
        try {
            M.writeValue(resp.getOutputStream(), body);
        } catch (IOException e) {
            // ignore
        }
    }

    private  String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private  String loc(String base, String coll, String id) {
        return URI.create(base + "/" + enc(coll) + "/" + enc(id)).toString();
    }

    private  void ensureMeta(ObjectNode n, String base, String coll, String id, long version) {
        ObjectNode meta = n.with("meta");
        meta.put("resourceType", coll.substring(0, coll.length() - 1)); // User / Group
        if (base.endsWith(coll)) {
            meta.put("location", base +  "/" + id);
        } else {
            meta.put("location", base + "/" + coll + "/" + id);
        }



    }
    private static void setEtag(HttpFilterResponse resp, ObjectNode n) {
        if (n.path("meta") != null && n.path("version") != null) {
            String v = n.path("meta").path("version").asText(null);
            if (v != null) resp.setHeader("ETag", "\"" + v + "\"");
        }
    }


    @Override
    public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain) throws Exception {
        if (logger.isDebugEnabled()) {
            logger.debug(request.getMethod() + " " + request.getRequestURL());
            byte[] requestBytes = (byte[]) request.getAttribute(ProxySys.MSG_BODY);
            if (requestBytes != null) {
                logger.debug(new String(requestBytes));
            }
        }


        try {
            request.getServletRequest().setAttribute("com.tremolosecurity.unison.proxy.noRedirectOnError", "com.tremolosecurity.unison.proxy.noRedirectOnError");
            response.setContentType(CT);
            if (request.getMethod().equals("POST")) {
                doPost(request, response, chain);
            } else if (request.getMethod().equals("GET")) {
                doGet(request, response, chain);
            } else if (request.getMethod().equals("PATCH")) {
                doPatch(request, response, chain);
            } else if (request.getMethod().equals("PUT")) {
                doPost(request, response, chain);
            } else if (request.getMethod().equals("DELETE")) {
                doDelete(request, response, chain);
            }
        } catch (Throwable t) {
            logger.error(String.format("Could not process request %s to %s",request.getMethod(),request.getRequestURL()),t);
            err(request,response,500,"unknown",t.getMessage());
        }
    }

    private UserStoreProviderLookups loadTarget(HttpFilterRequest request, HttpFilterResponse response) throws IOException,ProvisioningException {
        ProvisioningTarget prov = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.lookupTarget);
        if (prov == null) {
            err(request, response, 500, "error", "Target does not exist");
            return null;
        }

        if (! (prov.getProvider() instanceof UserStoreProviderLookups)) {
            err(request, response, 500, "error", "Provider does not support lookups");
            return null;
        }

        UserStoreProviderLookups target = (UserStoreProviderLookups) prov.getProvider();
        return target;

    }
    private void doDelete(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain) throws Exception {
        String[] p = split(request);
        if (p == null || p.length == 0) { err(request,response, 404, "invalidPath", "Unknown"); return; }
        if (!("Users".equals(p[0]) || "Groups".equals(p[0]))) { err(request,response, 404, "invalidPath", "Unknown DELETE"); return; }

        String id = p[1];

        switch (p[0]) {
            case "Users":
                final ObjectNode copy = M.createObjectNode();
                if (this.lookupFromLDAP) {
                    // load from MyVD - create a SCIM object

                    LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(this.searchBase, 2, "(" + this.idAttributeName + "=" + id + ")", new ArrayList<String>());
                    if (!res.hasMore()) {
                        err(request, response, 404, "objectNotFound", "Could not find the created object");
                        return;
                    }


                    LDAPEntry entry = res.next();

                    while (res.hasMore()) res.next();


                    ldap2scim(entry, copy);
                } else {

                    UserStoreProviderLookups target = loadTarget(request, response);
                    if (target == null) {
                        return;
                    }

                    User user = target.lookupUserById(id);
                    if (user == null) {
                        err(request, response, 404, "objectNotFound", "Could not find the object");
                        return;
                    }

                    user2scim(user,copy,target);
                }

                // translate object to SCIM --> TremoloUser
                // not very efficient, but consistent

                String uidAttr = copy.get(this.uidAttributeName).asText();
                User scimUser = new User(uidAttr);
                copy.fieldNames().forEachRemaining(name -> {
                    Attribute userAttr = new Attribute(name,copy.get(name).toString());
                    scimUser.getAttribs().put(name, userAttr);
                });
                scimUser.getAttribs().put(this.idAttributeName,new Attribute(this.idAttributeName,copy.get("id").asText()));


                runWorkflow(request, response, scimUser, copy, uidAttr, p,this.deleteUserWorkflowName);
                break;
            case "Groups":
                String groupid = null;
                if (this.lookupFromLDAP) {
                    LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(this.searchBase, 2, "(" + this.groupIdName + "=" + id + ")", new ArrayList<String>());

                    if (!res.hasMore()) {
                        err(request, response, 404, "objectNotFound", "Could not find the object");
                        return;
                    }

                    LDAPEntry entry = res.next();

                    while (res.hasMore()) res.next();

                    LDAPAttribute displayNameAttribute = entry.getAttribute(this.groupLookupAttributeName);
                    if (displayNameAttribute == null) {
                        err(request, response, 400, "objectNotFound", "Group " + id + " does not have a " + this.groupLookupAttributeName + " attribute");
                        return;
                    }

                    scimUser = new User("sys");

                    groupid = displayNameAttribute.getStringValue();


                } else {
                    UserStoreProviderLookups target = loadTarget(request, response);
                    if (target == null) {
                        return;
                    }

                    if (target.isGroupIdUniqueId()) {
                        groupid = id;
                    } else {
                        Group group = target.lookupGroupById(id);

                        if (group == null) {
                            err(request, response, 404, "objectNotFound", "Could not find the object");
                            return;
                        }

                        groupid = group.getName();
                    }

                }

                deleteGroup(response, groupid , id);

                response.setStatus(201);


        }
    }

    record NodeSearch(
        JsonNode node,
        JsonNode parent,
        String path,
        String op,
        String value
    ) {}

    record ObjectInfo(
            String objectName,
            String op,
            String value
    ) {}

    private ObjectInfo parseObjectName(String objectName) {
        String op = null;
        String value = null;
        int startBracket = objectName.indexOf('[');
        if (startBracket > 0) {
            int endBracket = objectName.indexOf(']');
            String filter = objectName.substring(startBracket + 1, endBracket);

            String trimmed = filter.trim();
            Matcher matcher = FILTER_PATTERN.matcher(trimmed);
            if (!matcher.matches()) {
                throw new IllegalArgumentException("Invalid filter format: " + filter);
            }

            op = matcher.group(1).toLowerCase(); // operator like eq, ne, etc.
            // The value can come from group 3 (double quotes), 4 (single quotes), or 5 (unquoted)
            value =
                    matcher.group(3) != null ? matcher.group(3) :
                            matcher.group(4) != null ? matcher.group(4) :
                                    matcher.group(5);

            objectName = objectName.substring(0,startBracket);
        }

        return new ObjectInfo(objectName,op,value);
    }

    private NodeSearch findObject(String path, JsonNode parent) {
        if (path.indexOf(':') > 0) {
            // remove the schema
            // not doing anything with the schema for now
            String schema = path.substring(0, path.indexOf(':'));
            path = path.substring(path.indexOf(':') + 1);
        }

        if (path.indexOf('.') > 0) {
            // there are children
            String objectName = path.substring(0, path.indexOf('.'));

            ObjectInfo objectInfo = parseObjectName(objectName);


            path = path.substring(path.indexOf('.') + 1);


            var obj = parent.get(objectInfo.objectName());
            if (obj != null) {
                // current object exists, look for children
                return findObject(path, obj);

            } else {
                // no object, return the value and false to indicate nothing found
                return new NodeSearch(null, parent, path,null,null);
            }
        } else {
            // get the object
            ObjectInfo objectInfo = parseObjectName(path);
            JsonNode node = parent.get(objectInfo.objectName());



            return new NodeSearch(node, parent, objectInfo.objectName(), objectInfo.op(), objectInfo.value());

        }
    }

    private void doPatch(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain) throws Exception {
        String[] p = split(request);
        if (p == null || p.length == 0) { err(request,response, 404, "invalidPath", "Unknown"); return; }
        if (!("Users".equals(p[0]) || "Groups".equals(p[0]))) { err(request,response, 404, "invalidPath", "Unknown POST"); return; }


        byte[] requestBytes = (byte[]) request.getAttribute(ProxySys.MSG_BODY);
        if (logger.isDebugEnabled()) {
            logger.debug(new String(requestBytes));
        }

        ByteArrayInputStream bais = new ByteArrayInputStream(requestBytes);

        ObjectNode payload = (ObjectNode) M.readTree(bais);
        String id = p[1];

        switch (p[0]) {
            case "Groups":
                String displayName = null;
                if (this.lookupFromLDAP) {
                    LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(this.searchBase, 2, "(" + this.groupIdName + "=" + id + ")", new ArrayList<String>());

                    if (!res.hasMore()) {
                        err(request, response, 404, "objectNotFound", "Could not find the object");
                        return;
                    }

                    LDAPEntry entry = res.next();

                    while (res.hasMore()) res.next();

                    LDAPAttribute displayNameAttribute = entry.getAttribute(this.groupLookupAttributeName);

                    if (displayNameAttribute == null) {
                        err(request, response, 400, "objectNotFound", "No " + this.groupLookupAttributeName + " attribute found");
                        return;
                    }

                    displayName = displayNameAttribute.getStringValue();
                } else {
                    UserStoreProviderLookups target = loadTarget(request, response);
                    if (target == null) {
                        return;
                    }

                    if (target.isGroupIdUniqueId()) {
                        displayName = id;
                    } else {
                        Group group = target.lookupGroupById(id);
                        if (group == null) {
                            err(request, response, 404, "objectNotFound", "Could not find the object");
                            return;
                        } else {
                            displayName = group.getName();
                        }
                    }


                }

                ArrayNode ops = (ArrayNode) payload.get("Operations");
                if (ops != null) {
                    for (JsonNode op : ops) {
                        String opType = op.get("op").asText();
                        String path = op.get("path").asText();
                        //remove schema
                        if (path.indexOf(':') >= 0) {
                            path = path.substring(path.indexOf(':') + 1);
                        }

                        if (! path.startsWith("members")) {
                            logger.warn("Only patching group members is supported," + path + " is not supported");
                        } else {
                            var found = findObject(path, op);
                            switch (opType) {
                                case "add":

                                    JsonNode values = op.get("value");

                                    if (values.isArray()) {
                                        ArrayNode valuesArray = (ArrayNode) values;
                                        for (JsonNode value : valuesArray) {
                                            String idToAdd = value.get("value").asText();
                                            memberGroupUpdate(request,response, idToAdd, displayName, true);
                                        }
                                    } else {
                                        String idToAdd = values.get("value").asText();
                                        memberGroupUpdate(request,response, idToAdd, displayName, true);
                                    }

                                    break;

                                case "remove":
                                    if (found.op() == null ||  ! found.op().equalsIgnoreCase("eq")) {
                                        throw new ProvisioningException("Only PATCH remove eq is supported");
                                    }

                                    if (found.value() == null || found.value().isEmpty()) {
                                        throw new ProvisioningException("When removing a member, a value must be specified in the path");
                                    }

                                    String idToRemove = found.value();
                                    memberGroupUpdate(request,response, idToRemove, displayName, false);

                                    break;

                                case "replace":
                                    // need to get all the current members
                                    ObjectNode currentGroup = null;
                                    if (this.lookupFromLDAP) {
                                        LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(this.searchBase, 2, "(" + this.groupIdName + "=" + id + ")", new ArrayList<String>());
                                        if (!res.hasMore()) {
                                            err(request, response, 404, "objectNotFound", "Could not find the  object");
                                            return;
                                        }


                                        LDAPEntry entry = res.next();

                                        while (res.hasMore()) res.next();

                                        currentGroup = ldapGroup2Scim(entry);
                                    } else {
                                        UserStoreProviderLookups target = loadTarget(request, response);
                                        if (target == null) {
                                            err(request, response, 500, "error", "Could not find the target");
                                            return;

                                        }

                                        Group group = null;

                                        if (target.isGroupIdUniqueId()) {
                                            group = target.lookupGroupByName(id);
                                        } else {
                                            group = target.lookupGroupById(id);
                                        }

                                        if (group == null) {
                                            err(request, response, 404, "objectNotFound", "Could not find the object");
                                        }

                                        currentGroup = tremoloGroup2Scim(group,target);
                                    }

                                    HashSet<String> currentMembers = new HashSet<String>();

                                    ArrayNode members = (ArrayNode) currentGroup.get("members");
                                    members.forEach(member -> {
                                        currentMembers.add(member.get("value").asText());
                                    });

                                    // go through the new members, provision for add and remove from the current members list
                                    values = op.get("value");

                                    if (values.isArray()) {
                                        ArrayNode valuesArray = (ArrayNode) values;
                                        for (JsonNode value : valuesArray) {
                                            String idToAdd = value.get("value").asText();
                                            memberGroupUpdate(request,response, idToAdd, displayName, true);
                                            currentMembers.remove(idToAdd);
                                        }
                                    } else {
                                        String idToAdd = values.get("value").asText();
                                        memberGroupUpdate(request,response, idToAdd, displayName, true);
                                        currentMembers.remove(idToAdd);
                                    }

                                    for (String groupIdToRemove : currentMembers) {
                                        memberGroupUpdate(request,response, groupIdToRemove, displayName, false);
                                    }

                                    break;
                            }
                        }

                    };
                }

                ObjectNode copy = null;
                if (this.lookupFromLDAP) {
                    LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(this.searchBase, 2, "(" + this.groupIdName + "=" + id + ")", new ArrayList<String>());
                    if (!res.hasMore()) {
                        err(request, response, 404, "objectNotFound", "Could not find the  object");
                        return;
                    }


                    LDAPEntry entry = res.next();
                    while (res.hasMore()) res.next();

                    copy = ldapGroup2Scim(entry);
                } else {
                    UserStoreProviderLookups target = loadTarget(request, response);
                    if (target == null) {
                        err(request, response, 500, "error", "Could not find the target");
                        return;
                    }

                    Group group = null;

                    group = target.lookupGroupById(id);

                    if (group == null) {
                        err(request, response, 404, "objectNotFound", "Could not find the object");
                        return;
                    }

                    copy = tremoloGroup2Scim(group,target);
                }

                ensureMeta(copy, base(request), p[0], id, 1);


                response.setStatus(200);
                response.setHeader("Location", loc(base(request), p[0], id));
                setEtag(response, copy);
                write(request,response, 200, copy);

                break;
            case "Users":
                // load from MyVD - create a SCIM object
                final ObjectNode copyuser = M.createObjectNode();
                if (this.lookupFromLDAP) {
                    LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(this.searchBase, 2, "(" + this.idAttributeName + "=" + id + ")", new ArrayList<String>());


                    if (!res.hasMore()) {
                        err(request, response, 404, "objectNotFound", "Could not find the object");
                        return;
                    }


                    LDAPEntry entry = res.next();

                    while (res.hasMore()) res.next();


                    ldap2scim(entry, copyuser);
                } else {
                    UserStoreProviderLookups target = loadTarget(request, response);
                    if (target == null) {
                        err(request, response, 500, "error", "Could not find the target");
                        return;
                    }

                    User fromTarget = null;
                    if (target.isUniqueIdTremoloId()) {
                        fromTarget = target.lookupUserByLogin(id);
                    } else {
                        fromTarget = target.lookupUserById(id);
                    }

                    if (fromTarget == null) {
                        err(request, response, 404, "objectNotFound", "Could not find the object");
                        return;
                    }

                    tremolo2scim(fromTarget,target,copyuser);
                }

                // with the object loaded, apply the patch
                ops = (ArrayNode) payload.get("Operations");
                ops.forEach(op ->{
                    String opType = op.get("op").asText();
                    String path = op.get("path").asText();
                    NodeSearch found = findObject(path, copyuser);
                    switch (opType) {
                        case "add":

                            JsonNode values = op.get("value");
                            if (found.node() == null) {
                                // path doesn't exist, the parent was returned
                                // add value to the parent
                                if (found.parent() instanceof ObjectNode){
                                    ((ObjectNode)found.parent()).set(found.path(), values);
                                } else {
                                    // this shouldn't happen
                                    logger.warn(String.format("Path %s is not an object",op.get("path").asText()));
                                }
                            } else {
                                // the path exists, make sure its an array list, if it isn't then replace with an array list
                                if (found.node().isArray()) {
                                    ((ArrayNode) found.node()).add(values);
                                } else {
                                    ArrayNode newVals = M.createArrayNode();
                                    newVals.add(found.node());

                                    if (values.isArray()) {
                                        newVals.addAll((ArrayNode) values);
                                    } else {
                                        newVals.add(values);
                                    }

                                }
                            }

                            break;

                        case "remove":
                            if (found.node() != null) {
                                ((ObjectNode) found.parent()).remove(found.path());
                            }

                            break;

                        case "replace":
                            values = op.get("value");
                            ((ObjectNode) found.parent()).set(found.path(),values);
                            break;
                    }
                });

                if (logger.isDebugEnabled()) {
                    logger.debug("Updated: " + copyuser.toString());
                }
                // translate from a SCIM object to an OpenUnison user
                String uidAttr = copyuser.get(this.uidAttributeName).asText();
                User scimUser = new User(uidAttr);
                copyuser.fieldNames().forEachRemaining(name -> {
                    Attribute userAttr = new Attribute(name,copyuser.get(name).toString());
                    scimUser.getAttribs().put(name, userAttr);
                });
                scimUser.getAttribs().put(this.idAttributeName,new Attribute(this.idAttributeName,copyuser.get("id").asText()));
                runWorkflow(request, response, scimUser, copyuser, uidAttr, p,this.workflowName);
        }
    }

    private void doGet(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain) throws Exception {
        String[] p = split(request);
        if (p == null || p.length == 0) { err(request,response, 404, "invalidPath", "Unknown"); return; }
        if (!("Users".equals(p[0]) || "Groups".equals(p[0]) || "ResourceTypes".equals(p[0]) || "Schemas".equals(p[0]) )) { err(request,response, 404, "invalidPath", "Unknown GET"); return; }

        switch (p[0]) {
            //case "ServiceProviderConfig": write(response, 200, spc(base(request))); return;
            case "ResourceTypes":
                if (p.length == 1) {
                    write(request, response, 200, ScimSchema.resourceTypes(base(request)));
                    return;
                } else {
                    ObjectNode ret = ScimSchema.resourceType(base(request),p[1]);
                    if (ret != null) {
                        write(request, response, 200, ret);
                    } else {
                        err(request, response, 404, "invalidPath", "Unknown ResourceType");
                    }
                    return;
                }
            case "Schemas":
                  if (p.length == 1) {
                      if (logger.isDebugEnabled()) {
                          logger.debug("Allowed attributes " + this.allowedAttributes);
                      }
                      write(request, response, 200, ScimSchema.schemas(base(request),this.allowedAttributes));
                  } else {
                      ObjectNode ret = ScimSchema.schema(base(request),p[1],this.allowedAttributes);
                      if (ret != null) {
                          write(request, response, 200, ret);
                      } else {
                          err(request, response, 404, "invalidPath", "Unknown Schema");
                      }
                  }
                  return;

            case "Users":
            case "Groups":

                if (p.length == 1) {
                    // search

                    Attribute attr = request.getParameter("filter");




                    String ldapFilter = null;
                    boolean isUser = true;
                    if (p[0].equalsIgnoreCase("Users")) {

                        if (attr != null) {
                            String filter = attr.getValues().get(0);
                            String scimFilter = toLdapFilter(filter,true);
                            ldapFilter = "(&(objectClass=" + GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getUserObjectClass() + ")" + scimFilter + ")";
                        } else {
                            ldapFilter = "(&(objectClass=" + GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getUserObjectClass() + ")(" + this.idAttributeName + "=*))";
                        }

                    } else {

                        isUser = false;
                        if (attr != null) {
                            String filter = attr.getValues().get(0);
                            String scimFilter = toLdapFilter(filter,false);
                            ldapFilter = "(&(objectClass=" + GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getGroupObjectClass() + ")" + scimFilter + ")";
                        } else {
                            ldapFilter = "(&(objectClass=" + GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getGroupObjectClass() + ")(" + this.groupIdName + "=*))";
                        }
                    }

                    attr = request.getParameter("attributes");
                    HashSet<String> attributesToReturn = new HashSet<>();
                    if (attr != null) {
                        String[] attrNames = attr.getValues().get(0).split(",");
                        Arrays.stream(attrNames).forEach(name -> attributesToReturn.add(name.toLowerCase()));

                    }

                    ArrayNode resources = M.createArrayNode();
                    int numRes = 0;
                    if (this.lookupFromLDAP) {
                        LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(this.searchBase, 2, ldapFilter, new ArrayList<>());




                        while (res.hasMore()) {
                            LDAPEntry entry = res.next();

                            ObjectNode resp = M.createObjectNode();
                            if (isUser) {
                                ldap2scim(entry, resp);
                            } else {
                                resp = ldapGroup2Scim(entry);
                            }


                            filterAttributes(request, attributesToReturn, resp, p);

                            resources.add(resp);
                            numRes++;


                        }
                    } else {
                        UserStoreProviderLookups target = this.loadTarget(request, response);
                        if (target == null) {
                            err(request,response, 500, "error", "Could not load target");
                            return;
                        }

                        if (isUser) {
                            List<User> res = target.searchUsers(ldapFilter);
                            for (User u : res) {
                                ObjectNode resp = M.createObjectNode();
                                tremolo2scim(u,target,resp);
                                filterAttributes(request, attributesToReturn, resp, p);

                                resources.add(resp);
                                numRes++;
                            }
                        } else {
                            List<Group> res = target.searchGroups(ldapFilter);
                            for (Group g : res) {
                                ObjectNode resp = tremoloGroup2Scim(g,target);
                                filterAttributes(request, attributesToReturn, resp, p);

                                resources.add(resp);
                                numRes++;
                            }

                        }

                    }

                    ObjectNode allResults = M.createObjectNode();
                    ArrayNode schemas = M.createArrayNode();
                    schemas.add("urn:ietf:params:scim:api:messages:2.0:ListResponse");
                    allResults.put("schemas", schemas);
                    allResults.put("Resources", resources);
                    allResults.put("totalResults", numRes);
                    allResults.put("startIndex", 1);
                    allResults.put("itemsPerPage", numRes);

                    write(request,response, 200, allResults);


                } else {

                    // lookup
                    String id = p[1];
                    ObjectNode copy = M.createObjectNode();

                    if (p[0].equalsIgnoreCase("Users")) {

                        if (this.lookupFromLDAP) {
                            LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(this.searchBase, 2, "(" + this.idAttributeName + "=" + id + ")", new ArrayList<String>());
                            if (!res.hasMore()) {
                                err(request, response, 404, "objectNotFound", "Could not find the  object");
                                return;
                            }


                            LDAPEntry entry = res.next();

                            while (res.hasMore()) res.next();

                            ldap2scim(entry, copy);
                        } else {
                            UserStoreProviderLookups target = this.loadTarget(request, response);
                            if (target == null) {
                                err(request,response, 500, "error", "Could not load target");
                                return;
                            }

                            User user = null;


                            user = target.lookupUserById(id);


                            tremolo2scim(user,target,copy);
                        }


                    } else {
                        if (this.lookupFromLDAP) {
                            LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(this.searchBase, 2, "(" + this.groupIdName + "=" + id + ")", new ArrayList<String>());
                            if (!res.hasMore()) {
                                err(request, response, 404, "objectNotFound", "Could not find the  object");
                                return;
                            }


                            LDAPEntry entry = res.next();
                            while (res.hasMore()) res.next();
                            copy = ldapGroup2Scim(entry);
                        } else {
                            UserStoreProviderLookups target = this.loadTarget(request, response);
                            if (target == null) {
                                err(request,response, 500, "error", "Could not load target");
                                return;
                            }

                            Group group = null;
                            if (target.isGroupIdUniqueId()) {
                                group = target.lookupGroupByName(id);
                            } else {
                                group = target.lookupGroupById(id);
                            }

                            copy = tremoloGroup2Scim(group,target);
                        }
                    }

                    ensureMeta(copy, base(request), p[0], id, 1);


                    response.setStatus(200);
                    response.setHeader("Location", loc(base(request), p[0], id));
                    setEtag(response, copy);
                    write(request,response, 200, copy);

                    return;
                }
            default:
                err(request,response, 404, "invalidPath", "Unknown endpoint"); return;
        }



    }

    private void filterAttributes(HttpFilterRequest request, HashSet<String> attributesToReturn, ObjectNode resp, String[] p) {
        if (!attributesToReturn.isEmpty()) {
            List<String> toremove = new ArrayList<>();
            resp.fieldNames().forEachRemaining(name -> {
                if (!name.equalsIgnoreCase("id") && !attributesToReturn.contains(name.toLowerCase())) {
                    toremove.add(name);
                }
            });

            for (String name : toremove) {
                resp.remove(name);
            }

        }

        ensureMeta(resp, base(request), p[0], resp.get("id").textValue(), 1);
    }

    ObjectNode tremoloGroup2Scim(Group group,UserStoreProviderLookups target) throws ProvisioningException {
        ObjectNode copy = M.createObjectNode();

        String groupid = null;
        ArrayNode groupMemberIds = M.createArrayNode();

        if (target.isGroupMembersUniqueIds()) {
            // the target is already unique ids, no need to translate
            group.getMembers().forEach(member -> groupMemberIds.add(createGroupMember(member)));
        } else {
            // translate from names to unique ids
            group.getMembers().forEach(member -> {
                try {
                    User fromTarget = target.lookupUserByLogin(member);
                    if (fromTarget != null) {
                        if (target.isUniqueIdTremoloId()) {
                            groupMemberIds.add(createGroupMember(fromTarget.getUserID()));
                        } else {
                            groupMemberIds.add(createGroupMember(fromTarget.getAttribs().get(this.idAttributeName).getValues().get(0)));
                        }
                    } else {
                        logger.warn(String.format("Could not find %s",member));
                    }
                } catch (ProvisioningException e) {
                    logger.warn(String.format("Could not load %s",member), e);

                }
            });
        }

        if (groupMemberIds.size() > 0) {
            copy.put("members", groupMemberIds);
        }


        copy.put("displayName", group.getName());


        ArrayNode schemas = M.createArrayNode();
        schemas.add("urn:ietf:params:scim:schemas:core:2.0:Group");
        copy.put("schemas", schemas);


        if (target.isGroupIdUniqueId()) {
            groupid = group.getId();
        } else {
            Attribute groupidAttribute = group.getAttributes().get(this.groupIdName.toUpperCase());
            if (groupidAttribute != null) {
                groupid = groupidAttribute.getValues().get(0);
            } else {
                throw new ProvisioningException("No group id found for " + group.getId());
            }
        }

        copy.put("id", groupid);
        return copy;
    }

    ObjectNode ldapGroup2Scim(LDAPEntry group) throws ProvisioningException {
        ObjectNode copy = M.createObjectNode();

        String groupid = null;
        ArrayNode groupMemberIds = M.createArrayNode();

        if (this.lookupFromLDAP) {
            LDAPAttribute groupLdapMembers = group.getAttribute(this.groupMemberAttributeName);
            List<ByteArray> vals = groupLdapMembers.getAllValues();
            vals.forEach(memberDNBytes -> {
                String memberDN = new String(memberDNBytes.getValue());
                try {
                    LDAPSearchResults memberSearch = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(memberDN, 0, "(objectClass=*)", new ArrayList<String>());
                    if (memberSearch.hasMore()) {

                        LDAPEntry memberEntry = memberSearch.next();
                        LDAPAttribute userUUID = memberEntry.getAttribute(this.idAttributeName);
                        if (userUUID != null) {
                            String memberUUID = userUUID.getStringValue();
                            ObjectNode memberNode = createGroupMember(memberUUID);
                            groupMemberIds.add(memberNode);
                        }


                    }

                    while (memberSearch.hasMore()) memberSearch.next();
                } catch (LDAPException e) {
                    if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
                        logger.warn(String.format("User DN %s not found", memberDN));
                    } else {
                        logger.warn("Could not load member", e);
                    }

                }
            });


            if (groupMemberIds.size() > 0) {
                copy.put("members", groupMemberIds);
            }

            LDAPAttribute displayNameAttribute = group.getAttribute(this.groupLookupAttributeName);
            if (displayNameAttribute != null) {
                copy.put("displayName", displayNameAttribute.getStringValue());
            }

            ArrayNode schemas = M.createArrayNode();
            schemas.add("urn:ietf:params:scim:schemas:core:2.0:Group");
            copy.put("schemas", schemas);

            LDAPAttribute groupidAttribute = group.getAttribute(this.groupIdName);

            if (groupidAttribute != null) {
                groupid = groupidAttribute.getStringValue();
            } else {
                throw new ProvisioningException("No group id found for " + group.getDN());
            }
        }

        copy.put("id", groupid);

        return copy;
    }

    private static ObjectNode createGroupMember(String memberUUID) {
        ObjectNode memberNode = M.createObjectNode();
        memberNode.put("type", "User");
        memberNode.put("value", memberUUID);
        return memberNode;
    }

    private void doPost(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain) throws Exception {
        String[] p = split(request);
        if (p == null || p.length == 0) { err(request,response, 404, "invalidPath", "Unknown"); return; }
        if (!("Users".equals(p[0]) || "Groups".equals(p[0]))) { err(request,response, 404, "invalidPath", "Unknown POST"); return; }

        byte[] requestBytes = (byte[]) request.getAttribute(ProxySys.MSG_BODY);
        if (logger.isDebugEnabled()) {
            logger.debug(new String(requestBytes));
        }
        ByteArrayInputStream bais = new ByteArrayInputStream(requestBytes);

        ObjectNode payload = (ObjectNode) M.readTree(bais);

        switch (p[0]) {
            case "Users":
                // translate from a SCIM object to an OpenUnison user
                JsonNode jsonNode = payload.get(this.uidAttributeName);
                if (jsonNode == null) {
                    err(request,response, 400, "invalidValue", "missing userName attribute");
                    return;
                }
                String uidAttr = payload.get(this.uidAttributeName).asText();
                User scimUser = new User(uidAttr);
                payload.fieldNames().forEachRemaining(name -> {
                    JsonNode node = payload.get(name);
                    if (node != null) {
                        String value = node.isTextual() ? node.asText() : node.toString();
                        Attribute userAttr = new Attribute(name, value);
                        scimUser.getAttribs().put(name, userAttr);
                    }
                });

                if (request.getMethod().equalsIgnoreCase("PUT")) {
                    scimUser.getAttribs().put(this.idAttributeName,new Attribute(this.idAttributeName,payload.get("id").asText()));
                }


                runWorkflow(request, response, scimUser, payload, uidAttr, p,this.workflowName);
                break;

            case "Groups":

                if (request.getMethod().equalsIgnoreCase("POST")) {


                    String displayName = payload.get("displayName") != null ? payload.get("displayName").asText() : null;
                    JsonNode members = payload.get("members");
                    if (members != null) {
                        if (members.isArray()) {
                            ArrayNode groupMembers = (ArrayNode) members;

                            for (JsonNode groupMember : groupMembers) {
                                JsonNode groupMemberValue = groupMember.get("value");

                                if (groupMemberValue == null) {
                                    err(request,response, 400, "invalidRequest", "members must have a value");
                                    return;
                                }

                                String memberid = groupMemberValue.asText();
                                if (memberGroupUpdate(request,response, memberid, displayName, true)) return;


                            }
                            ;
                        } else {
                            err(request,response, 400, "invalidRequest", "members must be an array");
                            return;
                        }
                    }

                    // now need to load it from LDAP
                    // lookup the user by the userName
                    if (request.getMethod().equalsIgnoreCase("DELETE")) {
                        response.setStatus(201);
                    } else {
                        ObjectNode copy = null;
                        if (this.lookupFromLDAP) {
                            LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(this.searchBase, 2, "(" + this.groupLookupAttributeName + "=" + displayName + ")", new ArrayList<String>());
                            if (!res.hasMore()) {
                                err(request, response, 409, "objectNotFound", "Could not find the created object");
                                return;
                            }
                            LDAPEntry entry = res.next();

                            while (res.hasMore()) res.next();

                            copy = this.ldapGroup2Scim(entry);

                        } else {
                            UserStoreProviderLookups target = this.loadTarget(request,response);
                            if (target == null) {
                                err(request,response,500,"error","Could not load target");
                                return;
                            }

                            Group group = null;

                            group = target.lookupGroupByName(displayName);


                            if (group == null) {
                                err(request, response, 409, "objectNotFound", "Could not find the created object");
                                return;
                            }

                            copy = tremoloGroup2Scim(group,target);

                        }



                        String groupid = copy.get("id").asText();
                        ensureMeta(copy, base(request), p[0], groupid, 1);


                        response.setStatus(201);
                        response.setHeader("Location", loc(base(request), p[0], groupid));

                        setEtag(response, copy);
                        write(request,response, 201, copy);

                    }
                } else if (request.getMethod().equalsIgnoreCase("PUT")) {
                    String id = payload.get("id").asText();
                    ObjectNode currentGroup = null;
                    if (this.lookupFromLDAP) {
                        LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(this.searchBase, 2, "(" + this.groupIdName + "=" + id + ")", new ArrayList<String>());
                        if (!res.hasMore()) {
                            err(request, response, 404, "objectNotFound", "Could not find the  object");
                            return;
                        }


                        LDAPEntry entry = res.next();

                        while (res.hasMore()) res.next();

                        currentGroup = ldapGroup2Scim(entry);
                    } else {
                        UserStoreProviderLookups target = this.loadTarget(request,response);
                        if (target == null) {
                            err(request,response,500,"error","Could not load target");
                        }

                        Group group = null;

                        group = target.lookupGroupById(id);

                        if (group == null) {
                            err(request, response, 409, "objectNotFound", "Could not find the  object");
                            return;
                        }

                        currentGroup = tremoloGroup2Scim(group,target);
                    }

                    String displayName = currentGroup.get("displayName").asText();
                    HashSet<String> currentMembers = new HashSet<String>();

                    ArrayNode members = (ArrayNode) currentGroup.get("members");
                    members.forEach(member -> {
                        currentMembers.add(member.get("value").asText());
                    });

                    // go through the new members, provision for add and remove from the current members list
                    JsonNode values = payload.get("members");

                    if (values.isArray()) {
                        ArrayNode valuesArray = (ArrayNode) values;
                        for (JsonNode value : valuesArray) {
                            String idToAdd = value.get("value").asText();
                            memberGroupUpdate(request,response, idToAdd, displayName, true);
                            currentMembers.remove(idToAdd);
                        }
                    } else {
                        String idToAdd = values.get("value").asText();
                        memberGroupUpdate(request,response, idToAdd, displayName, true);
                        currentMembers.remove(idToAdd);
                    }

                    for (String groupIdToRemove : currentMembers) {
                        memberGroupUpdate(request,response, groupIdToRemove, displayName, false);
                    }

                    ObjectNode copy = null;
                    if (this.lookupFromLDAP) {
                        LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(this.searchBase, 2, "(" + this.groupIdName + "=" + id + ")", new ArrayList<String>());
                        if (!res.hasMore()) {
                            err(request, response, 404, "objectNotFound", "Could not find the  object");
                            return;
                        }


                        LDAPEntry entry = res.next();

                        while (res.hasMore()) res.next();

                        copy = ldapGroup2Scim(entry);
                    } else {
                        UserStoreProviderLookups target = this.loadTarget(request,response);
                        if (target == null) {
                            err(request,response,500,"error","Could not load target");
                            return;
                        }

                        Group group = null;
                        if (target.isGroupIdUniqueId()) {
                            group = target.lookupGroupByName(id);
                        } else {
                            group = target.lookupGroupById(id);
                        }

                        if (group == null) {
                            err(request, response, 409, "objectNotFound", "Could not find the  object");
                            return;
                        }

                        copy = tremoloGroup2Scim(group,target);
                    }

                    ensureMeta(copy, base(request), p[0], id, 1);


                    response.setStatus(200);
                    response.setHeader("Location", loc(base(request), p[0], id));
                    setEtag(response, copy);
                    write(request,response, 200, copy);
                }
        }

    }

    private boolean deleteGroup(HttpFilterResponse response, String groupName, String groupId) throws LDAPException, IOException, ProvisioningException {

        HashMap<String,Object> wfrequest = new HashMap<>();

        wfrequest.put("groupname", groupName);
        wfrequest.put("groupid", groupId);

        User tsUser = new User("sys");
        tsUser.getAttribs().put(this.lookupAttributeName,new Attribute(this.lookupAttributeName,"sys"));
        tsUser.getAttribs().put(this.idAttributeName,new Attribute(this.idAttributeName, "sys"));

        Workflow wf = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getWorkFlow(this.groupDeleteWorkflow);
        wfrequest.put(ProvisioningParams.UNISON_EXEC_TYPE,ProvisioningParams.UNISON_EXEC_SYNC);

        wf.executeWorkflow(tsUser,wfrequest);
        return false;
    }

    private boolean memberGroupUpdate(HttpFilterRequest request,HttpFilterResponse response, String memberid, String displayName,boolean add) throws LDAPException, IOException, ProvisioningException {
        String userId = null;
        if (this.lookupFromLDAP) {
            LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(this.searchBase, 2, "(" + this.idAttributeName + "=" + memberid + ")", new ArrayList<String>());
            if (!res.hasMore()) {
                err(request, response, 404, "objectNotFound", "Could not find the member " + memberid);
                return true;
            }


            LDAPEntry entry = res.next();

            while (res.hasMore()) res.next();

            userId = entry.getAttribute(this.lookupAttributeName).getStringValue();

            while (res.hasMore()) res.next();
        } else {
            UserStoreProviderLookups target = this.loadTarget(request,response);
            if (target == null) {
                err(request,response,500,"error","Could not load target");
                return false;
            }

            if (target.isUniqueIdTremoloId()) {
                userId = memberid;
            } else {
                User userFromTremolo = target.lookupUserById(memberid);
                if (userFromTremolo == null) {
                    logger.warn(String.format("Could not find user with id %s",memberid));
                    return false;
                } else {
                    userId = userFromTremolo.getUserID();
                }
            }


        }

        HashMap<String,Object> wfrequest = new HashMap<>();
        wfrequest.put("removegroup",add ? "false" : "true");
        wfrequest.put("groupname", displayName);

        User tsUser = new User(userId);
        tsUser.getAttribs().put(this.lookupAttributeName,new Attribute(this.lookupAttributeName,userId));
        tsUser.getAttribs().put(this.idAttributeName,new Attribute(this.idAttributeName, memberid));

        Workflow wf = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getWorkFlow(this.groupWorkflow);
        wfrequest.put(ProvisioningParams.UNISON_EXEC_TYPE,ProvisioningParams.UNISON_EXEC_SYNC);

        wf.executeWorkflow(tsUser,wfrequest);
        return false;
    }

    private void runWorkflow(HttpFilterRequest request, HttpFilterResponse response, User scimUser, ObjectNode payload, String uidAttr, String[] p,String workflowName) throws ProvisioningException, LDAPException, IOException {
        User tremoloUser = this.scim2tremolo.mapUser(scimUser,true);
        if (scimUser.getAttribs().get(this.idAttributeName) != null && payload.get("id") != null) {
            tremoloUser.getAttribs().put(this.idAttributeName,new Attribute(this.idAttributeName,payload.get("id").asText()));
        }
        // check if there's a password

        if (payload.get("password") != null) {
            tremoloUser.setPassword(payload.get("password").asText());
        }

        // call the workflow
        Workflow wf = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getWorkFlow(workflowName);
        HashMap<String,Object> wfrequest = new HashMap<>();
        wfrequest.put(ProvisioningParams.UNISON_EXEC_TYPE,ProvisioningParams.UNISON_EXEC_SYNC);

        wf.executeWorkflow(tremoloUser,wfrequest);

        // lookup the user by the userName
        if (request.getMethod().equalsIgnoreCase("DELETE")) {
            response.setStatus(201);
        } else {
            String id = null;
            ObjectNode copy = null;
            if (this.lookupFromLDAP) {
                LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(this.searchBase, 2, "(" + this.lookupAttributeName + "=" + uidAttr + ")", new ArrayList<String>());
                if (!res.hasMore()) {
                    err(request, response, 409, "objectNotFound", "Could not find the created object");
                    return;
                }

                copy = M.createObjectNode();
                LDAPEntry entry = res.next();

                while (res.hasMore()) res.next();

                id = ldap2scim(entry, copy);
            } else {
                copy = M.createObjectNode();
                UserStoreProviderLookups target = this.loadTarget(request,response);
                if (target == null) {
                    err(request, response, 500, "error", "Could not find the target");
                    return;
                }

                User user = null;
                user = target.lookupUserByLogin(uidAttr);


                id = tremolo2scim(user,target,copy);
            }
            ensureMeta(copy, base(request), p[0], id, 1);


            response.setStatus(201);
            response.setHeader("Location", loc(base(request), p[0], id));
            setEtag(response, copy);
            write(request,response, 201, copy);

        }
    }

    private String user2scim(User fromTremolo, ObjectNode copy,UserStoreProviderLookups target) throws ProvisioningException {


        User forScim = this.tremolo2scim.mapUser(fromTremolo,true);


        String id = null;

        if (target.isUniqueIdTremoloId()) {
            id = fromTremolo.getUserID();
        } else {
            id = fromTremolo.getAttribs().get(this.idAttributeName).getValues().get(0);
        }




        copy.put("id", id);

        ArrayNode schemas = M.createArrayNode();
        schemas.add("urn:ietf:params:scim:schemas:core:2.0:User");
        copy.put("schemas", schemas);

        forScim.getAttribs().keySet().forEach(attrName -> {
            Attribute attr = forScim.getAttribs().get(attrName);
            String val = attr.getValues().get(0);
            boolean isJson = (val.startsWith("{") || val.startsWith("["));
            if (isJson) {
                try {
                    copy.put(attrName,M.readTree(val));
                } catch (JsonProcessingException e) {
                    logger.warn("Could not parse JSON " + val, e);
                }
            } else {
                if (attr.getValues().size() == 1) {
                    copy.put(attrName, val);
                } else {
                    ArrayNode array = M.createArrayNode();
                    attr.getValues().forEach(val2 -> array.add(val2));
                    copy.put(attrName, array);
                }
            }

        });
        return id;
    }

    private String ldap2scim(LDAPEntry entry, ObjectNode copy) throws ProvisioningException {
        User fromTremolo = new User(entry.getDN().toString());
        entry.getAttributeSet().keySet().forEach(
                attrName -> {
                    Attribute attr = new Attribute(attrName.toString());
                    LDAPAttribute ldap = entry.getAttribute(attrName.toString());
                    ldap.getAllValues().forEach(val -> attr.getValues().add(new String(val.getValue())));
                    fromTremolo.getAttribs().put(attrName.toString(), attr);
                }
        );

        User forScim = this.tremolo2scim.mapUser(fromTremolo,true);


        String id = entry.getAttribute(this.idAttributeName).getStringValue();


        copy.put("id", id);

        ArrayNode schemas = M.createArrayNode();
        schemas.add("urn:ietf:params:scim:schemas:core:2.0:User");
        copy.put("schemas", schemas);

        forScim.getAttribs().keySet().forEach(attrName -> {
            Attribute attr = forScim.getAttribs().get(attrName);
            if (attr.getValues().size() > 0) {
                String val = attr.getValues().get(0);
                boolean isJson = (val.startsWith("{") || val.startsWith("["));
                if (isJson) {

                    try {
                        copy.put(attrName, M.readTree(val));
                    } catch (JsonProcessingException e) {
                        logger.warn("Could not parse JSON " + val, e);
                    }
                } else {
                    if (! ScimSchema.isMultiValued(attrName)) {
                        copy.put(attrName, val);
                    } else {
                        ArrayNode array = M.createArrayNode();
                        attr.getValues().forEach(val2 -> array.add(val2));
                        copy.put(attrName, array);
                    }
                }
            }

        });
        return id;
    }

    private String tremolo2scim(User fromTremolo,UserStoreProviderLookups target, ObjectNode copy) throws ProvisioningException {


        User forScim = this.tremolo2scim.mapUser(fromTremolo,true);


        String id = null;

        if (target.isUniqueIdTremoloId()) {
            id = fromTremolo.getUserID();
        } else {
            id = fromTremolo.getAttribs().get(this.idAttributeName).getValues().get(0);
        }




        copy.put("id", id);

        ArrayNode schemas = M.createArrayNode();
        schemas.add("urn:ietf:params:scim:schemas:core:2.0:User");
        copy.put("schemas", schemas);

        forScim.getAttribs().keySet().forEach(attrName -> {
            Attribute attr = forScim.getAttribs().get(attrName);
            String val = attr.getValues().get(0);
            boolean isJson = (val.startsWith("{") || val.startsWith("["));
            if (isJson) {
                try {
                    copy.put(attrName,M.readTree(val));
                } catch (JsonProcessingException e) {
                    logger.warn("Could not parse JSON " + val, e);
                }
            } else {
                if (attr.getValues().size() == 1) {
                    copy.put(attrName, val);
                } else {
                    ArrayNode array = M.createArrayNode();
                    attr.getValues().forEach(val2 -> array.add(val2));
                    copy.put(attrName, array);
                }
            }

        });
        return id;
    }

    private  void err(HttpFilterRequest request,HttpFilterResponse resp, int code, String scimType, String detail) throws IOException {
        ObjectNode e = M.createObjectNode();
        e.set("schemas", M.createArrayNode().add("urn:ietf:params:scim:api:messages:2.0:Error"));
        e.put("scimType", scimType);
        e.put("detail", detail);
        e.put("status", Integer.toString(code));
        write(request,resp, code, e);
    }


    public String groupId2Dn(String memberid) throws LDAPException {
        LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(this.searchBase,2,"(" + this.idAttributeName + "=" + memberid + ")",new ArrayList<String>());
        if (! res.hasMore()) {
            return null;
        }


        LDAPEntry entry = res.next();

        while (res.hasMore()) res.next();

        return entry.getDN();


    }

    private String base(HttpFilterRequest req) {
        return ProxyTools.getInstance().getFqdnUrl(req.getRequestURL().toString(),req.getServletRequest());
    }


    @Override
    public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain, StringBuffer data) throws Exception {

    }

    @Override
    public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain, byte[] data, int length) throws Exception {

    }

    @Override
    public void initFilter(HttpFilterConfig config) throws Exception {
        this.rootUri = config.getUrlType().getUri();
        this.uidAttributeName = config.getAttribute("uidAttributeName").getValues().get(0);
        this.idAttributeName = config.getAttribute("idAttributeName").getValues().get(0);
        this.workflowName = config.getAttribute("workflowName").getValues().get(0);
        this.deleteUserWorkflowName = config.getAttribute("deleteUserWorkflowName").getValues().get(0);
        this.searchBase = config.getAttribute("searchBase").getValues().get(0);
        this.lookupAttributeName = config.getAttribute("lookupAttributeName").getValues().get(0);
        this.groupWorkflow = config.getAttribute("groupWorkflow").getValues().get(0);


        this.groupLookupAttributeName = config.getAttribute("groupLookupAttributeName").getValues().get(0);
        this.groupIdName = config.getAttribute("groupIdName").getValues().get(0);
        this.groupMemberAttributeName = config.getAttribute("groupMemberAttributeName").getValues().get(0);
        this.groupDeleteWorkflow = config.getAttribute("groupDeleteWorkflow").getValues().get(0);

        this.lookupFromLDAP = config.getAttribute("lookupFromLDAP").getValues().get(0).equalsIgnoreCase("true");

        if (! this.lookupFromLDAP) {
            this.lookupTarget = config.getAttribute("lookupTarget").getValues().get(0);
        }

        this.allowedAttributes = new HashSet<String>();
        this.allowedAttributes.add("id");

        Attribute scim2tremoloMapping = config.getAttribute("scim2tremolo");
        if (scim2tremoloMapping != null) {
            List<Map<String,String>> attrCfgs = new ArrayList<>();
            scim2tremoloMapping.getValues().forEach(attrName -> {
                HashMap<String,String> cfg = new HashMap<>();
                cfg.put("name", attrName);
                Attribute attr = config.getAttribute("scim2tremolo." + attrName + ".source");
                if (attr == null) {
                    logger.warn("Configuration " + "scim2tremolo." + attrName + ".source missing" );
                    return;
                } else {
                    cfg.put("source",attr.getValues().get(0));
                }

                attr = config.getAttribute("scim2tremolo." + attrName + ".sourceType");
                if (attr == null) {
                    logger.warn("Configuration " + "scim2tremolo." + attrName + ".sourceType missing" );
                    return;
                } else {
                    cfg.put("sourceType",attr.getValues().get(0));
                }

                attr = config.getAttribute("scim2tremolo." + attrName + ".targetType");
                if (attr == null) {
                    logger.warn("Configuration " + "scim2tremolo." + attrName + ".targetType missing" );
                } else {
                    cfg.put("targetType",attr.getValues().get(0));
                }

                attrCfgs.add(cfg);
            });
            this.scim2tremolo = new MapIdentity(attrCfgs,true);
        } else {
            logger.warn("No scim2tremolo mapping found");
            this.scim2tremolo = new MapIdentity(new ArrayList<>(),true);
        }

        Attribute tremolo2scimMapping = config.getAttribute("tremolo2scim");
        if (tremolo2scimMapping != null) {
            List<Map<String,String>> attrCfgs = new ArrayList<>();

            tremolo2scimMapping.getValues().forEach(attrName -> {
                HashMap<String,String> cfg = new HashMap<>();
                cfg.put("name", attrName);
                this.allowedAttributes.add(attrName);
                Attribute attr = config.getAttribute("tremolo2scim." + attrName + ".source");
                if (attr == null) {
                    logger.warn("Configuration " + "tremolo2scim." + attrName + ".source missing" );
                    return;
                } else {
                    cfg.put("source",attr.getValues().get(0));
                }

                attr = config.getAttribute("tremolo2scim." + attrName + ".sourceType");
                if (attr == null) {
                    logger.warn("Configuration " + "tremolo2scim." + attrName + ".sourceType missing" );
                    return;
                } else {
                    cfg.put("sourceType",attr.getValues().get(0));
                }

                attr = config.getAttribute("tremolo2scim." + attrName + ".targetType");
                if (attr == null) {
                    logger.warn("Configuration " + "tremolo2scim." + attrName + ".targetType missing" );
                } else {
                    cfg.put("targetType",attr.getValues().get(0));
                }

                attrCfgs.add(cfg);
            });

            this.tremolo2scim = new MapIdentity(attrCfgs,true);
        } else {
            logger.warn("No tremolo2scim mapping found");
        }

        this.scimFilterAttrib2Ldap = new HashMap<>();
        Attribute filterMap = config.getAttribute("userFilterScim2Ldap");
        if (filterMap != null) {
            filterMap.getValues().forEach(map -> {
               String scim = map.substring(0,map.indexOf('='));
               String ldap = map.substring(map.indexOf('=')+1);
               this.scimFilterAttrib2Ldap.put(scim.toLowerCase(),ldap);
            });
        }

        this.scimGroupFilterAttrib2Ldap = new HashMap<>();
        filterMap = config.getAttribute("groupFilterScim2Ldap");
        if (filterMap != null) {
            filterMap.getValues().forEach(map -> {
                String scim = map.substring(0,map.indexOf('='));
                String ldap = map.substring(map.indexOf('=')+1);
                this.scimGroupFilterAttrib2Ldap.put(scim.toLowerCase(),ldap);
            });
        }
        
    }

    public  String toLdapFilter(String scimFilter,boolean userFilter) {
        if (scimFilter == null || scimFilter.isBlank()) {
            throw new IllegalArgumentException("SCIM filter must not be null or blank");
        }

        Tokenizer tokenizer = new Tokenizer(scimFilter,userFilter);
        Parser parser = new Parser(tokenizer);
        String ldap = parser.parseExpression();

        if (tokenizer.peek().type != TokenType.EOF) {
            throw new IllegalArgumentException("Trailing input after valid filter: " + tokenizer.peek().text);
        }

        return ldap;
    }

    // ===== Lexical analysis =====

    private enum TokenType {
        IDENT,      // attribute names, bare values
        STRING,     // "quoted value"
        AND,
        OR,
        NOT,
        EQ, NE, CO, SW, EW, GT, GE, LT, LE, PR,
        LPAREN, RPAREN,
        EOF
    }

    private record Token(TokenType type, String text) { }

    private static final class Tokenizer {
        private final String input;
        private int pos;
        private Token lookahead;
        boolean userFilter;


        Tokenizer(String input,boolean userFilter) {
            this.input = input;
            this.pos = 0;
            this.lookahead = null;
            this.userFilter = userFilter;

        }

        Token peek() {
            if (lookahead == null) {
                lookahead = nextTokenInternal();
            }
            return lookahead;
        }

        Token consume() {
            Token t = peek();
            lookahead = null;
            return t;
        }

        private Token nextTokenInternal() {
            skipWhitespace();
            if (pos >= input.length()) {
                return new Token(TokenType.EOF, "");
            }

            char c = input.charAt(pos);

            // Parentheses
            if (c == '(') {
                pos++;
                return new Token(TokenType.LPAREN, "(");
            }
            if (c == ')') {
                pos++;
                return new Token(TokenType.RPAREN, ")");
            }

            // Quoted string
            if (c == '"') {
                return readQuotedString();
            }

            // Identifier / keyword / operator
            if (isIdentStart(c)) {
                return readWord();
            }

            throw new IllegalArgumentException("Unexpected character at position " + pos + ": '" + c + "'");
        }

        private void skipWhitespace() {
            while (pos < input.length()) {
                char c = input.charAt(pos);
                if (!Character.isWhitespace(c)) {
                    break;
                }
                pos++;
            }
        }

        private boolean isIdentStart(char c) {
            // Accept letters, digits, underscore, dot, colon, dash
            return Character.isLetterOrDigit(c) || c == '_' || c == '.' || c == ':' || c == '-';
        }

        private Token readQuotedString() {
            StringBuilder sb = new StringBuilder();
            pos++; // skip opening quote

            while (pos < input.length()) {
                char c = input.charAt(pos++);
                if (c == '"') {
                    // end
                    return new Token(TokenType.STRING, sb.toString());
                }
                // simplistic: no escape support here; add if needed
                sb.append(c);
            }
            throw new IllegalArgumentException("Unterminated quoted string");
        }

        private Token readWord() {
            int start = pos;
            while (pos < input.length()) {
                char c = input.charAt(pos);
                if (!isIdentStart(c)) {
                    break;
                }
                pos++;
            }
            String text = input.substring(start, pos);
            String lower = text.toLowerCase(Locale.ROOT);

            return switch (lower) {
                case "and" -> new Token(TokenType.AND, text);
                case "or"  -> new Token(TokenType.OR, text);
                case "not" -> new Token(TokenType.NOT, text);
                case "eq"  -> new Token(TokenType.EQ, text);
                case "ne"  -> new Token(TokenType.NE, text);
                case "co"  -> new Token(TokenType.CO, text);
                case "sw"  -> new Token(TokenType.SW, text);
                case "ew"  -> new Token(TokenType.EW, text);
                case "gt"  -> new Token(TokenType.GT, text);
                case "ge"  -> new Token(TokenType.GE, text);
                case "lt"  -> new Token(TokenType.LT, text);
                case "le"  -> new Token(TokenType.LE, text);
                case "pr"  -> new Token(TokenType.PR, text);
                default    -> new Token(TokenType.IDENT, text);
            };
        }

        public boolean isUserFilter() {
            return userFilter;
        }


    }

    // ===== Parser (recursive descent) =====

    private  final class Parser {
        private final Tokenizer tokenizer;

        Parser(Tokenizer tokenizer) {
            this.tokenizer = tokenizer;
        }

        // expression := orExpr
        String parseExpression() {
            return parseOr();
        }

        // orExpr := andExpr ( OR andExpr )*
        private String parseOr() {
            List<String> parts = new ArrayList<>();
            parts.add(parseAnd());

            while (tokenizer.peek().type == TokenType.OR) {
                tokenizer.consume(); // OR
                parts.add(parseAnd());
            }

            if (parts.size() == 1) {
                return parts.get(0);
            }
            StringBuilder sb = new StringBuilder();
            sb.append("(|");
            for (String p : parts) {
                sb.append(p);
            }
            sb.append(")");
            return sb.toString();
        }

        // andExpr := notExpr ( AND notExpr )*
        private String parseAnd() {
            List<String> parts = new ArrayList<>();
            parts.add(parseNot());

            while (tokenizer.peek().type == TokenType.AND) {
                tokenizer.consume(); // AND
                parts.add(parseNot());
            }

            if (parts.size() == 1) {
                return parts.get(0);
            }
            StringBuilder sb = new StringBuilder();
            sb.append("(&");
            for (String p : parts) {
                sb.append(p);
            }
            sb.append(")");
            return sb.toString();
        }

        // notExpr := [ NOT ] primary
        private String parseNot() {
            if (tokenizer.peek().type == TokenType.NOT) {
                tokenizer.consume();
                String inner = parsePrimary();
                return "(!" + inner + ")";
            }
            return parsePrimary();
        }

        // primary := '(' expression ')' | condition
        private String parsePrimary() {
            if (tokenizer.peek().type == TokenType.LPAREN) {
                tokenizer.consume(); // '('
                String inner = parseExpression();
                Token t = tokenizer.consume();
                if (t.type != TokenType.RPAREN) {
                    throw new IllegalArgumentException("Expected ')' but found: " + t.text);
                }
                return inner;
            }
            return parseCondition();
        }

        // condition := attr [op value] | attr PR
        private String parseCondition() {
            Token attrTok = tokenizer.consume();
            if (attrTok.type != TokenType.IDENT) {
                throw new IllegalArgumentException("Expected attribute name, found: " + attrTok.text);
            }
            String attr = attrTok.text;

            Token opTok = tokenizer.consume();
            return switch (opTok.type) {
                case PR -> buildPresent(attr);

                case EQ, NE, CO, SW, EW, GT, GE, LT, LE -> {
                    Token valueTok = tokenizer.consume();
                    if (valueTok.type != TokenType.STRING && valueTok.type != TokenType.IDENT) {
                        throw new IllegalArgumentException("Expected value after operator " + opTok.text +
                                " for attribute " + attr);
                    }
                    String value = valueTok.text;
                    yield buildComparison(attr, opTok.type, value,tokenizer.isUserFilter());
                }

                default -> throw new IllegalArgumentException(
                        "Expected operator (eq, ne, co, sw, ew, gt, ge, lt, le, pr) after attribute " + attr +
                                " but found: " + opTok.text);
            };
        }
    }

    // ===== SCIM -> LDAP fragment builders =====

    private String buildPresent(String attr) {
        return "(" + attr + "=*)";
    }

    private String buildComparison(String attr, TokenType op, String value,boolean userFilter) {
        if (userFilter) {
            String ldapAttr = this.scimFilterAttrib2Ldap.get(attr.toLowerCase());
            if (ldapAttr != null) {
                attr = ldapAttr;
            }
        } else {
            if (attr.toLowerCase().equalsIgnoreCase("member")) {
                attr = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getGroupMemberAttribute();
                if (this.lookupFromLDAP) {
                    try {
                        String memberdn = this.groupId2Dn(value);
                        if (memberdn != null) {
                            value = memberdn;
                        }
                    } catch (LDAPException e) {
                        logger.warn("Could not get the DN for the member " + value, e);
                    }


                }

            } else {
                String ldapAttr = this.scimGroupFilterAttrib2Ldap.get(attr.toLowerCase());
                if (ldapAttr != null) {
                    attr = ldapAttr;
                }
            }
        }

        String escaped = escapeLdap(value);

        return switch (op) {
            case EQ -> "(" + attr + "=" + escaped + ")";
            case NE -> "(!(" + attr + "=" + escaped + "))";

            case CO -> "(" + attr + "=*" + escaped + "*)";
            case SW -> "(" + attr + "=" + escaped + "*)";
            case EW -> "(" + attr + "=*" + escaped + ")";

            // LDAP only supports >= and <=.
            // We approximate:
            //   gt -> >=
            //   ge -> >=
            //   lt -> <=
            //   le -> <=
            case GT, GE -> "(" + attr + ">=" + escaped + ")";
            case LT, LE -> "(" + attr + "<=" + escaped + ")";

            default -> throw new IllegalArgumentException("Unsupported operator: " + op);
        };
    }

    // Escape per RFC 4515:  *, (, ), \, NUL
    private String escapeLdap(String value) {
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '*':
                    sb.append("\\2a");
                    break;
                case '(':
                    sb.append("\\28");
                    break;
                case ')':
                    sb.append("\\29");
                    break;
                case '\\':
                    sb.append("\\5c");
                    break;
                case '\u0000':
                    sb.append("\\00");
                    break;
                default:
                    sb.append(c);
            }
        }
        return sb.toString();
    }
}

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

package com.tremolosecurity.k8s.util;

import com.google.common.collect.ComparisonChain;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.tremolosecurity.myvd.dataObj.RoleInfo;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningTarget;
import com.tremolosecurity.proxy.auth.AddPortalRolesToUserData;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;
import jakarta.servlet.ServletException;
import org.apache.log4j.Logger;

import java.util.*;

import org.json.simple.JSONArray;

public class PortalGroupMapper {
    static PortalGroupMapper mapper = null;
    static Logger logger = Logger.getLogger(PortalGroupMapper.class);

    Map<String, RoleInfo> roles;
    String extSuffix;
    String intSuffix;

    String k8sTargetName;

    Map<String,String> role2label;

    public static PortalGroupMapper getInstance() {
        return mapper;
    }

    public static void initialize(String extSuffix, String intSuffix, String k8sTargetName,String role2labelCfg) {
        mapper = new PortalGroupMapper(extSuffix, intSuffix, k8sTargetName,role2labelCfg);
    }

    private PortalGroupMapper(String extSuffix, String intSuffix, String k8sTargetName,String role2labelCfg) {
        this.extSuffix = extSuffix;
        this.intSuffix = intSuffix;
        this.k8sTargetName = k8sTargetName;
        this.role2label = new HashMap<String, String>();

        StringTokenizer toker = new StringTokenizer(role2labelCfg,",",false);
        while (toker.hasMoreTokens()) {
            String token = toker.nextToken();
            int eq = token.indexOf('=');
            if (eq > 0) {
                String role = token.substring(0,eq);
                String label = token.substring(eq+1);
                this.role2label.put(role, label);
            }
        }

        this.roles = new HashMap<String,RoleInfo>();
    }

    public JSONArray generateMappings(List<String> groups, HashMap<String,Map<String,Map<String,Integer>>> clusterAz) throws ServletException{
        JSONArray portalGroupVals = new JSONArray();
        List<RoleInfo> sortedRoles = new ArrayList<RoleInfo>();
        Set<RoleInfo> addedRoles = new HashSet<RoleInfo>();


        for (String group : groups) {
            RoleInfo ri = this.roles.get(group);
            if (ri == null) {
                try {
                    ri = this.loadRoleInfo(group);





                } catch (ProvisioningException e) {
                    throw new ServletException("unable to load role " + group,e);
                }
            }

            if (clusterAz != null) {

                Map<String, Map<String, Integer>> cluster = clusterAz.get(ri.getCluster());
                if (cluster == null) {
                    cluster = new HashMap<String, Map<String, Integer>>();
                    clusterAz.put(ri.getCluster(), cluster);
                }

                Map<String, Integer> ns = cluster.get(ri.getNamespace());
                if (ns == null) {
                    ns = new HashMap<String, Integer>();
                    cluster.put(ri.getNamespace(), ns);
                }
                ns.put(ri.getName(), 1);
            }

            if (!addedRoles.contains(ri)) {
                sortedRoles.add(ri);
                addedRoles.add(ri);
            }

        }



        Collections.sort(sortedRoles, new Comparator<RoleInfo>() {
            @Override
            public int compare(RoleInfo o1, RoleInfo o2) {
                return ComparisonChain.start()
                        .compare(o1.getCluster(), o2.getCluster())
                        .compare(o1.getNamespace(), o2.getNamespace())
                        .compare(o1.getName(), o2.getName())
                        .result();
            }
        });



        for (RoleInfo ri : sortedRoles) {
            portalGroupVals.add(ri.toJSON());
        }

        return portalGroupVals;
    }

    public List<String> generateMappings(LDAPEntry entry) throws ProvisioningException {
        JSONArray portalGroupVals = new JSONArray();
        List<RoleInfo> sortedRoles = new ArrayList<RoleInfo>();
        Set<RoleInfo> addedRoles = new HashSet<RoleInfo>();

        LDAPAttribute groups = entry.getAttribute("groups");


        if (groups == null) {
            logger.warn("No groups attribute, returning an empty list");
            return new ArrayList<String>();
        }

        Enumeration enumer = groups.getStringValues();
        while (enumer.hasMoreElements()) {
            String group = (String) enumer.nextElement();
            RoleInfo ri = this.roles.get(group);
            if (ri == null) {
                    ri = this.loadRoleInfo(group);
            }

            if (!addedRoles.contains(ri)) {
                sortedRoles.add(ri);
                addedRoles.add(ri);
            }

        }



        Collections.sort(sortedRoles, new Comparator<RoleInfo>() {
            @Override
            public int compare(RoleInfo o1, RoleInfo o2) {
                return ComparisonChain.start()
                        .compare(o1.getCluster(), o2.getCluster())
                        .compare(o1.getNamespace(), o2.getNamespace())
                        .compare(o1.getName(), o2.getName())
                        .result();
            }
        });

        for (RoleInfo ri : sortedRoles) {
            portalGroupVals.add(ri.toJSON());
        }

        List<String> portalGroups = new ArrayList<String>();
        portalGroups.add(portalGroupVals.toString());

        return portalGroups;
    }

    OpenShiftTarget findTarget(String name) throws ProvisioningException {
        if (logger.isDebugEnabled()) logger.debug(String.format("looking for target '%s'", name));
        ProvisioningTarget target = null;

        try {
            target = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(name);
        } catch (ProvisioningException e) {

        }

        int lastDash = name.lastIndexOf('-');

        while (target == null && lastDash > 0) {

            if (lastDash > 0) {
                name = name.substring(0,lastDash);
                if (logger.isDebugEnabled()) logger.debug(String.format("looking for target '%s'", name));
                try {
                    target = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(name);
                } catch (ProvisioningException e) {
                    lastDash = name.lastIndexOf('-');
                }

            }
        }

        if (target != null) {
            if (logger.isDebugEnabled()) logger.debug("found target");
            return (OpenShiftTarget) target.getProvider();
        } else {
            if (logger.isDebugEnabled()) logger.debug("can't find target");
            return null;
        }
    }

    private RoleInfo loadRoleInfo(String roleName) throws ProvisioningException {
        if (logger.isDebugEnabled()) logger.debug(String.format("Looking for role '%s'", roleName));
        RoleInfo role = this.roles.get(roleName);
        if (role != null) {
            if (logger.isDebugEnabled()) logger.debug("found and returning");
            return role;
        } else {
            if (roleName.startsWith("k8s-")) {
                if (logger.isDebugEnabled()) logger.debug("roleName starts with k8s-");
                if (roleName.startsWith("k8s-cluster-")) {
                    if (logger.isDebugEnabled()) logger.debug("roleName starts with k8s-cluster-");

                    // lookup cluster
                    String localName = roleName;
                    if (localName.endsWith(extSuffix)) {
                        localName = localName.substring(0,localName.lastIndexOf(extSuffix));
                    } else if (localName.endsWith(this.intSuffix)) {
                        localName = localName.substring(0,localName.lastIndexOf(this.intSuffix));
                    }

                    if (logger.isDebugEnabled()) logger.debug(String.format("localName without suffix '%s'", localName));


                    localName = localName.substring("k8s-cluster-".length());

                    if (logger.isDebugEnabled()) logger.debug(String.format("localName without prefix '%s'", localName));

                    OpenShiftTarget target = this.findTarget(localName);
                    if (target != null) {

                        if (logger.isDebugEnabled()) logger.debug("Found target");

                        String clusterLabel = target.getLabel();
                        String roleLabel = localName.substring(target.getName().length() + 1);

                        role = new RoleInfo(Character.toUpperCase(roleLabel.charAt(0)) + roleLabel.substring(1),clusterLabel,"N/A");
                        this.roles.put(roleName, role);
                        return role;
                    } else {
                        role = new RoleInfo(roleName,"N/A","N/A");
                        return role;
                    }


                } else if (roleName.startsWith("k8s-namespace-")) {
                    String localName = roleName;
                    if (localName.endsWith(extSuffix)) {
                        localName = localName.substring(0,localName.lastIndexOf(extSuffix));
                    } else if (localName.endsWith(this.intSuffix)) {
                        localName = localName.substring(0,localName.lastIndexOf(this.intSuffix));
                    }

                    localName = localName.substring("k8s-namespace-".length());
                    String roleCfgNameFound = null;
                    for (String roleCfgName : this.role2label.keySet()) {
                        if (localName.startsWith(roleCfgName)) {
                            roleCfgNameFound = roleCfgName;
                            break;
                        }
                    }

                    if (roleCfgNameFound == null) {
                        role = new RoleInfo(roleName,"N/A","N/A");
                        return role;
                    }

                    localName = localName.substring(roleCfgNameFound.length() + 1);

                    OpenShiftTarget target = null;

                    try {
                        target = this.findTarget(localName);
                    } catch (ProvisioningException e) {
                        target = null;
                    }

                    if (target != null) {
                        String clusterLabel = target.getLabel();
                        String namespace = localName.substring(target.getName().length() + 1);
                        role = new RoleInfo(this.role2label.get(roleCfgNameFound),clusterLabel,namespace);
                        this.roles.put(roleName, role);
                        return role;
                    } else {
                        role = new RoleInfo(roleName,"N/A","N/A");
                        return role;
                    }

                }
            } else if (roleName.startsWith("approvers-k8s-")) {
                // approvers-k8s-cluster-ns
                String localName = roleName.substring("approvers-".length());
                if (localName.startsWith("k8s-k8s-")) {
                    localName = localName.substring("k8s-".length());
                }
                OpenShiftTarget target = this.findTarget(localName);
                if (target != null) {
                    String clusterLabel = target.getLabel();
                    String namespace = localName.substring(target.getName().length() + 1);
                    role = new RoleInfo("Approver",clusterLabel,namespace);
                    this.roles.put(roleName, role);
                    return role;
                } else {
                    role = new RoleInfo(roleName,"N/A","N/A");
                    return role;
                }

            } else {
                role = new RoleInfo(roleName,"N/A","N/A");
                this.roles.put(roleName, role);
                return role;
            }
        }

        // no cfg found
        role = new RoleInfo(roleName,"N/A","N/A");
        return role;
    }
}

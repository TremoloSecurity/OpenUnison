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

package com.tremolosecurity.provisioning.core.providers;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.UserStoreProviderLookups;
import com.tremolosecurity.provisioning.core.*;
import com.tremolosecurity.proxy.mappings.JavaScriptMappings;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import org.apache.log4j.Logger;
import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Value;
import org.graalvm.polyglot.io.IOAccess;
import org.graalvm.polyglot.proxy.ProxyExecutable;

import java.util.*;
import java.util.concurrent.CompletableFuture;

public class JavaScriptTarget implements UserStoreProviderWithAddGroup, UserStoreProviderWithMetadata, UserStoreProviderLookups {

    String javaScript;
    Map<String,Object> state;
    boolean initCompleted;

    Map<String,String> annotations;
    Map<String,String> labels;


    boolean createGroups;
    boolean userLookups;

    List<String> jsToLoad;

    static Logger logger = Logger.getLogger(JavaScriptTarget.class.getName());

    public JavaScriptTarget() {
        this.annotations = new HashMap<>();
        this.labels = new HashMap<>();
    }

    public Object execFunction(String functionName, Object... parameters) throws ProvisioningException{
        try {
            Context context = Context.newBuilder("js").allowAllAccess(true).allowIO(IOAccess.ALL).build();
            context.getBindings("js").putMember("state", state);
            context.getBindings("js").putMember("labels", labels);
            context.getBindings("js").putMember("annotations", annotations);

            if (this.jsToLoad.size() > 0) {
                JavaScriptMappings javascripts = (JavaScriptMappings) GlobalEntries.getGlobalEntries().get("javascripts");
                if (javascripts != null) {
                    this.jsToLoad.forEach(jsName -> {
                        String javascript = javascripts.getMapping(jsName);
                        if (javascript != null) {
                            context.eval("js", javascript);
                        } else {
                            logger.warn("JavScript " + jsName + " not found");
                        }
                    });
                } else {
                    logger.warn("No javascripts loader initialized");
                }
            }

            Value val = context.eval("js",this.javaScript);
            Value doTask = context.getBindings("js").getMember(functionName);

            Value result = doTask.execute(parameters);

            Object ret = result.as(Object.class);
            context.close();
            return ret;
        } catch (Throwable t) {
            throw new ProvisioningException("Could not execute function " + functionName, t);
        }
    }

    public void execFunctionVoid(String functionName, Object... parameters) throws ProvisioningException{
        try {
            Context context = Context.newBuilder("js").allowAllAccess(true).build();
            context.getBindings("js").putMember("state", state);

            if (this.jsToLoad.size() > 0) {
                JavaScriptMappings javascripts = (JavaScriptMappings) GlobalEntries.getGlobalEntries().get("javascripts");
                if (javascripts != null) {
                    this.jsToLoad.forEach(jsName -> {
                        String javascript = javascripts.getMapping(jsName);
                        if (javascript != null) {
                            context.eval("js", javascript);
                        } else {
                            logger.warn("JavScript " + jsName + " not found");
                        }
                    });
                } else {
                    logger.warn("No javascripts loader initialized");
                }
            }

            Value val = context.eval("js",this.javaScript);
            Value doTask = context.getBindings("js").getMember(functionName);
            doTask.executeVoid(parameters);

            context.close();

        } catch (Throwable t) {
            throw new ProvisioningException("Could not execute function " + functionName, t);
        }
    }

    @Override
    public User lookupUserByLogin(String login) throws ProvisioningException {
        if (! this.userLookups) {
            throw new ProvisioningException("enableUserLookups is false");
        }

        if (! this.initCompleted) {
            throw new ProvisioningException("JavaScript is not initialized");
        }

        Object result = execFunction("lookupUserByLogin", login);
        return (User) result;


    }

    @Override
    public User lookupUserById(String id) throws ProvisioningException {
        if (! this.userLookups) {
            throw new ProvisioningException("enableUserLookups is false");
        }

        if (! this.initCompleted) {
            throw new ProvisioningException("JavaScript is not initialized");
        }

        Object result = execFunction("lookupUserById", id);
        return (User) result;
    }

    @Override
    public Group lookupGroupById(String id) throws ProvisioningException {
        if (! this.userLookups) {
            throw new ProvisioningException("enableUserLookups is false");
        }

        if (! this.initCompleted) {
            throw new ProvisioningException("JavaScript is not initialized");
        }

        Object result = execFunction("lookupGroupById", id);
        return (Group) result;


    }

    @Override
    public Group lookupGroupByName(String groupName) throws ProvisioningException {
        if (! this.userLookups) {
            throw new ProvisioningException("enableUserLookups is false");
        }

        if (! this.initCompleted) {
            throw new ProvisioningException("JavaScript is not initialized");
        }

        Object result = execFunction("lookupGroupByName", groupName);
        return (Group) result;
    }

    @Override
    public boolean isGroupMembersUniqueIds() {

        if (! this.initCompleted) {
            return false;
        }

        try {
            Object result = execFunction("isGroupMembersUniqueIds");
            return (Boolean) result;
        } catch (ProvisioningException e) {
            logger.warn("isGroupMembersUniqueIds failed", e);
        }

        return false;
    }

    @Override
    public boolean isUniqueIdTremoloId() {

        if (! this.initCompleted) {
            return false;
        }

        try {
            Object result = execFunction("isUniqueIdTremoloId");
            return (Boolean) result;
        } catch (ProvisioningException e) {
            logger.warn("isUniqueIdTremoloId failed", e);
        }

        return false;
    }

    @Override
    public boolean isGroupIdUniqueId() {
        if (! this.initCompleted) {
            return false;
        }

        try {
            Object result = execFunction("isGroupIdUniqueId");
            return (Boolean) result;
        } catch (ProvisioningException e) {
            logger.warn("isGroupIdUniqueId failed", e);
        }


        return false;
    }



    @Override
    public List<User> searchUsers(String ldapFilter) throws ProvisioningException {
        if (! this.userLookups) {
            throw new ProvisioningException("enableUserLookups is false");
        }

        if (! this.initCompleted) {
            throw new ProvisioningException("JavaScript is not initialized");
        }

        Object result = execFunction("searchUsers", ldapFilter);
        return (List) result;
    }

    @Override
    public List<Group> searchGroups(String ldapFilter) throws ProvisioningException {
        if (! this.userLookups) {
            throw new ProvisioningException("enableUserLookups is false");
        }

        if (! this.initCompleted) {
            throw new ProvisioningException("JavaScript is not initialized");
        }

        Object result = execFunction("searchGroups", ldapFilter);
        return (List) result;
    }




    @Override
    public void addGroup(String name, Map<String, String> additionalAttributes, User user, Map<String, Object> request) throws ProvisioningException {
        if (! this.createGroups) {
            throw new ProvisioningException("enableCreateGroups is false");
        }

        if (! this.initCompleted) {
            throw new ProvisioningException("JavaScript is not initialized");
        }

        execFunctionVoid("addGroup", name, additionalAttributes);
    }

    @Override
    public void deleteGroup(String name, User user, Map<String, Object> request) throws ProvisioningException {
        if (! this.createGroups) {
            throw new ProvisioningException("enableCreateGroups is false");
        }

        if (! this.initCompleted) {
            throw new ProvisioningException("JavaScript is not initialized");
        }

        execFunctionVoid("deleteGroup", name, user);
    }

    @Override
    public boolean isGroupExists(String name, User user, Map<String, Object> request) throws ProvisioningException {
        if (! this.createGroups) {
            throw new ProvisioningException("enableCreateGroups is false");
        }

        if (! this.initCompleted) {
            throw new ProvisioningException("JavaScript is not initialized");
        }

        Object result = execFunction("isGroupExists", name, user);
        return (Boolean) result;
    }




    @Override
    public void createUser(User user, Set<String> attributes, Map<String, Object> request) throws ProvisioningException {
        if (! this.initCompleted) {
            throw new ProvisioningException("JavaScript is not initialized");
        }

        execFunctionVoid("createUser", user, attributes,request);
    }

    @Override
    public void setUserPassword(User user, Map<String, Object> request) throws ProvisioningException {
        if (! this.initCompleted) {
            throw new ProvisioningException("JavaScript is not initialized");
        }

        execFunctionVoid("setUserPassword", user);
    }

    @Override
    public void syncUser(User user, boolean addOnly, Set<String> attributes, Map<String, Object> request) throws ProvisioningException {
        if (! this.initCompleted) {
            throw new ProvisioningException("JavaScript is not initialized");
        }

        execFunctionVoid("syncUser", user, addOnly, attributes,request);
    }

    @Override
    public void deleteUser(User user, Map<String, Object> request) throws ProvisioningException {
        if (! this.initCompleted) {
            throw new ProvisioningException("JavaScript is not initialized");
        }

        execFunctionVoid("deleteUser", user,request);
    }

    @Override
    public User findUser(String userID, Set<String> attributes, Map<String, Object> request) throws ProvisioningException {
        if (! this.initCompleted) {
            throw new ProvisioningException("JavaScript is not initialized");
        }

        Object result = execFunction("findUser", userID, attributes);
        return (User) result;
    }


    private void checkFunctionExists(Context context, String functionName,String numberOfParameters,boolean required) throws ProvisioningException {
        Value function =  context.getBindings("js").getMember(functionName);
        if (function == null || ! function.canExecute()) {
            if (required) {
                throw new ProvisioningException("Function " + functionName + " must be defined with " + numberOfParameters + " parameters");
            } else {
                logger.warn("Function " + functionName + " is not defined");
            }
        }
    }

    @Override
    public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr, String name) throws ProvisioningException {
        initCompleted = false;

        Context context = Context.newBuilder("js").allowAllAccess(true).build();
        context.getBindings("js").putMember("state", state);



        try {

            this.jsToLoad = new ArrayList<String>();
            if (cfg.get("includeJs") != null) {
                jsToLoad.addAll(cfg.get("includeJs").getValues());
            }

            this.javaScript = cfg.get("javaScript").getValues().get(0);
            cfg.remove("javaScript");
            state = new HashMap<String,Object>();

            state.put("name",name);
            state.put("cfgMgr",cfgMgr);

            context.getBindings("js").putMember("state", state);

            if (this.jsToLoad.size() > 0) {
                JavaScriptMappings javascripts = (JavaScriptMappings) GlobalEntries.getGlobalEntries().get("javascripts");
                if (javascripts != null) {
                    this.jsToLoad.forEach(jsName -> {
                        String javascript = javascripts.getMapping(jsName);
                        if (javascript != null) {
                            context.eval("js", javascript);
                        } else {
                            logger.warn("JavScript " + jsName + " not found");
                        }
                    });
                } else {
                    logger.warn("No javascripts loader initialized");
                }
            }

            Value val = context.eval("js",this.javaScript);

            Value init = context.getBindings("js").getMember("init");
            if (init == null || ! init.canExecute()) {
                throw new ProvisioningException("init function must be defined with three parameters");
            }

            boolean requireAllFunctions = cfg.get("requireAllFunctions") == null || cfg.get("requireAllFunctions").getValues().get(0).equalsIgnoreCase("true");


            // check standard methods
            checkFunctionExists(context, "createUser", "four",requireAllFunctions);
            checkFunctionExists(context, "setUserPassword", "two",requireAllFunctions);
            checkFunctionExists(context, "syncUser", "four",requireAllFunctions);
            checkFunctionExists(context, "deleteUser", "two",requireAllFunctions);
            checkFunctionExists(context, "findUser", "three",requireAllFunctions);
            checkFunctionExists(context, "shutdown", "no",requireAllFunctions);

            if (cfg.get("enableCreateGroups") != null) {
                this.createGroups = Boolean.parseBoolean(cfg.get("enableCreateGroups").getValues().get(0));
                if (this.createGroups) {
                    checkFunctionExists(context, "addGroup", "four",requireAllFunctions);
                    checkFunctionExists(context, "deleteGroup", "three",requireAllFunctions);
                    checkFunctionExists(context, "isGroupExists", "three",requireAllFunctions);
                }
            }

            if (cfg.get("enableUserLookups") != null) {
                this.userLookups = Boolean.parseBoolean(cfg.get("enableUserLookups").getValues().get(0));
                if (this.userLookups) {
                    checkFunctionExists(context, "lookupUserByLogin", "one",requireAllFunctions);
                    checkFunctionExists(context, "lookupUserById", "one",requireAllFunctions);
                    checkFunctionExists(context, "lookupGroupById", "one",requireAllFunctions);
                    checkFunctionExists(context, "lookupGroupByName", "one",requireAllFunctions);
                    checkFunctionExists(context, "isGroupMembersUniqueIds", "none",requireAllFunctions);
                    checkFunctionExists(context, "isUniqueIdTremoloId", "none",requireAllFunctions);
                    checkFunctionExists(context, "isGroupIdUniqueId", "none",requireAllFunctions);
                    checkFunctionExists(context, "searchUsers", "one",requireAllFunctions);
                    checkFunctionExists(context, "searchGroups", "one",requireAllFunctions);

                }
            }




            init.executeVoid(cfg,cfgMgr,name);
            context.close();
            initCompleted = true;


        } catch (Throwable t) {
            logger.error("Could not initialize javascript task",t);
            return;
        }

    }

    @Override
    public void shutdown() throws ProvisioningException {

    }

    @Override
    public Map<String, String> getAnnotations() {
        return Map.of();
    }

    @Override
    public Map<String, String> getLabels() {
        return Map.of();
    }
}

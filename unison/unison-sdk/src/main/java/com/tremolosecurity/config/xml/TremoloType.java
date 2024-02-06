/*******************************************************************************
 * Copyright (c) 2024 Tremolo Security, Inc.
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
 *******************************************************************************/
//
// This file was generated by the Eclipse Implementation of JAXB, v3.0.0 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2024.02.03 at 03:46:44 PM EST 
//


package com.tremolosecurity.config.xml;

import java.math.BigInteger;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlType;


/**
 * 
 * 				The base configuration type for Unison
 * 			
 * 
 * <p>Java class for tremoloType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="tremoloType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="applications" type="{http://www.tremolosecurity.com/tremoloConfig}applicationsType"/&gt;
 *         &lt;element name="myvdConfig" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
 *         &lt;element name="authMechs" type="{http://www.tremolosecurity.com/tremoloConfig}authMechTypes"/&gt;
 *         &lt;element name="authChains" type="{http://www.tremolosecurity.com/tremoloConfig}authChainsType"/&gt;
 *         &lt;element name="customAzRules" type="{http://www.tremolosecurity.com/tremoloConfig}customAzRulesType" minOccurs="0"/&gt;
 *         &lt;element name="resultGroups" type="{http://www.tremolosecurity.com/tremoloConfig}resultGroupsType"/&gt;
 *         &lt;element name="keyStorePath" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
 *         &lt;element name="keyStorePassword" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
 *         &lt;element name="provisioning" type="{http://www.tremolosecurity.com/tremoloConfig}provisioningType" minOccurs="0"/&gt;
 *         &lt;element name="notifications" type="{http://www.tremolosecurity.com/tremoloConfig}notificationsType" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *       &lt;attribute name="ldapRoot" type="{http://www.w3.org/2001/XMLSchema}string" default="o=Tremolo" /&gt;
 *       &lt;attribute name="groupObjectClass" type="{http://www.w3.org/2001/XMLSchema}string" default="groupOfUniqueNames" /&gt;
 *       &lt;attribute name="groupMemberAttribute" type="{http://www.w3.org/2001/XMLSchema}string" default="uniqueMember" /&gt;
 *       &lt;attribute name="userObjectClass" type="{http://www.w3.org/2001/XMLSchema}string" default="inetOrgPerson" /&gt;
 *       &lt;attribute name="threadsPerRoute" type="{http://www.w3.org/2001/XMLSchema}integer" default="6" /&gt;
 *       &lt;attribute name="upgradeHandler" type="{http://www.w3.org/2001/XMLSchema}string" default="com.tremolosecurity.proxy.undertow.UndertowUpgradeRequestManager" /&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "tremoloType", propOrder = {
    "applications",
    "myvdConfig",
    "authMechs",
    "authChains",
    "customAzRules",
    "resultGroups",
    "keyStorePath",
    "keyStorePassword",
    "provisioning",
    "notifications"
})
public class TremoloType {

    @XmlElement(required = true)
    protected ApplicationsType applications;
    @XmlElement(required = true)
    protected String myvdConfig;
    @XmlElement(required = true)
    protected AuthMechTypes authMechs;
    @XmlElement(required = true)
    protected AuthChainsType authChains;
    protected CustomAzRulesType customAzRules;
    @XmlElement(required = true)
    protected ResultGroupsType resultGroups;
    @XmlElement(required = true)
    protected String keyStorePath;
    @XmlElement(required = true)
    protected String keyStorePassword;
    protected ProvisioningType provisioning;
    protected NotificationsType notifications;
    @XmlAttribute(name = "ldapRoot")
    protected String ldapRoot;
    @XmlAttribute(name = "groupObjectClass")
    protected String groupObjectClass;
    @XmlAttribute(name = "groupMemberAttribute")
    protected String groupMemberAttribute;
    @XmlAttribute(name = "userObjectClass")
    protected String userObjectClass;
    @XmlAttribute(name = "threadsPerRoute")
    protected BigInteger threadsPerRoute;
    @XmlAttribute(name = "upgradeHandler")
    protected String upgradeHandler;

    /**
     * Gets the value of the applications property.
     * 
     * @return
     *     possible object is
     *     {@link ApplicationsType }
     *     
     */
    public ApplicationsType getApplications() {
        return applications;
    }

    /**
     * Sets the value of the applications property.
     * 
     * @param value
     *     allowed object is
     *     {@link ApplicationsType }
     *     
     */
    public void setApplications(ApplicationsType value) {
        this.applications = value;
    }

    /**
     * Gets the value of the myvdConfig property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getMyvdConfig() {
        return myvdConfig;
    }

    /**
     * Sets the value of the myvdConfig property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setMyvdConfig(String value) {
        this.myvdConfig = value;
    }

    /**
     * Gets the value of the authMechs property.
     * 
     * @return
     *     possible object is
     *     {@link AuthMechTypes }
     *     
     */
    public AuthMechTypes getAuthMechs() {
        return authMechs;
    }

    /**
     * Sets the value of the authMechs property.
     * 
     * @param value
     *     allowed object is
     *     {@link AuthMechTypes }
     *     
     */
    public void setAuthMechs(AuthMechTypes value) {
        this.authMechs = value;
    }

    /**
     * Gets the value of the authChains property.
     * 
     * @return
     *     possible object is
     *     {@link AuthChainsType }
     *     
     */
    public AuthChainsType getAuthChains() {
        return authChains;
    }

    /**
     * Sets the value of the authChains property.
     * 
     * @param value
     *     allowed object is
     *     {@link AuthChainsType }
     *     
     */
    public void setAuthChains(AuthChainsType value) {
        this.authChains = value;
    }

    /**
     * Gets the value of the customAzRules property.
     * 
     * @return
     *     possible object is
     *     {@link CustomAzRulesType }
     *     
     */
    public CustomAzRulesType getCustomAzRules() {
        return customAzRules;
    }

    /**
     * Sets the value of the customAzRules property.
     * 
     * @param value
     *     allowed object is
     *     {@link CustomAzRulesType }
     *     
     */
    public void setCustomAzRules(CustomAzRulesType value) {
        this.customAzRules = value;
    }

    /**
     * Gets the value of the resultGroups property.
     * 
     * @return
     *     possible object is
     *     {@link ResultGroupsType }
     *     
     */
    public ResultGroupsType getResultGroups() {
        return resultGroups;
    }

    /**
     * Sets the value of the resultGroups property.
     * 
     * @param value
     *     allowed object is
     *     {@link ResultGroupsType }
     *     
     */
    public void setResultGroups(ResultGroupsType value) {
        this.resultGroups = value;
    }

    /**
     * Gets the value of the keyStorePath property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getKeyStorePath() {
        return keyStorePath;
    }

    /**
     * Sets the value of the keyStorePath property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setKeyStorePath(String value) {
        this.keyStorePath = value;
    }

    /**
     * Gets the value of the keyStorePassword property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    /**
     * Sets the value of the keyStorePassword property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setKeyStorePassword(String value) {
        this.keyStorePassword = value;
    }

    /**
     * Gets the value of the provisioning property.
     * 
     * @return
     *     possible object is
     *     {@link ProvisioningType }
     *     
     */
    public ProvisioningType getProvisioning() {
        return provisioning;
    }

    /**
     * Sets the value of the provisioning property.
     * 
     * @param value
     *     allowed object is
     *     {@link ProvisioningType }
     *     
     */
    public void setProvisioning(ProvisioningType value) {
        this.provisioning = value;
    }

    /**
     * Gets the value of the notifications property.
     * 
     * @return
     *     possible object is
     *     {@link NotificationsType }
     *     
     */
    public NotificationsType getNotifications() {
        return notifications;
    }

    /**
     * Sets the value of the notifications property.
     * 
     * @param value
     *     allowed object is
     *     {@link NotificationsType }
     *     
     */
    public void setNotifications(NotificationsType value) {
        this.notifications = value;
    }

    /**
     * Gets the value of the ldapRoot property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getLdapRoot() {
        if (ldapRoot == null) {
            return "o=Tremolo";
        } else {
            return ldapRoot;
        }
    }

    /**
     * Sets the value of the ldapRoot property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setLdapRoot(String value) {
        this.ldapRoot = value;
    }

    /**
     * Gets the value of the groupObjectClass property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getGroupObjectClass() {
        if (groupObjectClass == null) {
            return "groupOfUniqueNames";
        } else {
            return groupObjectClass;
        }
    }

    /**
     * Sets the value of the groupObjectClass property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setGroupObjectClass(String value) {
        this.groupObjectClass = value;
    }

    /**
     * Gets the value of the groupMemberAttribute property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getGroupMemberAttribute() {
        if (groupMemberAttribute == null) {
            return "uniqueMember";
        } else {
            return groupMemberAttribute;
        }
    }

    /**
     * Sets the value of the groupMemberAttribute property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setGroupMemberAttribute(String value) {
        this.groupMemberAttribute = value;
    }

    /**
     * Gets the value of the userObjectClass property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getUserObjectClass() {
        if (userObjectClass == null) {
            return "inetOrgPerson";
        } else {
            return userObjectClass;
        }
    }

    /**
     * Sets the value of the userObjectClass property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setUserObjectClass(String value) {
        this.userObjectClass = value;
    }

    /**
     * Gets the value of the threadsPerRoute property.
     * 
     * @return
     *     possible object is
     *     {@link BigInteger }
     *     
     */
    public BigInteger getThreadsPerRoute() {
        if (threadsPerRoute == null) {
            return new BigInteger("6");
        } else {
            return threadsPerRoute;
        }
    }

    /**
     * Sets the value of the threadsPerRoute property.
     * 
     * @param value
     *     allowed object is
     *     {@link BigInteger }
     *     
     */
    public void setThreadsPerRoute(BigInteger value) {
        this.threadsPerRoute = value;
    }

    /**
     * Gets the value of the upgradeHandler property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getUpgradeHandler() {
        if (upgradeHandler == null) {
            return "com.tremolosecurity.proxy.undertow.UndertowUpgradeRequestManager";
        } else {
            return upgradeHandler;
        }
    }

    /**
     * Sets the value of the upgradeHandler property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setUpgradeHandler(String value) {
        this.upgradeHandler = value;
    }

}

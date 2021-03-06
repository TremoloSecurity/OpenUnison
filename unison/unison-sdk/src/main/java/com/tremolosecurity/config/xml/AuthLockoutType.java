//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2021.05.06 at 10:01:59 AM EDT 
//


package com.tremolosecurity.config.xml;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlType;


/**
 * Configuration for making sure brute force attacks can't be used
 * 
 * <p>Java class for authLockoutType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="authLockoutType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;attribute name="enabled" type="{http://www.w3.org/2001/XMLSchema}boolean" default="false" />
 *       &lt;attribute name="maxFailedAttempts" type="{http://www.w3.org/2001/XMLSchema}int" />
 *       &lt;attribute name="maxLockoutTime" type="{http://www.w3.org/2001/XMLSchema}long" />
 *       &lt;attribute name="numFailedAttribute" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="lastFailedAttribute" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="lastSucceedAttribute" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="updateAttributesWorkflow" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="uidAttributeName" type="{http://www.w3.org/2001/XMLSchema}string" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "authLockoutType")
public class AuthLockoutType {

    @XmlAttribute(name = "enabled")
    protected Boolean enabled;
    @XmlAttribute(name = "maxFailedAttempts")
    protected Integer maxFailedAttempts;
    @XmlAttribute(name = "maxLockoutTime")
    protected Long maxLockoutTime;
    @XmlAttribute(name = "numFailedAttribute")
    protected String numFailedAttribute;
    @XmlAttribute(name = "lastFailedAttribute")
    protected String lastFailedAttribute;
    @XmlAttribute(name = "lastSucceedAttribute")
    protected String lastSucceedAttribute;
    @XmlAttribute(name = "updateAttributesWorkflow")
    protected String updateAttributesWorkflow;
    @XmlAttribute(name = "uidAttributeName")
    protected String uidAttributeName;

    /**
     * Gets the value of the enabled property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public boolean isEnabled() {
        if (enabled == null) {
            return false;
        } else {
            return enabled;
        }
    }

    /**
     * Sets the value of the enabled property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setEnabled(Boolean value) {
        this.enabled = value;
    }

    /**
     * Gets the value of the maxFailedAttempts property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getMaxFailedAttempts() {
        return maxFailedAttempts;
    }

    /**
     * Sets the value of the maxFailedAttempts property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setMaxFailedAttempts(Integer value) {
        this.maxFailedAttempts = value;
    }

    /**
     * Gets the value of the maxLockoutTime property.
     * 
     * @return
     *     possible object is
     *     {@link Long }
     *     
     */
    public Long getMaxLockoutTime() {
        return maxLockoutTime;
    }

    /**
     * Sets the value of the maxLockoutTime property.
     * 
     * @param value
     *     allowed object is
     *     {@link Long }
     *     
     */
    public void setMaxLockoutTime(Long value) {
        this.maxLockoutTime = value;
    }

    /**
     * Gets the value of the numFailedAttribute property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getNumFailedAttribute() {
        return numFailedAttribute;
    }

    /**
     * Sets the value of the numFailedAttribute property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setNumFailedAttribute(String value) {
        this.numFailedAttribute = value;
    }

    /**
     * Gets the value of the lastFailedAttribute property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getLastFailedAttribute() {
        return lastFailedAttribute;
    }

    /**
     * Sets the value of the lastFailedAttribute property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setLastFailedAttribute(String value) {
        this.lastFailedAttribute = value;
    }

    /**
     * Gets the value of the lastSucceedAttribute property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getLastSucceedAttribute() {
        return lastSucceedAttribute;
    }

    /**
     * Sets the value of the lastSucceedAttribute property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setLastSucceedAttribute(String value) {
        this.lastSucceedAttribute = value;
    }

    /**
     * Gets the value of the updateAttributesWorkflow property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getUpdateAttributesWorkflow() {
        return updateAttributesWorkflow;
    }

    /**
     * Sets the value of the updateAttributesWorkflow property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setUpdateAttributesWorkflow(String value) {
        this.updateAttributesWorkflow = value;
    }

    /**
     * Gets the value of the uidAttributeName property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getUidAttributeName() {
        return uidAttributeName;
    }

    /**
     * Sets the value of the uidAttributeName property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setUidAttributeName(String value) {
        this.uidAttributeName = value;
    }

}

//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2015.12.27 at 08:58:13 PM EST 
//


package com.tremolosecurity.config.xml;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlType;


/**
 * Database configuration for connecting to the scheduler database
 * 
 * <p>Java class for scheduleDBType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="scheduleDBType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;attribute name="delegateClassName" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="driver" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="url" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="user" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="password" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="maxConnections" type="{http://www.w3.org/2001/XMLSchema}int" />
 *       &lt;attribute name="validationQuery" type="{http://www.w3.org/2001/XMLSchema}string" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "scheduleDBType")
public class ScheduleDBType {

    @XmlAttribute(name = "delegateClassName")
    protected String delegateClassName;
    @XmlAttribute(name = "driver")
    protected String driver;
    @XmlAttribute(name = "url")
    protected String url;
    @XmlAttribute(name = "user")
    protected String user;
    @XmlAttribute(name = "password")
    protected String password;
    @XmlAttribute(name = "maxConnections")
    protected Integer maxConnections;
    @XmlAttribute(name = "validationQuery")
    protected String validationQuery;

    /**
     * Gets the value of the delegateClassName property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDelegateClassName() {
        return delegateClassName;
    }

    /**
     * Sets the value of the delegateClassName property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDelegateClassName(String value) {
        this.delegateClassName = value;
    }

    /**
     * Gets the value of the driver property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDriver() {
        return driver;
    }

    /**
     * Sets the value of the driver property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDriver(String value) {
        this.driver = value;
    }

    /**
     * Gets the value of the url property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getUrl() {
        return url;
    }

    /**
     * Sets the value of the url property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setUrl(String value) {
        this.url = value;
    }

    /**
     * Gets the value of the user property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getUser() {
        return user;
    }

    /**
     * Sets the value of the user property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setUser(String value) {
        this.user = value;
    }

    /**
     * Gets the value of the password property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPassword() {
        return password;
    }

    /**
     * Sets the value of the password property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPassword(String value) {
        this.password = value;
    }

    /**
     * Gets the value of the maxConnections property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getMaxConnections() {
        return maxConnections;
    }

    /**
     * Sets the value of the maxConnections property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setMaxConnections(Integer value) {
        this.maxConnections = value;
    }

    /**
     * Gets the value of the validationQuery property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getValidationQuery() {
        return validationQuery;
    }

    /**
     * Sets the value of the validationQuery property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setValidationQuery(String value) {
        this.validationQuery = value;
    }

}

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
 * Provides a mapping of the Unison user object. This
 * 				task creates a copy of the object for all children of this task
 * 			
 * 
 * <p>Java class for provisionMappingType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="provisionMappingType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *       &lt;/sequence>
 *       &lt;attribute name="targetAttributeName" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="targetAttributeSource" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="sourceType">
 *         &lt;simpleType>
 *           &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *             &lt;enumeration value="static"/>
 *             &lt;enumeration value="user"/>
 *             &lt;enumeration value="custom"/>
 *             &lt;enumeration value="composite"/>
 *           &lt;/restriction>
 *         &lt;/simpleType>
 *       &lt;/attribute>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "provisionMappingType")
public class ProvisionMappingType {

    @XmlAttribute(name = "targetAttributeName")
    protected String targetAttributeName;
    @XmlAttribute(name = "targetAttributeSource")
    protected String targetAttributeSource;
    @XmlAttribute(name = "sourceType")
    protected String sourceType;

    /**
     * Gets the value of the targetAttributeName property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getTargetAttributeName() {
        return targetAttributeName;
    }

    /**
     * Sets the value of the targetAttributeName property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setTargetAttributeName(String value) {
        this.targetAttributeName = value;
    }

    /**
     * Gets the value of the targetAttributeSource property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getTargetAttributeSource() {
        return targetAttributeSource;
    }

    /**
     * Sets the value of the targetAttributeSource property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setTargetAttributeSource(String value) {
        this.targetAttributeSource = value;
    }

    /**
     * Gets the value of the sourceType property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSourceType() {
        return sourceType;
    }

    /**
     * Sets the value of the sourceType property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSourceType(String value) {
        this.sourceType = value;
    }

}

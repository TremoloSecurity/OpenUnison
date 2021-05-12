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
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * Notify the subject of a workflow
 * 
 * <p>Java class for notifyUserType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="notifyUserType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://www.tremolosecurity.com/tremoloConfig}workflowTaskType">
 *       &lt;sequence>
 *         &lt;element name="msg" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *       &lt;/sequence>
 *       &lt;attribute name="subject" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="mailAttrib" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="contentType" type="{http://www.w3.org/2001/XMLSchema}string" />
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "notifyUserType", propOrder = {
    "msg"
})
public class NotifyUserType
    extends WorkflowTaskType
{

    @XmlElement(required = true)
    protected String msg;
    @XmlAttribute(name = "subject")
    protected String subject;
    @XmlAttribute(name = "mailAttrib")
    protected String mailAttrib;
    @XmlAttribute(name = "contentType")
    protected String contentType;

    /**
     * Gets the value of the msg property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getMsg() {
        return msg;
    }

    /**
     * Sets the value of the msg property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setMsg(String value) {
        this.msg = value;
    }

    /**
     * Gets the value of the subject property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSubject() {
        return subject;
    }

    /**
     * Sets the value of the subject property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSubject(String value) {
        this.subject = value;
    }

    /**
     * Gets the value of the mailAttrib property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getMailAttrib() {
        return mailAttrib;
    }

    /**
     * Sets the value of the mailAttrib property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setMailAttrib(String value) {
        this.mailAttrib = value;
    }

    /**
     * Gets the value of the contentType property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getContentType() {
        return contentType;
    }

    /**
     * Sets the value of the contentType property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setContentType(String value) {
        this.contentType = value;
    }

}

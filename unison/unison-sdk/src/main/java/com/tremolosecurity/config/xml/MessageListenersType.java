//
// This file was generated by the Eclipse Implementation of JAXB, v3.0.0 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2024.02.15 at 08:46:42 PM EST 
//


package com.tremolosecurity.config.xml;

import java.util.ArrayList;
import java.util.List;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlType;


/**
 * List of message listeners
 * 
 * <p>Java class for messageListenersType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="messageListenersType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="dynamicListeners" type="{http://www.tremolosecurity.com/tremoloConfig}dynamicPortalUrlsType" minOccurs="0"/&gt;
 *         &lt;element name="listener" type="{http://www.tremolosecurity.com/tremoloConfig}messageListenerType" maxOccurs="unbounded" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "messageListenersType", propOrder = {
    "dynamicListeners",
    "listener"
})
public class MessageListenersType {

    protected DynamicPortalUrlsType dynamicListeners;
    protected List<MessageListenerType> listener;

    /**
     * Gets the value of the dynamicListeners property.
     * 
     * @return
     *     possible object is
     *     {@link DynamicPortalUrlsType }
     *     
     */
    public DynamicPortalUrlsType getDynamicListeners() {
        return dynamicListeners;
    }

    /**
     * Sets the value of the dynamicListeners property.
     * 
     * @param value
     *     allowed object is
     *     {@link DynamicPortalUrlsType }
     *     
     */
    public void setDynamicListeners(DynamicPortalUrlsType value) {
        this.dynamicListeners = value;
    }

    /**
     * Gets the value of the listener property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the Jakarta XML Binding object.
     * This is why there is not a <CODE>set</CODE> method for the listener property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getListener().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link MessageListenerType }
     * 
     * 
     */
    public List<MessageListenerType> getListener() {
        if (listener == null) {
            listener = new ArrayList<MessageListenerType>();
        }
        return this.listener;
    }

}

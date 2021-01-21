//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vhudson-jaxb-ri-2.1-661
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a>
// Any modifications to this file will be lost upon recompilation of the source schema.
// Generated on: 2021.01.15 at 11:43:19 AM EST
//


package com.healthmarketscience.jackcess.crypt.model;

/**
 * <p>Java class for CT_DataIntegrity complex type.
 *
 * <p>The following schema fragment specifies the expected content contained within this class.
 *
 * <pre>
 * &lt;complexType name="CT_DataIntegrity">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;attribute name="encryptedHmacKey" use="required" type="{http://www.w3.org/2001/XMLSchema}base64Binary" />
 *       &lt;attribute name="encryptedHmacValue" use="required" type="{http://www.w3.org/2001/XMLSchema}base64Binary" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 *
 *
 */
// @XmlAccessorType(XmlAccessType.FIELD)
// @XmlType(name = "CT_DataIntegrity")
public class CTDataIntegrity {

    // @XmlAttribute(required = true)
    protected byte[] encryptedHmacKey;
    // @XmlAttribute(required = true)
    protected byte[] encryptedHmacValue;

    /**
     * Gets the value of the encryptedHmacKey property.
     *
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getEncryptedHmacKey() {
        return encryptedHmacKey;
    }

    /**
     * Sets the value of the encryptedHmacKey property.
     *
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setEncryptedHmacKey(byte[] value) {
        this.encryptedHmacKey = ((byte[]) value);
    }

    /**
     * Gets the value of the encryptedHmacValue property.
     *
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getEncryptedHmacValue() {
        return encryptedHmacValue;
    }

    /**
     * Sets the value of the encryptedHmacValue property.
     *
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setEncryptedHmacValue(byte[] value) {
        this.encryptedHmacValue = ((byte[]) value);
    }

}

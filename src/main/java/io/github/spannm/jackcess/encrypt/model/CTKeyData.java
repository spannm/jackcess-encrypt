//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vhudson-jaxb-ri-2.1-661
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a>
// Any modifications to this file will be lost upon recompilation of the source schema.
// Generated on: 2021.01.15 at 11:43:19 AM EST
//

package io.github.spannm.jackcess.encrypt.model;

/**
 * <p>Java class for CT_KeyData complex type.
 *
 * <p>The following schema fragment specifies the expected content contained within this class.
 *
 * <pre>
 * &lt;complexType name="CT_KeyData"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;attribute name="saltSize" use="required" type="{http://schemas.microsoft.com/office/2006/encryption}ST_SaltSize" /&gt;
 *       &lt;attribute name="blockSize" use="required" type="{http://schemas.microsoft.com/office/2006/encryption}ST_BlockSize" /&gt;
 *       &lt;attribute name="keyBits" use="required" type="{http://schemas.microsoft.com/office/2006/encryption}ST_KeyBits" /&gt;
 *       &lt;attribute name="hashSize" use="required" type="{http://schemas.microsoft.com/office/2006/encryption}ST_HashSize" /&gt;
 *       &lt;attribute name="cipherAlgorithm" use="required" type="{http://schemas.microsoft.com/office/2006/encryption}ST_CipherAlgorithm" /&gt;
 *       &lt;attribute name="cipherChaining" use="required" type="{http://schemas.microsoft.com/office/2006/encryption}ST_CipherChaining" /&gt;
 *       &lt;attribute name="hashAlgorithm" use="required" type="{http://schemas.microsoft.com/office/2006/encryption}ST_HashAlgorithm" /&gt;
 *       &lt;attribute name="saltValue" use="required" type="{http://www.w3.org/2001/XMLSchema}base64Binary" /&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 *
 *
 */
// @XmlAccessorType(XmlAccessType.FIELD)
// @XmlType(name = "CT_KeyData")
@SuppressWarnings("PMD.VisibilityModifier")
public class CTKeyData {

    // @XmlAttribute(required = true)
    protected long   saltSize;
    // @XmlAttribute(required = true)
    protected long   blockSize;
    // @XmlAttribute(required = true)
    protected long   keyBits;
    // @XmlAttribute(required = true)
    protected long   hashSize;
    // @XmlAttribute(required = true)
    protected String cipherAlgorithm;
    // @XmlAttribute(required = true)
    protected String cipherChaining;
    // @XmlAttribute(required = true)
    protected String hashAlgorithm;
    // @XmlAttribute(required = true)
    protected byte[] saltValue;

    /**
     * Gets the value of the saltSize property.
     *
     */
    public long getSaltSize() {
        return saltSize;
    }

    /**
     * Sets the value of the saltSize property.
     *
     */
    public void setSaltSize(long value) {
        this.saltSize = value;
    }

    /**
     * Gets the value of the blockSize property.
     *
     */
    public long getBlockSize() {
        return blockSize;
    }

    /**
     * Sets the value of the blockSize property.
     *
     */
    public void setBlockSize(long value) {
        this.blockSize = value;
    }

    /**
     * Gets the value of the keyBits property.
     *
     */
    public long getKeyBits() {
        return keyBits;
    }

    /**
     * Sets the value of the keyBits property.
     *
     */
    public void setKeyBits(long value) {
        this.keyBits = value;
    }

    /**
     * Gets the value of the hashSize property.
     *
     */
    public long getHashSize() {
        return hashSize;
    }

    /**
     * Sets the value of the hashSize property.
     *
     */
    public void setHashSize(long value) {
        this.hashSize = value;
    }

    /**
     * Gets the value of the cipherAlgorithm property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getCipherAlgorithm() {
        return cipherAlgorithm;
    }

    /**
     * Sets the value of the cipherAlgorithm property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setCipherAlgorithm(String value) {
        this.cipherAlgorithm = value;
    }

    /**
     * Gets the value of the cipherChaining property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getCipherChaining() {
        return cipherChaining;
    }

    /**
     * Sets the value of the cipherChaining property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setCipherChaining(String value) {
        this.cipherChaining = value;
    }

    /**
     * Gets the value of the hashAlgorithm property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    /**
     * Sets the value of the hashAlgorithm property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setHashAlgorithm(String value) {
        this.hashAlgorithm = value;
    }

    /**
     * Gets the value of the saltValue property.
     *
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getSaltValue() {
        return saltValue;
    }

    /**
     * Sets the value of the saltValue property.
     *
     * @param _value
     *     allowed object is
     *     byte[]
     */
    public void setSaltValue(byte[] _value) {
        this.saltValue = _value;
    }

}

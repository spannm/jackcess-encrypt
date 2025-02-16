package io.github.spannm.jackcess.encrypt.impl.office;

import io.github.spannm.jackcess.encrypt.InvalidCryptoConfigurationException;
import io.github.spannm.jackcess.encrypt.model.*;
import io.github.spannm.jackcess.encrypt.model.cert.CTCertificateKeyEncryptor;
import io.github.spannm.jackcess.encrypt.model.cert.STCertificateKeyEncryptorUri;
import io.github.spannm.jackcess.encrypt.model.password.CTPasswordKeyEncryptor;
import io.github.spannm.jackcess.encrypt.model.password.STPasswordKeyEncryptorUri;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

public final class XmlEncryptionParser {
    private static final Logger         LOGGER                      = System.getLogger(XmlEncryptionParser.class.getName());

    private static final String         ENC_NS                   = "http://schemas.microsoft.com/office/2006/encryption";
    private static final String         PWD_NS                   = "http://schemas.microsoft.com/office/2006/keyEncryptor/password";
    private static final String         CERT_NS                  = "http://schemas.microsoft.com/office/2006/keyEncryptor/certificate";

    private static final Base64.Decoder B64_DEC                  = Base64.getDecoder();

    private static final EntityResolver IGNORING_ENTITY_RESOLVER =
        new EntityResolver() {
            @Override
            public InputSource resolveEntity(String publicId, String systemId) throws SAXException, IOException {
                return new InputSource(new StringReader(""));
            }
        };

    private XmlEncryptionParser() {
    }

    public static CTEncryption parseEncryptionDescriptor(byte[] _xmlBytes) {
        try {
            Document doc = newBuilder().parse(new ByteArrayInputStream(_xmlBytes));

            Element encryptionEl = doc.getDocumentElement();
            if (!"encryption".equals(encryptionEl.getLocalName()) || !ENC_NS.equals(encryptionEl.getNamespaceURI())) {
                throw new InvalidCryptoConfigurationException("Unexpected xml config " + encryptionEl.getTagName());
            }

            return parseEncryption(encryptionEl);

        } catch (InvalidCryptoConfigurationException _ex) {
            throw _ex;
        } catch (Exception _ex) {
            throw new InvalidCryptoConfigurationException("Failed parsing encryption descriptor", _ex);
        }
    }

    private static CTEncryption parseEncryption(Element _encryptionEl) {
        CTEncryption encryption = new CTEncryption();

        encryption.setKeyData(parseKeyData(getElement(_encryptionEl, "keyData", ENC_NS, true)));
        encryption.setDataIntegrity(parseDataIntegrity(getElement(_encryptionEl, "dataIntegrity", ENC_NS, false)));
        encryption.setKeyEncryptors(parseKeyEncryptors(getElement(_encryptionEl, "keyEncryptors", ENC_NS, true)));

        return encryption;
    }

    private static CTKeyData parseKeyData(Element _keyDataEl) {
        CTKeyData keyData = new CTKeyData();

        keyData.setSaltSize(getLongAttribute(_keyDataEl, "saltSize"));
        keyData.setBlockSize(getLongAttribute(_keyDataEl, "blockSize"));
        keyData.setKeyBits(getLongAttribute(_keyDataEl, "keyBits"));
        keyData.setHashSize(getLongAttribute(_keyDataEl, "hashSize"));
        keyData.setCipherAlgorithm(getStringAttribute(_keyDataEl, "cipherAlgorithm"));
        keyData.setCipherChaining(getStringAttribute(_keyDataEl, "cipherChaining"));
        keyData.setHashAlgorithm(getStringAttribute(_keyDataEl, "hashAlgorithm"));
        keyData.setSaltValue(getBase64Attribute(_keyDataEl, "saltValue"));

        return keyData;
    }

    private static CTDataIntegrity parseDataIntegrity(Element _dataIntegrityEl) {
        if (_dataIntegrityEl == null) {
            return null;
        }

        CTDataIntegrity dataIntegrity = new CTDataIntegrity();

        dataIntegrity.setEncryptedHmacKey(getBase64Attribute(_dataIntegrityEl, "encryptedHmacKey"));
        dataIntegrity.setEncryptedHmacValue(getBase64Attribute(_dataIntegrityEl, "encryptedHmacValue"));

        return dataIntegrity;
    }

    private static CTKeyEncryptors parseKeyEncryptors(Element _keyEncryptorsEl) {
        CTKeyEncryptors keyEncryptors = new CTKeyEncryptors();

        for (Element encryptor : getElements(_keyEncryptorsEl, "keyEncryptor", ENC_NS)) {
            keyEncryptors.getKeyEncryptor().add(parseKeyEncryptor(encryptor));
        }

        return keyEncryptors;
    }

    private static CTKeyEncryptor parseKeyEncryptor(Element _keyEncryptorEl) {
        CTKeyEncryptor keyEncryptor = new CTKeyEncryptor();

        String typeUri = getStringAttribute(_keyEncryptorEl, "uri");
        keyEncryptor.setUri(typeUri);

        Object encryptor = null;
        if (STPasswordKeyEncryptorUri.HTTP_SCHEMAS_MICROSOFT_COM_OFFICE_2006_KEY_ENCRYPTOR_PASSWORD.value().equals(typeUri)) {
            encryptor = parsePasswordKeyEncryptor(_keyEncryptorEl);
        } else if (STCertificateKeyEncryptorUri.HTTP_SCHEMAS_MICROSOFT_COM_OFFICE_2006_KEY_ENCRYPTOR_CERTIFICATE.value().equals(typeUri)) {
            encryptor = parseCertificateKeyEncryptor(_keyEncryptorEl);
        } else {
            throw createException("Unexpected xml config ", typeUri, _keyEncryptorEl);
        }

        keyEncryptor.setAny(encryptor);

        return keyEncryptor;
    }

    private static CTPasswordKeyEncryptor parsePasswordKeyEncryptor(Element _parentEl) {
        Element pwdEncryptorEl = getElement(_parentEl, "encryptedKey", PWD_NS, true);

        CTPasswordKeyEncryptor pwdEncryptor = new CTPasswordKeyEncryptor();

        pwdEncryptor.setSaltSize(getLongAttribute(pwdEncryptorEl, "saltSize"));
        pwdEncryptor.setBlockSize(getLongAttribute(pwdEncryptorEl, "blockSize"));
        pwdEncryptor.setKeyBits(getLongAttribute(pwdEncryptorEl, "keyBits"));
        pwdEncryptor.setHashSize(getLongAttribute(pwdEncryptorEl, "hashSize"));
        pwdEncryptor.setCipherAlgorithm(getStringAttribute(pwdEncryptorEl, "cipherAlgorithm"));
        pwdEncryptor.setCipherChaining(getStringAttribute(pwdEncryptorEl, "cipherChaining"));
        pwdEncryptor.setHashAlgorithm(getStringAttribute(pwdEncryptorEl, "hashAlgorithm"));
        pwdEncryptor.setSaltValue(getBase64Attribute(pwdEncryptorEl, "saltValue"));
        pwdEncryptor.setSpinCount(getLongAttribute(pwdEncryptorEl, "spinCount"));
        pwdEncryptor.setEncryptedVerifierHashInput(getBase64Attribute(pwdEncryptorEl, "encryptedVerifierHashInput"));
        pwdEncryptor.setEncryptedVerifierHashValue(getBase64Attribute(pwdEncryptorEl, "encryptedVerifierHashValue"));
        pwdEncryptor.setEncryptedKeyValue(getBase64Attribute(pwdEncryptorEl, "encryptedKeyValue"));

        return pwdEncryptor;
    }

    private static CTCertificateKeyEncryptor parseCertificateKeyEncryptor(Element _parentEl) {
        Element certEncryptorEl = getElement(_parentEl, "encryptedKey", CERT_NS, true);

        CTCertificateKeyEncryptor certEncryptor = new CTCertificateKeyEncryptor();

        certEncryptor.setEncryptedKeyValue(getBase64Attribute(certEncryptorEl, "encryptedKeyValue"));
        certEncryptor.setX509Certificate(getBase64Attribute(certEncryptorEl, "x509Certificate"));
        certEncryptor.setCertVerifier(getBase64Attribute(certEncryptorEl, "certVerifier"));

        return certEncryptor;
    }

    private static Element getElement(Element _parentEl, String _localName, String _ns, boolean _required) {
        NodeList list = _parentEl.getElementsByTagNameNS(_ns, _localName);
        if ((list != null) && (list.getLength() > 0)) {
            return (Element) list.item(0);
        }
        if (!_required) {
            return null;
        }
        throw createException(_localName, _parentEl);
    }

    private static List<Element> getElements(Element _parentEl, String _localName, String _ns) {
        NodeList list = _parentEl.getElementsByTagNameNS(_ns, _localName);
        if ((list == null) || (list.getLength() == 0)) {
            return Collections.emptyList();
        }
        List<Element> els = new ArrayList<>();
        for (int i = 0; i < list.getLength(); ++i) {
            els.add((Element) list.item(i));
        }
        return els;
    }

    private static long getLongAttribute(Element _el, String _localName) {
        String attrValue = _el.getAttribute(_localName);
        if (attrValue == null || attrValue.isBlank()) {
            throw createException(_localName, _el);
        }
        return Long.parseLong(attrValue.trim());
    }

    private static String getStringAttribute(Element _el, String _localName) {
        String attrValue = _el.getAttribute(_localName);
        if (attrValue == null || attrValue.isBlank()) {
            throw createException(_localName, _el);
        }
        return attrValue;
    }

    private static byte[] getBase64Attribute(Element _el, String _localName) {
        String attrValue = _el.getAttribute(_localName);
        if (attrValue == null || attrValue.isBlank()) {
            throw createException(_localName, _el);
        }
        return B64_DEC.decode(attrValue);
    }

    private static DocumentBuilder newBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        maybeSetAttribute(factory, XMLConstants.ACCESS_EXTERNAL_DTD, "");
        maybeSetAttribute(factory, XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        factory.setIgnoringComments(true);
        factory.setCoalescing(true);
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.setEntityResolver(IGNORING_ENTITY_RESOLVER);
        return builder;
    }

    private static void maybeSetAttribute(DocumentBuilderFactory _factory, String _propName, String _propValue) {
        try {
            _factory.setAttribute(_propName, _propValue);
        } catch (IllegalArgumentException _ex) {
            LOGGER.log(Level.WARNING, "Xml parser does not support property " + _propName);
        }
    }

    private static InvalidCryptoConfigurationException createException(String _localName, Element _el) {
        return createException("Could not find xml config ", _localName, _el);
    }

    private static InvalidCryptoConfigurationException createException(String _context, String _localName, Element _el) {
        return new InvalidCryptoConfigurationException(_context + _localName + " under " + _el.getTagName());
    }

}

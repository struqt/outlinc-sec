package outlinc.sec.crypto;

import org.apache.commons.codec.binary.Base64;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class CryptoData {

    static public void accountAdd(String name, String secret, String keyStr, boolean debug) {
        EncryptAccount a = new EncryptAccount(name, new Base64().decode(keyStr), secret, debug);
        accounts.put(name, a);
    }

    static public boolean accountDebug(String name) {
        return accounts.containsKey(name) && accounts.get(name).debug;
    }

    static public String encryptToXml(String account, String message) throws XMLStreamException, GeneralSecurityException {
        return encryptToXml(account, message, null);
    }

    static public String errorXml(Integer error, String hint) {
        StringBuilder s = new StringBuilder();
        s.append('<').append("xml").append('>');
        makeXmlNode("error", error.toString(), s);
        if (hint != null && hint.length() > 0) {
            makeXmlCDataNode("hint", hint, s);
        }
        s.append('<').append('/').append("xml").append('>');
        return s.toString();
    }

    static public String encryptToXml(String account, String message, Map<String, String> debug) throws XMLStreamException, GeneralSecurityException {
        EncryptAccount a = accounts.get(account);
        if (a == null) {
            throw new GeneralSecurityException("No EncryptAccount with name: " + account);
        }
        CryptoData data = new CryptoData();
        data.account = account;
        data.message = message;
        return data.encryptToXml(a.secret, a.key, debug);
    }

    static public CryptoData decryptFromXml(String xml) throws XMLStreamException, GeneralSecurityException {
        Charset charset = UTF_8;
        return CryptoData.decryptFromXml(xml.getBytes(charset), charset);
    }

    static public CryptoData decryptFromXml(byte[] xml) throws XMLStreamException, GeneralSecurityException {
        return CryptoData.decryptFromXml(xml, UTF_8);
    }

    static public CryptoData decryptFromXml(byte[] xml, Charset charset) throws XMLStreamException, GeneralSecurityException {
        CryptoData data = decodeFromXml(xml, charset);
        if (data.getError() != 0) {
            return data;
        }
        EncryptAccount a = accounts.get(data.account);
        if (a == null) {
            throw new GeneralSecurityException("No EncryptAccount with name: " + data.account);
        }
        if (!data.checkSignature(a.secret)) {
            throw new GeneralSecurityException("Signature mismatch with name: " + data.account);
        }
        data.decrypt(a.key, a.debug);
        return data;
    }

    private String account = "";
    private String nonce = "";
    private String timestamp = "";
    private String message = "";
    private String encrypted;
    private String signature;
    private Integer error = 0;
    private String hint = "";

    private CryptoData() {
    }

    public Integer getError() {
        return error;
    }

    public String getErrorHint() {
        return hint;
    }

    public String getAccount() {
        return account;
    }

    public String getMessage() {
        return message;
    }

    private String encryptToXml(String token, byte[] key, Map<String, String> debug) throws GeneralSecurityException {
        if (nonce == null || nonce.length() <= 0) {
            nonce = String.valueOf(Math.abs(new Random().nextLong()));
        }
        if (timestamp == null || timestamp.length() <= 0) {
            timestamp = String.valueOf(System.currentTimeMillis() / 1000L);
        }
        if (message == null) {
            message = "";
        }
        if (token == null) {
            token = "";
        }
        byte[] bytes = CryptoHelper.encryptAES(key, message.getBytes(UTF_8));
        this.encrypted = new Base64().encodeToString(bytes);
        this.signature = CryptoHelper.SHA256(token + nonce + timestamp + encrypted);
        return encodeToXml(this, debug);
    }

    private void decrypt(byte[] key, boolean debug) throws GeneralSecurityException {
        byte[] bytes = Base64.decodeBase64(encrypted);
        byte[] decrypted = CryptoHelper.decryptAES(key, bytes);
        if (!debug || message == null || message.trim().length() <= 0) {
            message = new String(decrypted, UTF_8);
        } else {
            byte[] raw = CryptoHelper.encryptAES(key, message.getBytes(UTF_8));
            encrypted = new Base64().encodeToString(raw);
        }
    }

    private boolean checkSignature(String token) throws NoSuchAlgorithmException {
        return signature != null
            && signature.equals(CryptoHelper.SHA256(token + nonce + timestamp + encrypted));
    }

    private static final Charset UTF_8 = Charset.forName("utf-8");
    private static final XMLInputFactory fac = XMLInputFactory.newFactory();
    private static final Map<String, EncryptAccount> accounts = new HashMap<String, EncryptAccount>();

    static {
        fac.setProperty(XMLInputFactory.IS_NAMESPACE_AWARE, Boolean.FALSE);
        fac.setProperty(XMLInputFactory.IS_COALESCING, Boolean.FALSE);
        fac.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.FALSE);
        fac.setProperty(XMLInputFactory.IS_VALIDATING, Boolean.FALSE);
        fac.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);
        fac.setProperty(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, Boolean.FALSE);
    }

    static private CryptoData decodeFromXml(byte[] bytes, Charset charset) throws XMLStreamException {
        return decodeFromXml(new ByteArrayInputStream(bytes), charset.displayName());
    }

    static private CryptoData decodeFromXml(InputStream inp, String encoding) throws XMLStreamException {
        CryptoData data = new CryptoData();
        readXmlList(inp, data, encoding);
        return data;
    }

    static private void readXmlList(InputStream inp, CryptoData data, String encoding) throws XMLStreamException {
        XMLStreamReader reader = null;
        try {
            reader = fac.createXMLStreamReader(inp, encoding);
            readXmlList(reader, data);
        } finally {
            if (reader != null) {
                reader.close();
            }
        }
    }

    static private String encodeToXml(CryptoData data, Map<String, String> debug) {
        StringBuilder s = new StringBuilder();
        s.append('<').append("xml").append('>');
        makeXmlNode("account", data.account, s);
        makeXmlNode("nonce", data.nonce, s);
        makeXmlNode("timestamp", data.timestamp, s);
        makeXmlNode("encrypted", data.encrypted, s);
        makeXmlNode("signature", data.signature, s);
        if (debug != null && debug.size() > 0) {
            s.append('<').append("debug").append('>');
            for (Map.Entry<String, String> e : debug.entrySet()) {
                makeXmlCDataNode(e.getKey(), e.getValue(), s);
            }
            s.append('<').append('/').append("debug").append('>');
        }
        s.append('<').append('/').append("xml").append('>');
        return s.toString();
    }

    static private void readXmlList(XMLStreamReader reader, CryptoData data) throws XMLStreamException {
        String key = null;
        String val;
        while (reader.hasNext()) {
            int event = reader.getEventType();
            switch (event) {
                case XMLStreamConstants.START_ELEMENT:
                    key = reader.getLocalName();
                    break;
                case XMLStreamConstants.CHARACTERS:
                    val = reader.getText().trim();
                    if (key != null && key.length() > 0 && val.length() > 0) {
                        XmlElement elem = XmlElement.none;
                        try {
                            elem = XmlElement.valueOf(XmlElement.class, key);
                        } catch (Exception ignored) {
                        }
                        switch (elem) {
                            case account:
                                data.account = val;
                                break;
                            case nonce:
                                data.nonce = val;
                                break;
                            case timestamp:
                                data.timestamp = val;
                                break;
                            case message:
                                data.message = val;
                                break;
                            case encrypted:
                                data.encrypted = val;
                                break;
                            case signature:
                                data.signature = val;
                                break;
                            case error:
                                data.error = Integer.valueOf(val);
                                break;
                            case hint:
                                data.hint = val;
                                break;
                            default:
                                break;
                        }
                        key = null;
                    }
                    break;
                default:
                    break;
            }
            reader.next();
        }
    } /* readXmlList */

    static private void makeXmlNode(String name, String value, StringBuilder s) {
        s.append('<').append(name).append('>');
        s.append(value);
        s.append('<').append('/').append(name).append('>');
    }

    static private void makeXmlCDataNode(String name, String value, StringBuilder s) {
        s.append('<').append(name).append('>');
        s.append("<![CDATA[");
        s.append(value);
        s.append("]]>");
        s.append('<').append('/').append(name).append('>');
    }

    private enum XmlElement {
        none, account, nonce, timestamp, message, encrypted, signature, error, hint
    }

    static private class EncryptAccount {

        final String name;
        final byte[] key;
        final String secret;
        final boolean debug;

        private EncryptAccount(String name, byte[] key, String secret, boolean debug) {
            this.name = name;
            this.key = key;
            this.secret = secret;
            this.debug = debug;
        }
    }
}

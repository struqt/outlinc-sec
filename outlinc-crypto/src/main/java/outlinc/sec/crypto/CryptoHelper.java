package outlinc.sec.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class CryptoHelper {

    static private final SecureRandom random = new SecureRandom();
    static private final int ivBytesLen = 16;
    static private final int padBytesLenMax = 16; /*32*/
    private static final Map<String, EncryptAccount> accounts = new ConcurrentHashMap<String, EncryptAccount>();

    public static long randomLong() {
        return random.nextLong();
    }

    public static byte[] randomBytes(int len) {
        if (len < 0) {
            return null;
        }
        byte[] bytes = new byte[len];
        random.nextBytes(bytes);
        return bytes;
    }

    static public EncryptAccount account(String name) {
        return accounts.get(name);
    }

    /**
     * Check if the account support debug mode
     *
     * @param name Account name
     * @return Enable debug support
     */
    static public boolean accountDebug(String name) {
        return accounts.containsKey(name) && accounts.get(name).debug;
    }

    /**
     * Define an account for data encryption and decryption
     * You must define an account before encryption or decryption
     *
     * @param name   Account name
     * @param secret A secret string for message signature
     * @param keyStr A base64 encoded string as symmetric encryption key
     * @param debug  Enable debug support
     */
    static public void accountAdd(String name, String secret, String keyStr, boolean debug) {
        if (name == null || name.length() <= 0) {
            return;
        }
        byte[] key = decodeBase64(keyStr);
        if (key == null || key.length <= 0) {
            return;
        }
        EncryptAccount a = new EncryptAccount(name, key, secret, debug);
        accounts.put(name, a);
    }

    static public byte[] decodeBase64(final String base64) {
        return Base64.decode(base64);
    }

    static public String encodeBase64UrlSafe(final byte[] bytes) {
        return Base64.encodeToUrlSafe(bytes);
    }

    static public String encodeBase64Raw(final byte[] bytes) {
        return Base64.encodeToString(bytes);
    }

    public static byte[] encryptAES(byte[] key, byte[] content) throws GeneralSecurityException {
        byte[] ivBytes = new byte[ivBytesLen];
        random.nextBytes(ivBytes);
        byte[] lengthBytes = encodeInteger(content.length);
        int lenWithoutPad = ivBytesLen + lengthBytes.length + content.length;
        byte[] padBytes = encodePKCS7(lenWithoutPad);
        final int lenUnencrypted = lenWithoutPad + padBytes.length;
        byte[] unencrypted = new byte[lenUnencrypted];
        ByteBuffer.wrap(unencrypted)
            .put(ivBytes)
            .put(lengthBytes)
            .put(content)
            .put(padBytes);
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec iv = new IvParameterSpec(key, 0, ivBytesLen);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
        return cipher.doFinal(unencrypted);
    }

    public static byte[] decryptAES(byte[] key, byte[] encrypted) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec iv = new IvParameterSpec(Arrays.copyOfRange(key, 0, ivBytesLen));
        cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
        byte[] decrypted = cipher.doFinal(encrypted);
        int pad = (int) decrypted[decrypted.length - 1];
        if (pad < 1 || pad > padBytesLenMax) {
            pad = 0;
        }
        byte[] bytes = Arrays.copyOfRange(decrypted, 0, decrypted.length - pad);
        byte[] networkOrder = Arrays.copyOfRange(bytes, ivBytesLen, ivBytesLen + 4);
        int positionContent = ivBytesLen + networkOrder.length;
        int xmlLength = decodeInteger(networkOrder);
        return Arrays.copyOfRange(bytes, positionContent, positionContent + xmlLength);
    }

    public static String SHA256(String s) throws NoSuchAlgorithmException {
        return bytesToHexString(digest(s, "SHA-256"));
    }

    private static byte[] encodePKCS7(int count) {
        int amountToPad = padBytesLenMax - (count % padBytesLenMax);
        if (amountToPad == 0) {
            amountToPad = padBytesLenMax;
        }
        byte[] bytes = new byte[amountToPad];
        byte pad = (byte) (amountToPad & 0xFF);
        for (int i = 0; i < amountToPad; i++) {
            bytes[i] = pad;
        }
        return bytes;
    }

    private static byte[] encodeInteger(int i) {
        byte[] orderBytes = new byte[4];
        orderBytes[3] = (byte) (i & 0xFF);
        orderBytes[2] = (byte) (i >> 8 & 0xFF);
        orderBytes[1] = (byte) (i >> 16 & 0xFF);
        orderBytes[0] = (byte) (i >> 24 & 0xFF);
        return orderBytes;
    }

    private static int decodeInteger(byte[] bytes) {
        int n = 0;
        for (int i = 0; i < 4; i++) {
            n <<= 8;
            n |= bytes[i] & 0xFF;
        }
        return n;
    }

    static byte[] digest(String s, String algorithm) throws NoSuchAlgorithmException {
        byte[] bytes;
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        messageDigest.update(s.getBytes());
        bytes = messageDigest.digest();
        return bytes;
    }

    private static String bytesToHexString(byte[] digest) {
        if (digest == null || digest.length <= 0) {
            return "";
        }
        StringBuilder s = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            String tempStr = Integer.toHexString(b & 0xff);
            if (tempStr.length() == 1) {
                s.append('0');
            }
            s.append(tempStr);
        }
        return s.toString().toLowerCase();
    }


    static class EncryptAccount {

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

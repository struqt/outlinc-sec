package outlinc.sec.crypto;

import java.security.GeneralSecurityException;

public class CryptoToken {

    static private final char SPLIT = '@';

    static public String create(byte[] payload, String account) throws GeneralSecurityException {
        if (payload == null) {
            payload = new byte[0];
        }
        CryptoHelper.EncryptAccount a = CryptoHelper.account(account);
        if (a == null) {
            throw new GeneralSecurityException("No security account: " + account);
        }
        byte[] encrypted = CryptoHelper.encryptAES(a.key, payload);
        String encryptedBase64 = CryptoHelper.encodeBase64UrlSafe(encrypted);
        String sigContent = a.secret + account + encryptedBase64;
        String signature = CryptoHelper.encodeBase64UrlSafe(CryptoHelper.digest(sigContent, "SHA-256"));
        return account + SPLIT + encryptedBase64 + SPLIT + signature;
    }

    static public byte[] parse(String token) throws GeneralSecurityException {
        if (token == null || token.length() < 5) {
            throw new GeneralSecurityException("Bad token format");
        }
        String[] parts = token.split(String.valueOf(SPLIT));
        if (parts.length != 3) {
            throw new GeneralSecurityException("Bad token format, need 3 parts");
        }
        String account = parts[0];
        String encryptedBase64 = parts[1];
        String signature = parts[2];
        CryptoHelper.EncryptAccount a = CryptoHelper.account(account);
        if (a == null) {
            throw new GeneralSecurityException("No security account: " + account);
        }
        String sigContent = a.secret + account + encryptedBase64;
        if (!signature.equals(Base64.encodeToUrlSafe(CryptoHelper.digest(sigContent, "SHA-256")))) {
            throw new GeneralSecurityException("Signature mismatch");
        }
        byte[] encrypted = CryptoHelper.decodeBase64(encryptedBase64);
        return CryptoHelper.decryptAES(a.key, encrypted);
    }


}

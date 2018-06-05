package outlinc.sec;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import outlinc.sec.crypto.Base64;
import outlinc.sec.crypto.CryptoData;
import outlinc.sec.crypto.CryptoHelper;
import outlinc.sec.crypto.CryptoToken;

import javax.xml.stream.XMLStreamException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CryptoTest {

    private static final Charset UTF_8 = Charset.forName("utf-8");
    private static final byte[] key = CryptoHelper.randomBytes(16);
    private static final String account = "test";
    private static final String secret = "SNCreIFSRlCC3PE9v3DO";
    private static final String message = "hello 123 !";

    @BeforeClass
    public static void init() throws Exception {
        String k = Base64.encodeToString(key);
        CryptoHelper.accountAdd(account, secret, k, true);
        log("secret:%s, key:%s", secret, k);
        CryptoHelper.decryptAES(key, CryptoHelper.encryptAES(key, message.getBytes(UTF_8)));
        CryptoData.decryptFromXml(CryptoData.encryptToXml(account, message));
    }

    @Test
    public void test_01_AES() throws GeneralSecurityException {
        String text = "encrypted:<xml><account>test<|fjdajfkdsafjkldjf";
        byte[] encrypted = CryptoHelper.encryptAES(key, text.getBytes(UTF_8));
        byte[] decrypted = CryptoHelper.decryptAES(key, encrypted);
        Assert.assertEquals(text, new String(decrypted, UTF_8));
    }


    @Test
    public void test_02_EncryptData() throws GeneralSecurityException, XMLStreamException {

        Assert.assertTrue(CryptoData.accountDebug(account));

        String encrypted = CryptoData.encryptToXml(account, message);
        CryptoData decrypted = CryptoData.decryptFromXml(encrypted);

        Assert.assertEquals(account, decrypted.getAccount());
        Assert.assertEquals(message, decrypted.getMessage());

        String encrypted2 = CryptoData.encryptToXml(decrypted.getAccount(), decrypted.getMessage());
        CryptoData decrypted2 = CryptoData.decryptFromXml(encrypted2);

        Assert.assertEquals(account, decrypted2.getAccount());
        Assert.assertEquals(message, decrypted2.getMessage());

        log("encrypted: %s", encrypted);
        log("encrypted: %s", encrypted2);
    }

    @Test
    public void test_02_DecryptError() throws GeneralSecurityException, XMLStreamException {
        String error = CryptoData.errorXml(600, "Some Error!");
        CryptoData decrypted = CryptoData.decryptFromXml(error);
        Assert.assertEquals(600, decrypted.getError().intValue());
        Assert.assertEquals("Some Error!", decrypted.getErrorHint());
    }

    @Test
    public void test_03_CryptoToken() throws GeneralSecurityException {
        //String text = UUID.randomUUID().toString() + "|" + System.currentTimeMillis();
        String text = "1511263547389|a1be301c-2f0a-4799-b772-8e4479d67d1e";
        String token = CryptoToken.create(text.getBytes(UTF_8), account);
        byte[] payload = CryptoToken.parse(token);
        Assert.assertEquals(text, new String(payload, UTF_8));
        log("Payload: %s", text);
        log("Token  : %s", token);
    }

    static private void log(String template, Object... args) {
        String s = String.format(template, args);
        System.out.println(s);
    }

}

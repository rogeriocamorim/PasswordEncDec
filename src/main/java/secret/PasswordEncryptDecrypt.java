package secret;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class PasswordEncryptDecrypt {
    private static final String THIS_IS_MY_SECRET_KEY = "This_is_my_secret_key";

    private PasswordEncryptDecrypt() {
        throw new IllegalStateException("Utility class");
    }
    public static String encrypt(String decryptedMessage) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            SecretKey secretKey = new SecretKeySpec(getKey(THIS_IS_MY_SECRET_KEY).getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Hex.encodeHexString(cipher.doFinal(decryptedMessage.getBytes()));
        } catch (IllegalBlockSizeException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException |
                 BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public static String decrypt(String encryptedMessage) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            SecretKey secretKey = new SecretKeySpec(getKey(THIS_IS_MY_SECRET_KEY).getBytes(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Hex.decodeHex(encryptedMessage)));
        } catch (IllegalBlockSizeException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException |
                 DecoderException e) {
            throw new RuntimeException(e);
        }
    }

    public static String getKey(String key){
        //AES only supports key sizes of 16, 24 or 32 bytes
        var size = key.length();
        if (size>=32) {
            return key.substring(0,32);
        }
        if (size>=24) {
            return key.substring(0,24);
        }
        if (size >= 16) {
            return key.substring(0,16);
        }
        return key + new String(new char[16-size]).replace('\0', ' ');
    }


}
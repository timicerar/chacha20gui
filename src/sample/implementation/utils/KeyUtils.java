package sample.implementation.utils;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class KeyUtils {
    public static byte[] generateNonce(final int nonceSize) {
        int size = nonceSize < 8 ? 8 : nonceSize / 8;
        byte[] nonce = new byte[size];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    public static SecretKey generateKey(final String algorithm, final int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        keyGenerator.init(keySize, SecureRandom.getInstanceStrong());
        return keyGenerator.generateKey();
    }
}

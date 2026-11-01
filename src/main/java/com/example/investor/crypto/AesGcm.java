package com.example.investor.crypto;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class AesGcm {
    private static final SecureRandom RANDOM = new SecureRandom();
    private AesGcm() { }
    public static byte[] randomKey() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        return key;
    }
    public static byte[] encrypt(byte[] key, byte[] plaintext, byte[] aad) {
        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        byte[] encrypted = crypt(Cipher.ENCRYPT_MODE, key, nonce, plaintext, aad);
        byte[] result = Arrays.copyOf(nonce, nonce.length + encrypted.length);
        System.arraycopy(encrypted, 0, result, nonce.length, encrypted.length);
        return result;
    }
    public static byte[] decrypt(byte[] key, byte[] ciphertext, byte[] aad) {
        if (ciphertext.length < 28) { throw new CryptoFailure(); }
        return crypt(Cipher.DECRYPT_MODE, key, Arrays.copyOf(ciphertext, 12),
                Arrays.copyOfRange(ciphertext, 12, ciphertext.length), aad);
    }
    private static byte[] crypt(int mode, byte[] key, byte[] nonce, byte[] input, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) { throw new CryptoFailure(); }
    }
}

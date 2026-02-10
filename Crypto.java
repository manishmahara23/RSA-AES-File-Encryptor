package ml_project.cn;

// ... (imports remain the same)
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class Crypto {
    public static final String RSA_ALGO = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public static final String AES_ALGO = "AES/GCM/NoPadding";
    public static final int AES_KEY_SIZE = 256; // bits
    public static final int GCM_IV_LENGTH = 12; // bytes
    public static final int GCM_TAG_LENGTH = 16; // bytes (128 bits)

    
    // RSA keypair generation
    public static KeyPair generateRSAKeyPair(int bits) throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(bits);
        return kpg.generateKeyPair();
    }

    // AES key generation
    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_SIZE);
        return kg.generateKey();
    }

    // RSA encrypt (public)
    public static byte[] rsaEncrypt(byte[] data, PublicKey pub) throws Exception {
        Cipher c = Cipher.getInstance(RSA_ALGO);
        c.init(Cipher.ENCRYPT_MODE, pub);
        return c.doFinal(data);
    }

    // RSA decrypt (private)
    public static byte[] rsaDecrypt(byte[] data, PrivateKey priv) throws Exception {
        Cipher c = Cipher.getInstance(RSA_ALGO);
        c.init(Cipher.DECRYPT_MODE, priv);
        return c.doFinal(data);
    }

    // Create AES cipher in GCM mode for ENCRYPT/DECRYPT
    public static Cipher createAESCipher(int mode, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGO);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv); 
        cipher.init(mode, key, spec);
        return cipher;
    }

    public static SecretKey fromBytesToAESKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static PublicKey publicKeyFromBytes(byte[] pubBytes) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(pubBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}
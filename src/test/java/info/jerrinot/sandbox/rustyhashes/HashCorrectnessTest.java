package info.jerrinot.sandbox.rustyhashes;

import io.questdb.cutlass.auth.AuthUtils;
import io.questdb.jar.jni.JarJniLoader;
import io.questdb.std.MemoryTag;
import io.questdb.std.Unsafe;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Random;

public class HashCorrectnessTest {

    private final Random rnd = new Random();
    private static final int MAX_PASSWORD_LENGTH = 64;
    private static final int SALT_LENGTH = 16;
    private static final int PRIVATE_KEY_LENGTH = 32;
    private static final int PUBLIC_KEY_LENGTH = 65;
    private static final int MAX_SIGNATURE_LENGTH = 72;
    private static long passwordPtr;
    private static long saltPtr;
    private static long hashPtr;
    private static long privKeyPtr;
    private static long pubKeyPtr;
    private static long signaturePtr;
    private static long challengePtr;
    private static SecretKeyFactory secretKeyFactory;
    private static Signature sigDer;
    private static Signature sigP1363;

    @BeforeClass
    public static void prepareNative() throws NoSuchAlgorithmException {
        JarJniLoader.loadLib(RustyHashMain.class, "/info/jerrinot/sandbox/rustyhashes/bin", "rustyhashing");
        passwordPtr = Unsafe.malloc(MAX_PASSWORD_LENGTH, MemoryTag.NATIVE_DEFAULT);
        saltPtr = Unsafe.malloc(SALT_LENGTH, MemoryTag.NATIVE_DEFAULT);
        hashPtr = Unsafe.malloc(256 / 8, MemoryTag.NATIVE_DEFAULT);
        privKeyPtr = Unsafe.malloc(PRIVATE_KEY_LENGTH, MemoryTag.NATIVE_DEFAULT);
        pubKeyPtr = Unsafe.malloc(PUBLIC_KEY_LENGTH, MemoryTag.NATIVE_DEFAULT);
        signaturePtr = Unsafe.malloc(MAX_SIGNATURE_LENGTH, MemoryTag.NATIVE_DEFAULT);
        challengePtr = Unsafe.malloc(MAX_PASSWORD_LENGTH, MemoryTag.NATIVE_DEFAULT);
        secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        sigDer = Signature.getInstance(AuthUtils.SIGNATURE_TYPE_DER);
        sigP1363 = Signature.getInstance(AuthUtils.SIGNATURE_TYPE_P1363);
    }

    @AfterClass
    public static void tearDownNative() {
        Unsafe.free(passwordPtr, MAX_PASSWORD_LENGTH, MemoryTag.NATIVE_DEFAULT);
        Unsafe.free(saltPtr, SALT_LENGTH, MemoryTag.NATIVE_DEFAULT);
        Unsafe.free(hashPtr, 256 / 8, MemoryTag.NATIVE_DEFAULT);
        Unsafe.free(privKeyPtr, PRIVATE_KEY_LENGTH, MemoryTag.NATIVE_DEFAULT);
        Unsafe.free(pubKeyPtr, PUBLIC_KEY_LENGTH, MemoryTag.NATIVE_DEFAULT);
        Unsafe.free(signaturePtr, MAX_SIGNATURE_LENGTH, MemoryTag.NATIVE_DEFAULT);
        Unsafe.free(challengePtr, MAX_PASSWORD_LENGTH, MemoryTag.NATIVE_DEFAULT);
    }

    @Test
    public void testProduceEqualHashes() throws InvalidKeySpecException {
        for (int i = 0; i < 10; i++) {
            byte[] password = randomPassword();
            byte[] salt = randomSalt();
            byte[] nativeBytes = hashNative(password, salt);
            byte[] jdkBytes = hashJdk(password, salt);
            Assert.assertArrayEquals(jdkBytes, nativeBytes);
        }
    }

    @Test
    public void testSignatureVerification() throws Exception {
        for (int i = 0; i < 1_000; i++) {
            RustyCrypto.genkey(privKeyPtr, pubKeyPtr);
            byte[] challenge = randomPassword();
            PrivateKey privateKey = ptrToPrivateKey(privKeyPtr);
            PublicKey publicKey = ptrToPublicKey(pubKeyPtr);

            assertSignature(challenge, privateKey, publicKey, sigDer);
            assertSignature(challenge, privateKey, publicKey, sigP1363);
        }
    }

    private static PublicKey ptrToPublicKey(long pubKeyPtr) {
        byte[] bytes = Utils.copyFromNative(pubKeyPtr, PUBLIC_KEY_LENGTH);
        byte[] xBytes = new byte[32];
        byte[] yBytes = new byte[32];
        System.arraycopy(bytes, 1, xBytes, 0, 32);
        System.arraycopy(bytes, 33, yBytes, 0, 32);
        String xString = Base64.getUrlEncoder().encodeToString(xBytes);
        String yString = Base64.getUrlEncoder().encodeToString(yBytes);
        return AuthUtils.toPublicKey(xString, yString);
    }

    private static PrivateKey ptrToPrivateKey(long privKeyPtr) {
        byte[] privateKeyBytes = Utils.copyFromNative(privKeyPtr, PRIVATE_KEY_LENGTH);
        String privateKeyStr = Base64.getUrlEncoder().encodeToString(privateKeyBytes);
        return AuthUtils.toPrivateKey(privateKeyStr);
    }

    private static void assertSignature(byte[] challenge, PrivateKey privateKey, PublicKey publicKey, Signature sig) throws Exception {
        // sign in JDK, verify in Rust
        sig.initSign(privateKey);
        sig.update(challenge);
        Utils.copyToNative(challengePtr, MAX_PASSWORD_LENGTH, challenge);
        byte[] sigBytes = sig.sign();
        Utils.copyToNative(signaturePtr, MAX_SIGNATURE_LENGTH, sigBytes);
        Assert.assertTrue(RustyCrypto.verify(pubKeyPtr, challengePtr, challenge.length, signaturePtr, sigBytes.length));

        // verify the same signature in JDK
        sig.initVerify(publicKey);
        sig.update(challenge);
        Assert.assertTrue(sig.verify(sigBytes));
    }

    private byte[] randomSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        for (int i = 0; i < SALT_LENGTH; i++) {
            salt[i] = (byte) rnd.nextInt();
        }
        return salt;
    }

    private static byte[] hashJdk(byte[] password, byte[] salt) throws InvalidKeySpecException {
        char[] passwordChars = new char[password.length];
        for (int i = 0; i < password.length; i++) {
            passwordChars[i] = (char) password[i];
        }
        PBEKeySpec spec = new PBEKeySpec(passwordChars, salt, 100_000, 256);
        return secretKeyFactory.generateSecret(spec).getEncoded();
    }

    private static byte[] hashNative(byte[] password, byte[] salt) {
        Utils.copyToNative(passwordPtr, MAX_PASSWORD_LENGTH, password);
        Utils.copyToNative(saltPtr, SALT_LENGTH, salt);
        RustyCrypto.hash(passwordPtr, password.length, saltPtr, SALT_LENGTH, hashPtr);
        return Utils.copyFromNative(hashPtr, 256 / 8);
    }

    private byte[] randomPassword() {
        long passwordLen = rnd.nextInt(MAX_PASSWORD_LENGTH) + 1;
        byte[] password = new byte[(int) passwordLen];
        for (int i = 0; i < passwordLen; i++) {
            password[i] = (byte) rnd.nextInt(127);
        }
        return password;
    }
}

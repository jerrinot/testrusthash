package info.jerrinot.sandbox.rustyhashes;

import io.questdb.cutlass.auth.AuthUtils;
import io.questdb.jar.jni.JarJniLoader;
import io.questdb.std.*;
import io.questdb.std.str.AbstractCharSink;
import io.questdb.std.str.CharSink;
import io.questdb.std.str.StringSink;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HexFormat;

public class RustyHashMain {
    private static final String HASHING_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String PASSWORD = "password";
    private static final byte[] SALT = "1234567890123456".getBytes(StandardCharsets.UTF_8);


    public static void main(String[] args) throws Exception {
        JarJniLoader.loadLib(RustyHashMain.class, "/info/jerrinot/sandbox/rustyhashes/bin", "rustyhashing");
        Module currentModule = RustyHashMain.class.getModule();
        Unsafe.addExports(Unsafe.JAVA_BASE_MODULE, currentModule, "sun.security.util");
//        hashJdk();
//        hashRust();
        ecRust();
    }

    private static void ecRust() throws Exception {
        int privateKeyLen = 32;
        int publicKeyLen = 65;

        long privKeyPtr = Unsafe.malloc(privateKeyLen, MemoryTag.NATIVE_DEFAULT);
        long pubKeyPtr = Unsafe.malloc(publicKeyLen, MemoryTag.NATIVE_DEFAULT);
        long signaturePtr = 0;
        int signatureLen = 0;
        String challenge = "hello";
        long challengePtr = Unsafe.malloc(challenge.length(), MemoryTag.NATIVE_DEFAULT);
        for (int i = 0; i < challenge.length(); i++) {
            Unsafe.getUnsafe().putByte(challengePtr + i, (byte) challenge.charAt(i));
        }
        try {
            RustyCrypto.genkey(privKeyPtr, pubKeyPtr);

            PrivateKey privateKey = toPrivateKey(privKeyPtr);

            Signature sigP1363 = Signature.getInstance(AuthUtils.SIGNATURE_TYPE_P1363);
            sigP1363.initSign(privateKey);
            sigP1363.update(challenge.getBytes(StandardCharsets.UTF_8));
            byte[] signatureP1363 = sigP1363.sign();

            byte[] reflectiveDerSignature = (byte[]) Class.forName("sun.security.util.ECUtil").getMethod("encodeSignature", byte[].class).invoke(null, signatureP1363);
            System.out.println("Java reflection DER signature (length=" + reflectiveDerSignature.length + ") : ");
            dumpSignature(reflectiveDerSignature);

            Signature sigDer = Signature.getInstance(AuthUtils.SIGNATURE_TYPE_DER);
            sigDer.initSign(privateKey);
            sigDer.update(challenge.getBytes(StandardCharsets.UTF_8));
            byte[] signatureDer = sigDer.sign();

            byte[] signatureToUse = signatureDer;

            signatureLen = signatureToUse.length;
            signaturePtr = Unsafe.malloc(signatureLen, MemoryTag.NATIVE_DEFAULT);
            Utils.copyToNative(signaturePtr, signatureLen, signatureToUse);

            boolean verify = RustyCrypto.verify(pubKeyPtr, challengePtr, challenge.length(), signaturePtr, signatureLen);
            System.out.println(verify);
        } finally {
            Unsafe.free(privKeyPtr, privateKeyLen, MemoryTag.NATIVE_DEFAULT);
            Unsafe.free(pubKeyPtr, publicKeyLen, MemoryTag.NATIVE_DEFAULT);
            Unsafe.free(signaturePtr, signatureLen, MemoryTag.NATIVE_DEFAULT);
            Unsafe.free(challengePtr, challenge.length(), MemoryTag.NATIVE_DEFAULT);
        }

    }

    private static void dumpSignature(byte[] signature) {
        System.out.println(HexFormat.of().withDelimiter(", ").formatHex(signature));
    }

    private static PrivateKey toPrivateKey(long privKeyPtr) {
        DirectBinarySequence dbs = new DirectBinarySequence();
        dbs.of(privKeyPtr, 256 / 8);
        StringSink sink = new StringSink();
        Chars.base64UrlEncode(dbs, Integer.MAX_VALUE, sink);
        PrivateKey privateKey = AuthUtils.toPrivateKey(sink.toString());
        return privateKey;
    }

    private static void hashJdk() throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory instance = SecretKeyFactory.getInstance(HASHING_ALGORITHM);
        PBEKeySpec spec = new PBEKeySpec(PASSWORD.toCharArray(), SALT, 100_000, 256);
        long startTime = System.nanoTime();
        for (int i = 0; i < 100; i++) {
            SecretKey secretKey = instance.generateSecret(spec);
        }
        long timeInMicros = (System.nanoTime() - startTime) / 1000;
        System.out.println("JDK duration: " + timeInMicros);
        SecretKey secretKey = instance.generateSecret(spec);
        byte[] encoded = secretKey.getEncoded();
        System.out.println(Arrays.toString(encoded));
    }

    private static void hashRust() {
        int passwordBufferSizeBytes = 4096;
        int hashSizeBytes = 256 / 8;

        long passwordPtr = Unsafe.malloc(passwordBufferSizeBytes, MemoryTag.NATIVE_DEFAULT);
        long hashPtr = Unsafe.malloc(hashSizeBytes, MemoryTag.NATIVE_DEFAULT);
        long saltPtr = Unsafe.malloc(SALT.length, MemoryTag.NATIVE_DEFAULT);
        Utils.copyToNative(saltPtr, SALT.length, SALT);
        try {
            DirectCharSink sink = new DirectCharSink(passwordPtr, passwordBufferSizeBytes);
            sink.encodeUtf8(PASSWORD);
            int passwordSize = sink.getSize();
            long startTime = System.nanoTime();
            for (int i = 0; i < 10; i++) {
                RustyCrypto.hash(passwordPtr, passwordSize, saltPtr, SALT.length, hashPtr);
            }
            long timeInMicros = (System.nanoTime() - startTime) / 1000;
            System.out.println("Rust duration: " + timeInMicros);
            byte[] buff = new byte[hashSizeBytes];
            for (int i = 0; i < hashSizeBytes; i++) {
                buff[i] = Unsafe.getUnsafe().getByte(hashPtr + i);
            }
            System.out.println(Arrays.toString(buff));
        } finally {
            Unsafe.free(passwordPtr, passwordBufferSizeBytes, MemoryTag.NATIVE_DEFAULT);
            Unsafe.free(hashPtr, hashSizeBytes, MemoryTag.NATIVE_DEFAULT);
            Unsafe.free(saltPtr, SALT.length, MemoryTag.NATIVE_DEFAULT);
        }
    }

    private static class DirectCharSink extends AbstractCharSink {
        private long lo;
        private long ptr;
        private long lim;

        private DirectCharSink(long ptr, int len) {
            this.lo = ptr;
            this.ptr = ptr;
            this.lim = ptr + len;
        }


        @Override
        public CharSink put(char c) {
            if (ptr == lim) {
                throw new RuntimeException("not enough space");
            }
            assert c < 128;
            Unsafe.getUnsafe().putByte(ptr, (byte) c);
            ptr++;
            return this;
        }

        public int getSize() {
            return (int) (ptr - lo);
        }
    }
}

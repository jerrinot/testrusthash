package info.jerrinot.sandbox.rustyhashes;

import io.questdb.jar.jni.JarJniLoader;
import io.questdb.std.MemoryTag;
import io.questdb.std.Unsafe;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class HashingBenchmark {
    private static final String HASHING_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int PASSWORD_LENGTH = 16;
    private static final int SALT_LENGTH = 16;
    private static final int PASSWORD_BUFFER_SIZE_BYTES = PASSWORD_LENGTH;
    private static final int HASH_SIZE_BYTES = 256 / 8;

    private byte[] salt;
    private char[] password;
    private long passwordPtr;
    private long hashPtr;
    private long saltPtr;
    private Random rnd;
    private SecretKeyFactory secretKeyFactory;

    @Setup
    public void prepare() throws NoSuchAlgorithmException {
        JarJniLoader.loadLib(RustyHashMain.class, "/info/jerrinot/sandbox/rustyhashes/bin", "rustyhashing");
        rnd = new Random();
        salt = new byte[SALT_LENGTH];
        password = new char[PASSWORD_LENGTH];
        rnd.nextBytes(salt);
        secretKeyFactory = SecretKeyFactory.getInstance(HASHING_ALGORITHM);

        passwordPtr = Unsafe.malloc(PASSWORD_BUFFER_SIZE_BYTES, MemoryTag.NATIVE_DEFAULT);
        hashPtr = Unsafe.malloc(HASH_SIZE_BYTES, MemoryTag.NATIVE_DEFAULT);
        saltPtr = Unsafe.malloc(SALT_LENGTH, MemoryTag.NATIVE_DEFAULT);
        for (int i = 0; i < SALT_LENGTH; i++) {
            Unsafe.getUnsafe().putByte(saltPtr + i, salt[i]);
        }
    }

    @TearDown
    public void tearDown() {
        Unsafe.free(passwordPtr, PASSWORD_BUFFER_SIZE_BYTES, MemoryTag.NATIVE_DEFAULT);
        Unsafe.free(hashPtr, HASH_SIZE_BYTES, MemoryTag.NATIVE_DEFAULT);
        Unsafe.free(saltPtr, SALT_LENGTH, MemoryTag.NATIVE_DEFAULT);
    }

    @Benchmark
    public void hashRust() {
        for (int i = 0; i < PASSWORD_LENGTH; i++) {
            Unsafe.getUnsafe().putByte(passwordPtr + i, (byte) rnd.nextInt());
        }
        RustyCrypto.hash(passwordPtr, PASSWORD_LENGTH, saltPtr, SALT_LENGTH, hashPtr);
    }

    @Benchmark
    public SecretKey hashJdk() throws InvalidKeySpecException {
        for (int i = 0; i < PASSWORD_LENGTH; i++) {
            password[i] = (char) rnd.nextInt();
        }
        PBEKeySpec spec = new PBEKeySpec(password, salt, 100_000, 256);
        return secretKeyFactory.generateSecret(spec);
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(HashingBenchmark.class.getSimpleName())
                .warmupIterations(3)
                .measurementIterations(3)
                .forks(1)
                .build();

        new Runner(opt).run();
    }
}

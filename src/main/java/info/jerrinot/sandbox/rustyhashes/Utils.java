package info.jerrinot.sandbox.rustyhashes;

import io.questdb.std.Unsafe;

public final class Utils {
    private Utils() {

    }


    public static void copyToNative(long basePtr, int ptrLen, byte[] src) {
        assert ptrLen >= src.length;
        for (int i = 0; i < src.length; i++) {
            Unsafe.getUnsafe().putByte(basePtr + i, src[i]);
        }
    }

    public static byte[] copyFromNative(long basePtr, int ptrLen) {
        byte[] result = new byte[ptrLen];
        for (int i = 0; i < ptrLen; i++) {
            result[i] = Unsafe.getUnsafe().getByte(basePtr + i);
        }
        return result;
    }
}

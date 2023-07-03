package info.jerrinot.sandbox.rustyhashes;

public class RustyCrypto {
    public static native void hash(long passwordPtr, int passwordLen, long saltPtr, int saltLen, long outPtr);
    public static native void genkey(long privKeyPtr, long pubKeyPtr);
    public static native boolean verify(long pubKeyPtr, long challangePtr, int challengeLen, long signaturePtr, int signatureLen);
}

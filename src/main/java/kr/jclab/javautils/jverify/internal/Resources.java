package kr.jclab.javautils.jverify.internal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Resources {
    private Resources() {}

    public static BouncyCastleProvider getBouncyCastleProvider() {
        return LazyHolder.PROVIDER;
    }

    private static class LazyHolder {
        public static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();
    }
}

package com.example.chen.aesutil;

public class Util {
    static {
        System.loadLibrary("util");
    }

    public static native String encrypty(String info, String key);
    public static native String ecbDecrypty(String info, String key);
    public static native String cbcEncrypty(String info, String key, String iv);
    public static native String cbcDecrypty(String info, String key, String iv);
}

package com.example.chen.aesutil;

public class Util {
    static {
        System.loadLibrary("util");
    }

    public native String encrypty(String info, String key);

    public native String cbcEncrypty(String info, String key, String iv);
}

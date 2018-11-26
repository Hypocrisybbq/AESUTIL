package com.example.chen.aesutil;

public class Util {
    static {
        System.loadLibrary("util");
    }

    public native String encrypt(String info, String key);
}

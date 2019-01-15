package com.example.chen.aesutil;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import com.example.chen.aesutil.jaes.AESUtil;

import java.io.UnsupportedEncodingException;
import java.security.Key;

public class MainActivity extends AppCompatActivity {

    private String info = "测试内容自己改啦";
    private String pass = "1234567890abcdef";
    private String iv = "abcdef1234567890";
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        String encrypt = Util.encrypty(info, pass);
        Log.e("CHEN", "encrypt: " + encrypt);
        String decrypty = Util.ecbDecrypty(encrypt, pass);
        Log.e("CHEN", "decrypty: " + decrypty);

        String cbcEncrypty = Util.cbcEncrypty(info, pass, iv);
        Log.e("CHEN", "cbcEncrypty: " + cbcEncrypty);
        String cbcDecrypty = Util.cbcDecrypty(cbcEncrypty, pass, iv);
        Log.e("CHEN", "cbcDecrypty: " + cbcDecrypty);
    }
}

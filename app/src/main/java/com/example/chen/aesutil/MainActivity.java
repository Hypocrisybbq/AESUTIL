package com.example.chen.aesutil;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import com.example.chen.aesutil.jaes.AESUtil;

import java.io.UnsupportedEncodingException;
import java.security.Key;

public class MainActivity extends AppCompatActivity {

    private String info = "陈祎喆";
    private String pass = "1234567890abcdef";
    private String iv = "abcdef1234567890";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Util util = new Util();
//        String encrypt = util.encrypty(info, pass);
//        Log.e("CHEN", "encrypt: " + encrypt);
//        String decrypty = util.ecbDecrypty(encrypt, pass);
//        Log.e("CHEN", "decrypty: " + decrypty);

//        String cbcEncrypty = util.cbcEncrypty(info, pass, iv);
        String cbcEncrypty = util.cbcEncrypty(info, pass, iv);
        Log.e("CHEN", "cbcEncrypty: " + cbcEncrypty);
//        String cbcDecrypty = util.cbcDecrypty(cbcEncrypty, pass, iv);
//        Log.e("CHEN", "cbcDecrypty: " + cbcDecrypty);
    }
}

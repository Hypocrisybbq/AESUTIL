package com.example.chen.aesutil;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import com.example.chen.aesutil.jaes.AESUtil;

import java.io.UnsupportedEncodingException;

public class MainActivity extends AppCompatActivity {

    private String info = "123abcABC*%!~#+_/中文测试";
    private String pass = "1234567890abcdef";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Util util = new Util();
        String encrypt = util.encrypty(info, pass);
    }
}

package com.example.chen.aesutil.jaes;

import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESUtil {

    private static String CIPHER_TYPE = "AES/ECB/PKCS5Padding";//设定参数
    private static String KEY_TYPE = "AES";//生成的key类型

    /**
     * aes加密
     */
    public static String AESEncryption(String info, String ivString, String keyString) {
        try {
            SecretKeySpec key = getKey(keyString);//生成密钥
            Cipher cipher = Cipher.getInstance(CIPHER_TYPE);//初始化
            if (ivString != null) {
                IvParameterSpec iv = getIv(ivString);//生成向量
                cipher.init(Cipher.ENCRYPT_MODE, key, iv);//模式为加密,输入加密模式,密钥和向量初始化cipher对象
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, key);
            }
            byte[] bytes = cipher.doFinal(info.getBytes("utf-8"));
            return Base64.encodeToString(bytes, Base64.DEFAULT);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * aes解密
     */
    public static String AESDecryption(String info, String ivString, String keyString) {
        try {
            SecretKeySpec key = getKey(keyString);//生成密钥
            Cipher cipher = Cipher.getInstance(CIPHER_TYPE);//初始化
            if (ivString != null) {
                IvParameterSpec iv = getIv(ivString);//生成向量
                cipher.init(Cipher.DECRYPT_MODE, key, iv);//模式为解密,输入加密模式,密钥和向量初始化cipher对象
            } else {
                cipher.init(Cipher.DECRYPT_MODE, key);
            }
            byte[] bytes = cipher.doFinal(Base64.decode(info, Base64.DEFAULT));//因为数据已经用Base编码过一次,所以需要解码一次
            return new String(bytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static SecretKeySpec getKey(String pass) {
        return new SecretKeySpec(pass.getBytes(), KEY_TYPE);
    }

    private static IvParameterSpec getIv(String ivString) {
        return new IvParameterSpec(ivString.getBytes());
    }
}
#include <jni.h>
#include "aes.h"
#include <android/log.h>
#include <cstring>
#include <malloc.h>

#define LOG_TAG "CHEN"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)


extern "C" {

/**
 * hasIv 是否是带Iv向量的加解密 1:带向量   0:不带向量
 * isEncrypt 是加密还是解密 1:加密   0:解密
 */
jstring encrypt(JNIEnv *env, jstring info, jstring key, jstring iv, int hasIv, int isEncrypt) {
    if (hasIv) {
        if (iv == NULL) {
            return env->NewStringUTF("向量不能为Null");
        }
    }
    if (info == NULL) {
        return env->NewStringUTF("明文不能为Null");
    }
    if (key == NULL) {
        return env->NewStringUTF("密钥不能为Null");
    }
    const char *info_str = env->GetStringUTFChars(info, JNI_FALSE);
    const char *key_str = env->GetStringUTFChars(key, JNI_FALSE);
    if (strlen(key_str) < 16) {
        return env->NewStringUTF("密钥长度不能小于16");
    }
    char *string = NULL;
    if (hasIv) {
        const char *iv_str = env->GetStringUTFChars(iv, JNI_FALSE);
        if (strlen(iv_str) < 16) {
            return env->NewStringUTF("向量不能小于16");
        }
        if (isEncrypt) {
            string = PCKS5Padding128CBCEncrypt(info_str, key_str, iv_str);
        } else {
            string = PCKS5Padding128CBCDecrypt(info_str, key_str, iv_str);
        }
    } else {
        if (isEncrypt) {
            string = PCKS5Padding128Encrypt(info_str, key_str);
        } else {
            string = PCKS5Padding128Decrypt(info_str, key_str);
        }
    }
    if (string == NULL) {
        return env->NewStringUTF("申请内存失败,请重试");
    } else {
        return env->NewStringUTF(string);
    }
}
/**
 * info 明文
 * key 密钥
 * iv 向量
 */
JNIEXPORT jstring JNICALL Java_com_example_chen_aesutil_Util_encrypty //ECB加密
        (JNIEnv *env, jobject, jstring info, jstring key) {
    return encrypt(env, info, key, NULL, 0, 1);
} ;
JNIEXPORT jstring JNICALL Java_com_example_chen_aesutil_Util_ecbDecrypty //ECB解密
        (JNIEnv *env, jobject, jstring info, jstring key) {
    return encrypt(env, info, key, NULL, 0, 0);
} ;
JNIEXPORT jstring JNICALL Java_com_example_chen_aesutil_Util_cbcEncrypty //CBC加密
        (JNIEnv *env, jobject, jstring info, jstring key, jstring iv) {
    return encrypt(env, info, key, iv, 1, 1);
} ;
JNIEXPORT jstring JNICALL Java_com_example_chen_aesutil_Util_cbcDecrypty //CBC解密
        (JNIEnv *env, jobject, jstring info, jstring key, jstring iv) {
    return encrypt(env, info, key, iv, 1, 0);
} ;
}

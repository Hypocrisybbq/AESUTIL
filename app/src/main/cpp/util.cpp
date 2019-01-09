#include <jni.h>
#include "aes.h"
#include <android/log.h>
#include <cstring>
#include <malloc.h>

#define LOG_TAG "CHEN"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)


extern "C" {


JNIEXPORT jstring JNICALL Java_com_example_chen_aesutil_Util_encrypty
        (JNIEnv *env, jobject, jstring info, jstring key) {
    if (info == NULL) {
        return env->NewStringUTF("明文不能为Null");
    }
    if (key == NULL) {
        return env->NewStringUTF("密钥不能为Null");
    }
    const char *info_str = env->GetStringUTFChars(info, JNI_FALSE);
    const char *key_str = env->GetStringUTFChars(key, JNI_FALSE);
    char *string = PCKS5Padding128Encrypt(info_str, key_str);
    return env->NewStringUTF(string);
} ;
JNIEXPORT jstring JNICALL Java_com_example_chen_aesutil_Util_ecbDecrypty
        (JNIEnv *env, jobject, jstring info, jstring key) {
    if (info == NULL) {
        return env->NewStringUTF("明文不能为Null");
    }
    if (key == NULL) {
        return env->NewStringUTF("密钥不能为Null");
    }
    const char *info_str = env->GetStringUTFChars(info, JNI_FALSE);
    const char *key_str = env->GetStringUTFChars(key, JNI_FALSE);
    char *string = PCKS5Padding128Decrypt(info_str, key_str);
    if (string != NULL) {
        return env->NewStringUTF(string);
    } else {
        return env->NewStringUTF("申请内存失败,请重试");
    }

} ;
JNIEXPORT jstring JNICALL Java_com_example_chen_aesutil_Util_cbcEncrypty
        (JNIEnv *env, jobject, jstring info, jstring key, jstring iv) {
    if (info == NULL) {
        return env->NewStringUTF("明文不能为Null");
    }
    if (key == NULL) {
        return env->NewStringUTF("密钥不能为Null");
    }
    if (iv == NULL) {
        return env->NewStringUTF("向量不能为Null");
    }

    const char *info_str = env->GetStringUTFChars(info, JNI_FALSE);
    const char *key_str = env->GetStringUTFChars(key, JNI_FALSE);
    const char *iv_str = env->GetStringUTFChars(iv, JNI_FALSE);
    char *string = PCKS5Padding128CBCEncrypt(info_str, key_str, iv_str);
    return env->NewStringUTF(string);
} ;
JNIEXPORT jstring JNICALL Java_com_example_chen_aesutil_Util_cbcDecrypty
        (JNIEnv *env, jobject, jstring info, jstring key, jstring iv) {
    if (info == NULL) {
        return env->NewStringUTF("明文不能为Null");
    }
    if (key == NULL) {
        return env->NewStringUTF("密钥不能为Null");
    }
    if (iv == NULL) {
        return env->NewStringUTF("向量不能为Null");
    }

    const char *info_str = env->GetStringUTFChars(info, JNI_FALSE);
    const char *key_str = env->GetStringUTFChars(key, JNI_FALSE);
    const char *iv_str = env->GetStringUTFChars(iv, JNI_FALSE);
    char *string = PCKS5Padding128CBCDecrypt(info_str, key_str, iv_str);
    if (string != NULL) {
        return env->NewStringUTF(string);
    } else {
        return env->NewStringUTF("申请内存失败,请重试");
    }
} ;

}

//
// Created by chen on 2018/11/22.
//

#include <jni.h>
#include "aes.h"
#include <android/log.h>

#define LOG_TAG "CHEN"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define AES_128
#ifdef AES_128
#define key_num 160
#define key_rounds 10
#endif


extern "C"
JNIEXPORT jstring JNICALL Java_com_example_chen_aesutil_Util_encrypt
        (JNIEnv *env, jobject, jstring info, jstring key) {

    uint8_t key_result[key_num];
    getKey(key, env, key_rounds, key_result);
    return env->NewStringUTF("abcd");
};
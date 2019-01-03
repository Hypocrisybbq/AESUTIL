//
// Created by chen on 2018/11/22.
//

#include <jni.h>
#include "aes.h"
#include "base.h"
#include <android/log.h>
#include <cstring>
#include <malloc.h>

#define LOG_TAG "CHEN"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)


extern "C"
JNIEXPORT jstring JNICALL Java_com_example_chen_aesutil_Util_encrypty
        (JNIEnv *env, jobject, jstring info, jstring key) {
    const char *info_str = env->GetStringUTFChars(info, JNI_FALSE);
    const char *key_str = env->GetStringUTFChars(key, JNI_FALSE);
     PCKS5Padding128Encrypt(info_str, key_str);
    return env->NewStringUTF("adv");
};
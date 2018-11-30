//
// Created by chen on 2018/11/22.
//

#include <jni.h>
#include "aes.h"
#include <android/log.h>
#include <cstring>

#define LOG_TAG "CHEN"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern "C"
JNIEXPORT jstring JNICALL Java_com_example_chen_aesutil_Util_encrypt
        (JNIEnv *env, jobject, jstring info, jstring key) {

    uint8_t key_result[key_rounds][key_num];//生成获取密钥扩展结果的指针
    getKey(key, env, key_result);//密钥扩展

    const char *info_char = env->GetStringUTFChars(info, JNI_FALSE);
    size_t info_size = strlen(info_char);
    uint8_t local_info[info_size];
    memcpy(local_info, info_char, info_size);

    //明文16字节为一组分组存储,并填充
    size_t part_num = info_size / 16 + 1;
    size_t part_last = info_size % 16;
    uint8_t fill_char = static_cast<uint8_t>(16 - part_last);
    uint8_t info_fill[part_num][16];
    for (int i = 0; i < (part_num * 16); ++i) {
        if (i < info_size) {
            info_fill[i / 16][i % 16] = local_info[i];
        } else {
            info_fill[i / 16][i % 16] = fill_char;
        }
    }

    encrypt_ecb(info_fill, part_num, key_result);
    for (int i = 0; i < 16; ++i) {
        LOGE("%x", info_fill[0][i]);
    }
//    env->NewStringUTF(reinterpret_cast<const char *>(info_fill));
//    return pJstring;
    return env->NewStringUTF("abcd");
};
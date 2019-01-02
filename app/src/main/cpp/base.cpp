//
// Created by chen on 2018/12/3.
//

#include <cstring>
#include "base.h"
#include <android/log.h>

#define LOG_TAG "CHEN"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

const char BASE_TAB[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const char EQUAL = '=';

/**
 * Base64位编码,
 * @param str  需要加密的字符串
 * @param result  最终返回的数组指针
 */
void base64Code(uint8_t str[], size_t length, char *result) {
    int j = 0; //用于存放每个字符的编码结果
//    size_t length = strlen(reinterpret_cast<const char *>(str)); //获取字符数组的长度
    LOGE("size_t:%zu", length);
    for (int i = 0; i < length; i++) {
        result[j++] = BASE_TAB[(str[i] >> 2) & 0x3f]; //获取第一个字符的前6位
        int start2 = (str[i] << 4) & 0x30;           //获取第一个字符的后两位
        if (++i < length) {                          //获取第二个字符的后四位
            int end2 = (str[i] >> 4) & 0x0f;
            result[j++] = BASE_TAB[start2 | end2];
        } else {                                    //位数不够==来凑
            result[j++] = BASE_TAB[start2];
            result[j++] = EQUAL;
            result[j++] = EQUAL;
            break;
        }
        int start3 = (str[i] << 2) & 0x3c;  //获取第二个字符的后四位
        if (++i < length) {                 //获取第三个字符的前两位
            int end3 = (str[i] >> 6) & 0x03;
            result[j++] = BASE_TAB[start3 | end3];
        } else {
            result[j++] = BASE_TAB[start2];
            result[j++] = EQUAL;
            break;
        }
        int info4 = (str[i]) & 0x3f;   //获取最后一个字符的后六位
        result[j++] = BASE_TAB[info4];
    }
    result[j] = '\0';
}

inline int num_strchr(const char *str, char c) //
{
    const char *pindex = strchr(str, c);
    if (NULL == pindex) {
        return -1;
    }
    return static_cast<int>(pindex - str);
}

int enBase64Code(const char *str, unsigned char *result) {
    int i = 0, j = 0;
    int trans[4] = {0, 0, 0, 0};
    for (; str[i] != '\0'; i += 4) {
        trans[0] = num_strchr(BASE_TAB, str[i]);
        trans[1] = num_strchr(BASE_TAB, str[i + 1]);
        result[j++] = static_cast<unsigned char>(((trans[0] << 2) & 0xfc) |
                                                 ((trans[1] >> 4) & 0x03));
        if (str[i + 2] == '=') {
            continue;
        } else {
            trans[2] = num_strchr(BASE_TAB, str[i + 2]);
        }
        result[j++] = static_cast<unsigned char>(((trans[1] << 4) & 0xf0) |
                                                 ((trans[2] >> 2) & 0x0f));

        if (str[i + 3] == '=') {
            continue;
        } else {
            trans[3] = num_strchr(BASE_TAB, str[i + 3]);
        }
        result[j++] = static_cast<unsigned char>(((trans[2] << 6) & 0xc0) | (trans[3] & 0x3f));
    }

    result[j] = '\0';
    return 0;
}
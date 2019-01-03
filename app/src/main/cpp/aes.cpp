//
// Created by chen on 2018/11/22.
//

#include <stdint.h>
#include <jni.h>
#include <cstring>
#include <malloc.h>
#include "aes.h"


//#define TEST
#ifdef TEST
static uint8_t temp_t[4][4] = {           //初始的密钥,测试数据
        {0x2b, 0x28, 0xab, 0x09},
        {0x7e, 0xae, 0xf7, 0xcf},
        {0x15, 0xd2, 0x15, 0x4f},
        {0x16, 0xa6, 0x88, 0x3c},
};
static uint8_t info_temp_f[4][4] = {
        {0x32, 0x88, 0x31, 0xe0},
        {0x43, 0x5a, 0x31, 0x37},
        {0xf6, 0x30, 0x98, 0x07},
        {0xa8, 0x8d, 0xa2, 0x34},
};
static uint8_t info_temp_t[4][4] = {
        {0x19, 0xa0, 0x9a, 0xe9},
        {0x3d, 0xf4, 0xc6, 0xf8},
        {0xe3, 0xe2, 0x8d, 0x48},
        {0xbe, 0x2b, 0x2a, 0x08},
};


static uint8_t info_temp[4][4] = {
        {0x61, 0x62, 0x63, 0x64},
        {0x61, 0x62, 0x63, 0x64},
        {0x61, 0x62, 0x63, 0x64},
        {0x61, 0x62, 0x63, 0x64},
};
static uint8_t temp[4][4] = {           //初始的密钥,测试数据
        {0x61, 0x62, 0x63, 0x64},
        {0x31, 0x32, 0x33, 0x34},
        {0x65, 0x66, 0x67, 0x68},
        {0x35, 0x36, 0x37, 0x38},
};
#endif

uint8_t mixCal2(uint8_t value) {//有限域的计算,所以高于8位的位会溢出,溢出的数据不需要,如果类型是int 请添加0xff,不然结果会出异常
    return static_cast<uint8_t>((value << 1) ^ ((value & 0x80) ? 0x1b : 0x00));
}

uint8_t mixCal3(uint8_t value) {
    return mixCal2(value) ^ value;
}

void print(char a, char b, char c) {
    LOGE("%x:%x:%x", a, b, c);
}

void PCKS5Padding128Encrypt(const char *info, const char *key) {
    size_t info_length = strlen(info);
    size_t info_length_max = ((info_length / 16) + 1) * 16;
    uint8_t *info_result = (uint8_t *) malloc(info_length_max);
    for (int i = 0; i < info_length_max; ++i) {
        if (i < info_length) {
            info_result[i] = (uint8_t) info[i];
        } else {
            info_result[i] = PAD[16 - info_length % 16];
        }
    }
    uint8_t key_result[176];
    getKey(key, key_result);
};

/**
 * 为了方便计算,密钥原16位也放入返回结果,位置为0-16
 */
void getKey(const char *key, uint8_t *result) {
    for (int i = 0; i < 16; ++i) {//前16位放置原来的密钥
        result[i] = (uint8_t) key[i];
    }
    for (int i = 1; i < 11; ++i) {//17-176位放密钥的扩展
        for (int j = 0; j < 4; ++j) {
            if (j == 0) {
                result[i * 16] = sbox[result[(i - 1) * 16 + 13]] ^ result[(i - 1) * 16] ^ key_box[i - 1];
                result[i * 16 + 1] = sbox[result[(i - 1) * 16 + 14]] ^ result[(i - 1) * 16 + 1];
                result[i * 16 + 2] = sbox[result[(i - 1) * 16 + 15]] ^ result[(i - 1) * 16 + 2];
                result[i * 16 + 3] = sbox[result[(i - 1) * 16 + 12]] ^ result[(i - 1) * 16 + 3];
            } else {
                for (int k = 0; k < 4; ++k) {
                    result[i * 16 + j * 4 + k] = result[(i - 1) * 16 + j * 4 + k] ^ result[i * 16 + (j - 1) * 4 + k];
                }
            }
        }
    }
};

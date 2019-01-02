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
    uint8_t *result = (uint8_t *) malloc(info_length_max);
    for (int i = 0; i < info_length_max; ++i) {
        if (i < info_length) {
            result[i] = (uint8_t) info[i];
        } else {
            result[i] = PAD[16 - info_length % 16];
        }
    }
};

void getKey(const char *key, uint8_t *key_result) {

}

//生成多轮密钥
void getKey(jstring key, JNIEnv *env, uint8_t result[key_rounds][key_num]) {//密钥扩展.视频中有一个地方的计算是错误的
    const char *key_string = env->GetStringUTFChars(key, JNI_FALSE);
    LOGE("%s", key_string);
    size_t key_length = strlen(key_string);
    uint8_t local_key[key_length];
    memcpy(local_key, key_string, key_length);
    uint8_t temp[4][4];
    for (int i = 0; i < key_length; ++i) {
        int low = i / 4;
        int column = i % 4;
        temp[low][column] = local_key[i];
    }
    for (int i = 0; i < key_rounds; ++i) {
        for (int j = 0; j < 4; ++j) {
            if (j == 0) {
                for (int k = 0; k < 4; ++k) {
                    if (k < 3) {
                        result[i][j + 4 * k] = sbox[temp[k + 1][3]] ^ temp[k][0] ^ key_box[k * 10 + i];
                    } else {
                        result[i][j + 4 * k] = sbox[temp[0][3]] ^ temp[k][0] ^ key_box[k * 10 + 1];
                    }
                }
            } else {
                for (int k = 0; k < 4; k++) {
                    result[i][j + 4 * k] = result[i][j + 4 * k - 1] ^ temp[k][j];
                }
            }
        }
        for (int k = 0; k < 16; ++k) {             //把初始数据传入result中
            temp[k / 4][k % 4] = result[i][k];
//            LOGE("%x", temp[k / 4][k % 4]);
        }
//        LOGE("%s", "-----------------------------------------------------------------------");
    }
};
//
////ecb加密
//void encrypt_ecb(uint8_t info[][16], size_t part_num, uint8_t key[key_rounds][key_num]) {
//    for (int m = 0; m < part_num; ++m) {
//        uint8_t info_temp[4][4];
//        for (int n = 0; n < 16; ++n) {
//            info_temp[n / 4][n % 4] = info[m][n];
////            LOGE("%x", info_temp[n / 4][n % 4]);
//        }
////        LOGE("%s", "----------------------------------------------------------");
//        for (int k = 0; k < key_rounds; ++k) {
//            for (int i = 0; i < 16; ++i) {
//                info_temp[i / 4][i % 4] = sbox[info_temp[i / 4][i % 4]];
////            LOGE("%x", info_temp[i / 4][i % 4]);
//            }
////        LOGE("%s", "----------------------------------------------------------");
//            uint8_t swap_temp = info_temp[1][0];//第二行行位移
//            info_temp[1][0] = info_temp[1][1];
//            info_temp[1][1] = info_temp[1][2];
//            info_temp[1][2] = info_temp[1][3];
//            info_temp[1][3] = swap_temp;
//
//            swap_temp = info_temp[2][0]; //第三行行位移
//            info_temp[2][0] = info_temp[2][2];
//            info_temp[2][2] = swap_temp;
//
//            swap_temp = info_temp[2][1];
//            info_temp[2][1] = info_temp[2][3];
//            info_temp[2][3] = swap_temp;
//
//            swap_temp = info_temp[3][3];
//            info_temp[3][3] = info_temp[3][2];
//            info_temp[3][2] = info_temp[3][1];
//            info_temp[3][1] = info_temp[3][0];
//            info_temp[3][0] = swap_temp;
//
//
//            if (k < (key_rounds - 1)) {
//                //列混淆
//                for (int j = 0; j < 4; ++j) {
//                    uint8_t a = info_temp[0][j];
//                    uint8_t b = info_temp[1][j];
//                    uint8_t c = info_temp[2][j];
//                    uint8_t d = info_temp[3][j];
//                    info_temp[0][j] = mixCal2(a) ^ mixCal3(b) ^ c ^ d;
//                    info_temp[1][j] = a ^ mixCal2(b) ^ mixCal3(c) ^ d;
//                    info_temp[2][j] = a ^ b ^ mixCal2(c) ^ mixCal3(d);
//                    info_temp[3][j] = mixCal3(a) ^ b ^ c ^ mixCal2(d);
//                }
//            }
//            for (int j = 0; j < 16; ++j) {
//                info_temp[j / 4][j % 4] = key[k][j] ^ info_temp[j / 4][j % 4];
////                LOGE("%x", info_temp[j / 4][j % 4]);
//            }
//            for (int n = 0; n < 16; ++n) {
//                info[m][n] = info_temp[n / 4][n % 4];
////                LOGE("%x", info[m][n]);
//            }
////            LOGE("%s", "-------------------------------------");
//        }
//
//    }
//};

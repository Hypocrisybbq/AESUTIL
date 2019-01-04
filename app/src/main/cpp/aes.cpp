//
// Created by chen on 2018/11/22.
//

#include <stdint.h>
#include <jni.h>
#include <cstring>
#include <malloc.h>
#include "aes.h"


uint8_t mixCal2(uint8_t value) {//有限域的计算,所以高于8位的位会溢出,溢出的数据不需要,如果类型是int 请添加0xff,不然结果会出异常
    return static_cast<uint8_t>((value << 1) ^ ((value & 0x80) ? 0x1b : 0x00));
}

uint8_t mixCal3(uint8_t value) {
    return mixCal2(value) ^ value;
}

void PCKS5Padding128Encrypt(const char *info, const char *key) {
    size_t info_length = strlen(info);//明文的长度
//    LOGE("info_length:%zu", info_length);
    size_t info_pcks5_num = info_length / 16 + 1;//明文用PCKS5Padding填充后的段是
//    LOGE("info_pcks5_num:%zu", info_pcks5_num);
    size_t info_length_max = (info_pcks5_num) * 16;//明文填充后的长度
//    LOGE("info_length_max:%zu", info_length_max);
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
    for (int i = 0; i < info_pcks5_num; ++i) {//明文进行分段加密
        aesEncrypt(info_result + i * 16, key_result + 16);
    }
};

void aesEncrypt(uint8_t *info_start, uint8_t *key) {
    for (int i = 0; i < 10; ++i) {
        subBytes(info_start);
        shiftRows(info_start);
        if (i < 9) {
            mixColumns(info_start);
        }
        addRoundKey(info_start, key + 16 * i);
    }

};

void subBytes(uint8_t *info_start) {
    for (int i = 0; i < 16; ++i) {
        info_start[i] = sbox[info_start[i]];
    }
};

void shiftRows(uint8_t *info_start) {
    uint8_t temp = info_start[1];
    info_start[1] = info_start[5];
    info_start[5] = info_start[9];
    info_start[9] = info_start[13];
    info_start[13] = temp;

    temp = info_start[2];
    info_start[2] = info_start[10];
    info_start[10] = temp;

    temp = info_start[6];
    info_start[6] = info_start[14];
    info_start[14] = temp;

    temp = info_start[15];
    info_start[15] = info_start[11];
    info_start[11] = info_start[7];
    info_start[7] = info_start[3];
    info_start[3] = temp;

};//行位移

void mixColumns(uint8_t *info_start) {
    uint8_t temp[16];
    for (int i = 0; i < 16; ++i) {
        temp[i] = info_start[i];
    }
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            int position = 4 * i + j;
            info_start[position]
                    = mixCal2(temp[position])
                      ^ mixCal3(temp[4 * i + (j + 1) % 4])
                      ^ temp[4 * i + (j + 2) % 4]
                      ^ temp[4 * i + (j + 3) % 4];
        }
    }
};//列混淆

void addRoundKey(uint8_t *info_start, uint8_t *key) {
    for (int i = 0; i < 16; ++i) {
        info_start[i] = info_start[i] ^ key[i];
    }
};//与键值异或


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
//    for (int i = 0; i < 176; ++i) {
//        LOGE("%x",result[i]);
//    }
};

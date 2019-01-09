//
// Created by chen on 2018/11/22.
//

#include <stdint.h>
#include <jni.h>
#include <cstring>
#include <malloc.h>
#include "aes.h"
#include "base64.h"

/*
 * 下面对应列混淆的矩阵计算,后面的数字代表要与矩阵中哪个数据进行计算
 * 可以参照aes.h中的列混淆和逆列混淆矩阵,方便理解
 */
uint8_t mixCal2(uint8_t value) {//有限域的计算,所以高于8位的位会溢出,溢出的数据不需要,如果类型是int 请添加0xff,不然结果会出异常
    return static_cast<uint8_t>((value << 1) ^ ((value & 0x80) ? 0x1b : 0x00));
}

uint8_t mixCal3(uint8_t value) {
    return mixCal2(value) ^ value;
}

uint8_t mixCal4(uint8_t value) {
    return mixCal2(mixCal2(value));
}

uint8_t mixCal8(uint8_t value) {
    return mixCal2(mixCal4(value));
}

uint8_t mixCal9(uint8_t value) {
    return mixCal8(value) ^ value;
}

uint8_t mixCal11(uint8_t value) {
    return mixCal9(value) ^ mixCal2(value);
}

uint8_t mixCal12(uint8_t value) {
    return mixCal8(value) ^ mixCal4(value);
}

uint8_t mixCal13(uint8_t value) {
    return mixCal12(value) ^ value;
}

uint8_t mixCal14(uint8_t value) {
    return mixCal12(value) ^ mixCal2(value);
}

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

void deSubBytes(uint8_t *info_start) {
    for (int i = 0; i < 16; ++i) {
        info_start[i] = rsbox[info_start[i]];
    }
};

void deShiftRows(uint8_t *info_start) {
    uint8_t temp = info_start[13];
    info_start[13] = info_start[9];
    info_start[9] = info_start[5];
    info_start[5] = info_start[1];
    info_start[1] = temp;

    temp = info_start[10];
    info_start[10] = info_start[2];
    info_start[2] = temp;

    temp = info_start[14];
    info_start[14] = info_start[6];
    info_start[6] = temp;

    temp = info_start[3];
    info_start[3] = info_start[7];
    info_start[7] = info_start[11];
    info_start[11] = info_start[15];
    info_start[15] = temp;

};//行位移

void deMixColumns(uint8_t *info_start) {
    uint8_t temp[16];
    for (int i = 0; i < 16; ++i) {
        temp[i] = info_start[i];
    }
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            int position = 4 * i + j;
            info_start[position]
                    = mixCal14(temp[position])
                      ^ mixCal11(temp[4 * i + (j + 1) % 4])
                      ^ mixCal13(temp[4 * i + (j + 2) % 4])
                      ^ mixCal9(temp[4 * i + (j + 3) % 4]);
        }
    }
};//列混淆

void addRoundKey(uint8_t *info_start, uint8_t *key) {
    for (int i = 0; i < 16; ++i) {
        info_start[i] ^= key[i];
    }
};//与键值异或

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

void aesEncrypt(uint8_t *info_start, uint8_t *key) {
    addRoundKey(info_start, key);
    for (int i = 1; i < 11; ++i) {
        subBytes(info_start);
        shiftRows(info_start);
        if (i < 10) {
            mixColumns(info_start);
        }
        addRoundKey(info_start, key + 16 * i);
    }
};

void cbcDeal(uint8_t *info, uint8_t *iv) {
    for (int i = 0; i < 16; ++i) {
        info[i] ^= iv[i];
    }
}

void aesDecrypt(uint8_t *info, uint8_t *key) {//解码的时候要反过来
    for (int i = 10; i > 0; --i) {
        addRoundKey(info, key + 16 * i);
        if (i < 10) {
            deMixColumns(info);
        }
        deShiftRows(info);
        deSubBytes(info);
    }
    addRoundKey(info, key);
}

/**
 * 去掉带向量部分的计算就是单纯的无向量加密函数了,
 * 如果不需要向量解密,可以把那两块代码直接拿掉
 * 拿掉以后调用外面的函数无论带不带向量都会变成ECB模式进行加密
 */
char *encryptDetail(const char *info, const char *key, const char *iv) {
    size_t info_length = strlen(info);//明文的长度
    size_t info_pcks5_num = info_length / 16 + 1;//明文用PCKS5Padding填充后的段是
    size_t info_length_max = (info_pcks5_num) * 16;//明文填充后的长度
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

    //---------------------------------------------------------Start 带向量计算部分
    uint8_t iv_result[16];
    if (iv != NULL) {
        for (int m = 0; m < 16; ++m) {
            iv_result[m] = (uint8_t) iv[m];
        }
    }
    //---------------------------------------------------------end 带向量计算部分


    for (int i = 0; i < info_pcks5_num; ++i) {//明文进行分段加密
        //---------------------------------------------------------Start 带向量计算部分
        if (iv != NULL) {
            if (i == 0) {
                cbcDeal(info_result, iv_result);
            } else {
                cbcDeal(info_result + i * 16, info_result + (i - 1) * 16);
            }
        }
        //---------------------------------------------------------end 带向量计算部分
        aesEncrypt(info_result + i * 16, key_result);
    }
    char *base64En = b64_encode(info_result, info_length_max);
    free(info_result);
    return base64En;
}

char *decryptDetail(const char *info, const char *key, const char *iv) {
    size_t base_info_length = strlen(info);//获取被Base64编码后密文的长度
    int add_num = 0;
    for (size_t i = base_info_length - 4; i < base_info_length; ++i) {//计算最后四位包含 = 的数量
        if (info[i] == '=') {
            add_num += 1;
        }
    }
    size_t result_length = base_info_length / 4 * 3 - add_num;//编码前原文的长度
    int encrypt_num = static_cast<int>(result_length / 16);//计算出密文的分段数
    if (encrypt_num <= 0) {
        return NULL;
    }
    uint8_t *info_result = b64_decode(info, base_info_length);//前面有用Base64编码,所以要反Base64编码获得加密后的明文

    uint8_t key_result[176];
    getKey(key, key_result);//密钥扩展

    uint8_t iv_result[16];
    //---------------------------------------------------------Start 带向量计算部分
    if (iv != NULL) {
        for (int i = 0; i < 16; ++i) {
            iv_result[i] = (uint8_t) iv[i];
        }
    }
    //---------------------------------------------------------end 带向量计算部分
    for (int i = encrypt_num - 1; i >= 0; --i) {
        aesDecrypt(info_result + i * 16, key_result);
        //---------------------------------------------------------Start 带向量计算部分
        if (iv != NULL) {
            if (i > 0) {
                cbcDeal(info_result + i * 16, info_result + (i - 1) * 16);
            } else {
                cbcDeal(info_result + i * 16, iv_result);
            }
        }
        //---------------------------------------------------------end 带向量计算部分
    }

    char *result = NULL;
    result = (char *) malloc(0);
    if (result == NULL) {
        return NULL;
    }
    result = (char *) realloc(result, result_length + 1);

    for (int i = 0; i < result_length; ++i) {
        result[i] = info_result[i];
    }
    result[result_length] = '\0';
    return result;
}


char *PCKS5Padding128Encrypt(const char *info, const char *key) { //ECB模式加密
    return encryptDetail(info, key, NULL);
};

char *PCKS5Padding128Decrypt(const char *info, const char *key) { //ECB模式解密
    return decryptDetail(info, key, NULL);
};

char *PCKS5Padding128CBCEncrypt(const char *info, const char *key, const char *iv) { //CBC模式加密
    return encryptDetail(info, key, iv);
};

char *PCKS5Padding128CBCDecrypt(const char *info, const char *key, const char *iv) { //CBC模式解密
    return decryptDetail(info, key, iv);
};


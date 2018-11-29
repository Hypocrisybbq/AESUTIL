//
// Created by chen on 2018/11/22.
//

#ifndef AESUTIL_AES_H
#define AESUTIL_AES_H

#define AES_128
#ifdef AES_128
#define key_num 16
#define key_rounds 10
#endif

/**
 *第一参数是需要密钥扩展的密钥,
 * 第二个是env.
 * 第三个参数是生成密钥的轮次,
 * 第四个是用来获取经过扩展后的密钥的数组指针
 */
void getKey(jstring key, JNIEnv *env, uint8_t result[key_rounds][key_num]);

/**
 *  uint8_t info[][16]: 明文分组后的明文数组
 *  size_t part_num: 明文分组后的组数
 *   uint8_t key[key_rounds][key_num]: 扩展后的密钥
 */
void encrypt_ecb(uint8_t info[][16], size_t part_num, uint8_t key[key_rounds][key_num]);

#endif //AESUTIL_AES_H

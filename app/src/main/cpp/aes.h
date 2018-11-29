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
 *第一参数是需要密钥扩展的密钥,第二个是env.第三个参数是生成密钥的轮次,第四个是经过扩展后的密钥
 */
void getKey(jstring key, JNIEnv *env, int rounds, uint8_t result[key_rounds][key_num]);

#endif //AESUTIL_AES_H

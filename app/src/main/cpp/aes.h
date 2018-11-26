//
// Created by chen on 2018/11/22.
//

#ifndef AESUTIL_AES_H
#define AESUTIL_AES_H

/**
 *第一参数是需要密钥扩展的密钥,第二个是env.第三个参数是生成密钥的轮次,第四个是经过扩展后的密钥
 */
uint8_t *getKey(jstring key, JNIEnv *env, int rounds, uint8_t *result);

#endif //AESUTIL_AES_H

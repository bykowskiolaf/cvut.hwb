//
// Created by Olaf Bykowski on 29/10/2024.
//

#ifndef AES_H
#define AES_H

#include <cstdint>

/* AES state type */
typedef uint32_t t_state[4];

void generateTBoxes();

void aes(uint8_t *in, uint8_t *out, uint8_t *skey);

#endif //AES_H

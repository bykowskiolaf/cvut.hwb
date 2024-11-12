//
// Created by Olaf Bykowski on 29/10/2024.
//

#ifndef HELPER_H
#define HELPER_H

#include <cstdint>

/* AES state type */
typedef uint32_t t_state[4];

// Function prototypes for helper functions
void hexprint16(uint8_t *p);
void hexprintw(uint32_t w);
void hexprintws(uint32_t *p, int cnt);
void printstate(t_state s);
uint32_t word(uint8_t a0, uint8_t a1, uint8_t a2, uint8_t a3);
uint8_t wbyte(uint32_t w, int pos);

#endif //HELPER_H

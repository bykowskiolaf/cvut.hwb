//
// Created by Olaf Bykowski on 29/10/2024.
//

#include "helper.h"
#include <cstdio>
#include <cstdint>

/* Helper functions */
void hexprint16(uint8_t *p) {
    for (int i = 0; i < 16; i++)
        printf("%02hhx ", p[i]);
    puts("");
}

void hexprintw(uint32_t w) {
    for (int i = 0; i < 32; i += 8)
        printf("%02hhx ", (w >> i) & 0xffU);
}

void hexprintws(uint32_t * p, int cnt) {
    for (int i = 0; i < cnt; i++)
        hexprintw(p[i]);
    puts("");
}
void printstate(t_state s) {
    hexprintw(s[0]);
    hexprintw(s[1]);
    hexprintw(s[2]);
    hexprintw(s[3]);
    puts("");
}

uint32_t word(uint8_t a0, uint8_t a1, uint8_t a2, uint8_t a3) {
    return a0 | (uint32_t)a1 << 8 | (uint32_t)a2 << 16 | (uint32_t)a3 << 24;
}

uint8_t wbyte(uint32_t w, int pos) {
    return (w >> (pos * 8)) & 0xff;
}

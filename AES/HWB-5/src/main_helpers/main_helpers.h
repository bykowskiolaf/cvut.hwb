//
// Created by Olaf Bykowski on 05/11/2024.
//

#ifndef MAIN_HELPERS_H
#define MAIN_HELPERS_H

#include <cstdint>

// Function declarations for AES testing helpers

void testSubBytes(int &test_failed);
void testShiftRows(int &test_failed);
void testMixColumns(int &test_failed);
void testXTime(int &test_failed);
void testExpandKey(int &test_failed);
void testAES(int &test_failed);

#endif //MAIN_HELPERS_H

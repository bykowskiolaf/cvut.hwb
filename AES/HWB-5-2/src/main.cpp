#include <cstdio>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include "aes/aes.h"
#include "main_helpers/main_helpers.h"

/*
Author: Olaf Hubert Bykowski, bykowola@fit.cvut.cz
Template: Jiri Bucek 2017
AES specification: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
*/

constexpr int DEFAULT_ITERATIONS = 1'000'000;  // Default number of iterations for averaging

int main(int argc, char *argv[]) {
    // Determine number of iterations from command-line argument, or use default
    const int iterations = (argc > 1) ? std::atoi(argv[1]) : DEFAULT_ITERATIONS;

    generateTBoxes();

    uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    uint8_t data[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    int test_failed = 0;
    testExpandKey(test_failed);

    if (test_failed) {
        printf("testExpandKey failed, exiting\n");
        return 1;
    }

    testXTime(test_failed);

    if (test_failed) {
        printf("testXTime failed, exiting\n");
        return 1;
    }

    testAES(test_failed);

    if (test_failed) {
        printf("testAES failed, exiting\n");
        return 1;
    }


    // Start measuring the total time for the loop
    const auto start = std::chrono::high_resolution_clock::now();

    // OFB Mode: output is fed back as input for the next round
    for (int i = 0; i < iterations; ++i) {
        aes(data, data, key);
    }

    const auto end = std::chrono::high_resolution_clock::now();
    const std::chrono::duration<double, std::milli> total_duration = end - start;

    // Print the resulting total time in milliseconds
    printf("Total time for %d iterations: %.2f ms\n", iterations, total_duration.count());

    // Set the program return code to the first byte of the output
    return data[0];
}

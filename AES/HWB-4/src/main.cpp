#include <cstdio>
#include <chrono>
#include "main_helpers/main_helpers.h"

/*
Author: Olaf Hubert Bykowski, bykowola@fit.cvut.cz
Template: Jiri Bucek 2017
AES specification: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
*/

constexpr int N = 1'000'000;  // Number of iterations for averaging

int main(int argc, char *argv[]) {
    int test_failed = 0;

    // Variables to accumulate total durations
    std::chrono::duration<double, std::micro> total_duration_subBytes(0);
    std::chrono::duration<double, std::micro> total_duration_shiftRows(0);
    std::chrono::duration<double, std::micro> total_duration_mixColumns(0);
    std::chrono::duration<double, std::micro> total_duration_xtime(0);
    std::chrono::duration<double, std::micro> total_duration_expandKey(0);
    std::chrono::duration<double, std::micro> total_duration_aes(0);

    for (int i = 0; i < N; ++i) {
        // Measure subBytes
        auto start = std::chrono::high_resolution_clock::now();
        testSubBytes(test_failed);
        auto end = std::chrono::high_resolution_clock::now();
        total_duration_subBytes += (end - start);

        // Measure shiftRows
        start = std::chrono::high_resolution_clock::now();
        testShiftRows(test_failed);
        end = std::chrono::high_resolution_clock::now();
        total_duration_shiftRows += (end - start);

        // Measure mixColumns
        start = std::chrono::high_resolution_clock::now();
        testMixColumns(test_failed);
        end = std::chrono::high_resolution_clock::now();
        total_duration_mixColumns += (end - start);

        // Measure xtime
        start = std::chrono::high_resolution_clock::now();
        testXTime(test_failed);
        end = std::chrono::high_resolution_clock::now();
        total_duration_xtime += (end - start);

        // Measure expandKey
        start = std::chrono::high_resolution_clock::now();
        testExpandKey(test_failed);
        end = std::chrono::high_resolution_clock::now();
        total_duration_expandKey += (end - start);

        // Measure AES encryption
        start = std::chrono::high_resolution_clock::now();
        testAES(test_failed);
        end = std::chrono::high_resolution_clock::now();
        total_duration_aes += (end - start);
    }

    // Calculate and print average durations
    printf("|--------------------------------|\n");
    printf("|  subBytes:      %10.2f us  |\n", total_duration_subBytes.count() / N);
    printf("|  shiftRows:     %10.2f us  |\n", total_duration_shiftRows.count() / N);
    printf("|  mixColumns:    %10.2f us  |\n", total_duration_mixColumns.count() / N);
    printf("|  xtime:         %10.2f us  |\n", total_duration_xtime.count() / N);
    printf("|  expandKey:     %10.2f us  |\n", total_duration_expandKey.count() / N);
    printf("|  aes:           %10.2f us  |\n", total_duration_aes.count() / N);
    printf("|  Total:         %10.2f ms  |\n", (total_duration_subBytes + total_duration_shiftRows + total_duration_mixColumns + total_duration_xtime + total_duration_expandKey + total_duration_aes).count() / 1000);
    printf("|--------------------------------|\n");

    if (test_failed) {
        printf("|*********** SOME TEST(S) FAILED ***********|\n");
        printf("Please fix me!\n");
    } else {
        printf("============== All tests OK! ===============\n");
    }

    return test_failed;
}

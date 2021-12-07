/*
 * @Date: 2021-12-07 00:28:32
 * @LastEditors: zx Zhou
 * @LastEditTime: 2021-12-08 00:17:35
 * @FilePath: /libdft64/tools/strcmp_test.cpp
 */

#include <iostream>
#include <cstdlib>
#include <cstring>

extern "C" {
void __attribute__((noinline)) __libdft_set_taint(void *p, unsigned int v) {
  printf("set: %p, %d\n", p, v);
}

void __attribute__((noinline)) __libdft_get_taint(void *p) {
  printf("get: %p\n", p);
}

void __attribute__((noinline)) __libdft_getval_taint(uint64_t v) {
  printf("getval: %lu\n", v);
}
}


int main(int argc, char* argv[]){
    FILE *f = fopen("/home/xposimon/Desktop/buginj/libdft64/tools/cur_input", "rb");
    char input[20];
    fread(input, 1, 20, f);
    fclose(f);
    char a[20] = "this is a test!!!!!";
    a[15] = input[14];
    a[2] = input[4];
    // printf("%s\n", input);
    __libdft_get_taint(a);
    __libdft_getval_taint(a[0]);
    __libdft_get_taint(input);
    __libdft_getval_taint(input[0]);
    if(!strcmp(a, input))printf("OK\n");
    return 0;
}
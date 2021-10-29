#include<cstdio>
#include<cstdlib>
#include<cstdint>
#include<cstring>

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

void f1(char* str){
	if (!strcmp(str, "check")){
		printf("[+] pass check 2\n");
	}
	return ;
}

int foo(int a){

printf("foo num: %d\n", a);
__libdft_get_taint(&a);
__libdft_getval_taint(a);
if (a == 0x62){
	printf("[+] pass check 3\n");
	return 1;
}
return 0; 
}

int foo2(int b){

printf("foo2 num: %d\n", b);
//__libdft_get_taint(&b);
//__libdft_getval_taint(b);
if (b == 0x63){
	printf("[+] pass check 3\n");
	return 1;
}
return 0; 
}

typedef int (*fptr)(int) ;

fptr farray[2] = { foo, foo2 };

int main(){
	FILE *f = fopen("/home/xposimon/Desktop/buginj/libdft64/tools/cur_input", "rb");
	char input[20];
	fread(input, 1, 20, f);
	printf("%s\n", input);
	if (input[0] == 'm' && input[1] == 'a'){
		printf("[+] pass check 1\n");
	}
	int i = 3; 
	int res = 0;
	for (; i <5; i++){
	res += farray[i-3](input[i]);
	}
	f1(input+5);
	__libdft_get_taint(&res);
	__libdft_getval_taint(res);
	return 0;
}

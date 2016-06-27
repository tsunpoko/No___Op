#include<stdio.h>

//gcc -o test -m32 test.c

int flag(){
	system("/bin/sh");
	exit(0);
}

int main(){
	char buf[128];
	
	printf(">>> ");
	gets(&buf);
	printf(buf);
	puts("");
	return 0;
}

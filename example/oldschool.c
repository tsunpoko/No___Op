#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main( )
{
    char buf[1024] = { 0, };

    printf( "YOUR INPUT :" );

    fgets( buf, 1020, stdin );

    printf( "RESPONSE :" );
    
    printf( buf );

    return 0;
}

# Insert some shit here

## mongoose.h
Modifiied <openssl/ssl.h> inlude to <wolfssl/openssl/ssl.h>

## Compilation, probably
### With mongoose 5.1
gcc -DUSE_SSL -DUSE_CYASSL -DHAVE_MD5 ./src/main.c ./src/mongoose.c -o mongoose -Wall -Wextra -lwolfssl -g

### With mongoose 6.5
gcc main.c mongoose.c -o mongoose -lwolfssl
#include <iostream>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>

using namespace std;

int main()
{
    printf("OpenSSL version: %s %s\n", OPENSSL_VERSION_TEXT, OpenSSL_version(OPENSSL_DIR));
}
#include <cstdio>

int main()
{
    char temp[100] = " ";
    char str[] = "Hello, World!";

    sprintf(temp, "%s", str);

    printf("temp: %s\n", temp);

    return 0;
}
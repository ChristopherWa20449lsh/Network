#include <thread>
#include <iostream>

using namespace std;

void func()
{
    int i = 0;
    while (true)
        ;
}

int main()
{
    thread th(func);
    th.detach();
    while (true)
        ;
    return 0;
}
#include <iostream>
#include <stdio.h>
#include <string>
#include <map>

using namespace std;

int main()
{
    map<string, const char *> m_typeMap;
    m_typeMap["html"] = "text/html";

    map<string, const char *>::iterator it = m_typeMap.find("html");

    printf("%s\n", it->second); // Output: text/html

    return 0;
}
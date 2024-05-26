#include <iostream>
#include <fstream>
#include <random>

using namespace std;

int main()
{
    int n = 0; // number of bytes

    cout << "Enter the number of bytes to generate: ";
    cin >> n;

    string filename = "test.txt";

    ofstream file(filename, ios::binary);
    if (!file)
    {
        cout << "Failed to open file for writing." << endl;
        return 1;
    }

    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < n; ++i)
    {
        unsigned char byte = static_cast<unsigned char>(dis(gen));
        file.write(reinterpret_cast<const char *>(&byte), sizeof(byte));
    }

    file.close();
    cout << "Text file generated successfully." << endl;

    return 0;
}
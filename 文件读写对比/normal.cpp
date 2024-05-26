#include <iostream>
#include <fstream>
#include <string>
#include <chrono>

using namespace std;

int main()
{

    auto start = chrono::high_resolution_clock::now();

    // Code to be timed
    ifstream inputFile("test.txt");
    if (inputFile.is_open())
    {
        string line;
        while (getline(inputFile, line))
        {
            // Do something with the line if needed
        }
        inputFile.close();
    }
    else
    {
        cout << "Failed to open the file." << endl;
    }
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
    cout << "Time taken: " << duration.count() << " milliseconds" << endl;

    return 0;
}
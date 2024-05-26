#include <openssl/bio.h>
#include <iostream>
#include <chrono>

using namespace std;

int main()
{
    auto start = chrono::high_resolution_clock::now();

    // 创建一个缓冲 BIO
    BIO *bio = BIO_new(BIO_f_buffer());

    // 创建一个文件 BIO
    BIO *file_bio = BIO_new_file("test.txt", "r");

    // 将缓冲 BIO 链接到文件 BIO
    BIO_push(bio, file_bio);

    // 读取文件
    char buffer[1024];
    while (true)
    {
        int bytes = BIO_read(bio, buffer, sizeof(buffer));
        if (bytes <= 0)
        {
            break;
        }
        // do nothing
    }

    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
    cout << "Time taken: " << duration.count() << " milliseconds" << endl;

    // 清理
    BIO_free_all(bio);

    return 0;
}
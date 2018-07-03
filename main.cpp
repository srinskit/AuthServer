#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string>
#include <pthread.h>
#include <csignal>
#include <list>
#include <queue>
#include <experimental/filesystem>
#include <arpa/inet.h>
#include "Crypt.h"

#define AS_PORT 8000
namespace fs = std::experimental::filesystem;
sig_atomic_t volatile shutdown_signaled = 0;
Crypt myCrypt;
SecureSock::Server server(&myCrypt);

void split(const std::string &str, char ch, std::vector<std::string> &res) {
    unsigned long i = std::string::npos, prev_i;
    do {
        ++i;
        prev_i = i;
        i = str.find_first_of(ch, prev_i);
        res.push_back(str.substr(prev_i, i - prev_i));
    } while (i < str.length());
}

void process(int from, const std::string &buff) {
    std::cout << buff << std::endl;
    std::vector<std::string> res;
    split(buff, ';', res);
    if (res[0] == "REG_PUB") {
        // REG_PUB; topic
        std::string key;
        if (!myCrypt.aes_get_key(res[1], key)) {
            myCrypt.aes_gen_key(key);
            myCrypt.aes_save_key(res[1], key);
        }
        server.write(from, key);
    } else if (res[0] == "REG_SUB") {
        // REG_SUB; topic
        std::string key;
        if (!myCrypt.aes_get_key(res[1], key)) {
            myCrypt.aes_gen_key(key);
            myCrypt.aes_save_key(res[1], key);
        }
        server.write(from, key);
    }
}

void mySigIntHandler(__attribute__((unused))int sig) {
    shutdown_signaled = 1;
    server.close();
}

std::list<int> *descriptors = nullptr;
std::queue<int> *accept_queue = nullptr;

void *core(void *_) {
    std::string buff;
    int max_descriptor = 0;
    fd_set read_set, err_set;
    while (!shutdown_signaled) {
        // Following while is the only critical section
        // Done to guarantee 'descriptors' is unchanged after select
        while (!accept_queue->empty()) {
            descriptors->push_back(accept_queue->front());
            accept_queue->pop();
        }
        FD_ZERO(&read_set);
        FD_ZERO(&err_set);
        max_descriptor = 0;
        for (auto &fd :*descriptors) {
            max_descriptor = std::max(max_descriptor, fd);
            FD_SET(fd, &read_set);
            FD_SET(fd, &err_set);
        }
        timeval timeout{0, 100000};
        auto sret = select(max_descriptor + 1, &read_set, nullptr, &err_set, &timeout);
        if (shutdown_signaled || sret <= 0)
            continue;
        descriptors->remove_if([err_set](int fd) { return FD_ISSET(fd, &err_set); });
        auto it = descriptors->begin();
        int fd;
        while (it != descriptors->end()) {
            fd = *it;
            ++it;
            if (FD_ISSET(fd, &read_set)) {
                ssize_t ret;
                buff.clear();
                if ((ret = server.read(fd, buff)) < 0) {
                    perror("read");
                } else if (ret == 0) {
                    descriptors->remove(fd);
                    printf("A client disconnected\n");
                } else {
                    process(fd, buff);
                }
            }
        }
    }
    pthread_exit(nullptr);
}

int main(int argc, char const *argv[]) {
    signal(SIGINT, mySigIntHandler);
    signal(SIGTERM, mySigIntHandler);
    int client_fd;
    myCrypt.initialize("AUS");
    const std::string root_ca_dir = getenv("ROOT_CA_DIR");
    myCrypt.add_cert("root", root_ca_dir + "root/rootca.crt");
    myCrypt.add_cert("S1", root_ca_dir + "inter/S1/S1.crt");
    myCrypt.load_my_key(root_ca_dir + "enduser/AuthServer/AuthServer.key", "");
    myCrypt.load_my_cert(root_ca_dir + "enduser/AuthServer/AuthServer.crt", "S1", true);
    if (!(server.init() && server.bind(AS_PORT) && server.listen("root", true))) {
        printf("Could not start server\n");
        myCrypt.terminate();
        return EXIT_FAILURE;
    }
    descriptors = new std::list<int>();
    accept_queue = new std::queue<int>();
    pthread_t pthread;
    pthread_create(&pthread, nullptr, core, nullptr);
    while (!shutdown_signaled) {
        if ((client_fd = server.accept()) < 0) {
            continue;
        }
        if (shutdown_signaled) break;
        accept_queue->push(client_fd);
    }
    pthread_join(pthread, nullptr);
    delete (descriptors);
    delete (accept_queue);
    myCrypt.terminate();
    return 0;
}


//    fs::path path;
//    path = "../Certificates";
//    for (auto &p : fs::directory_iterator(path)) {
//        auto pth = fs::path(p);
//        myCrypt.add_cert(pth.stem(), pth.c_str());
//    }
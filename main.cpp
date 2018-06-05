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
#include "Crypt/Crypt.h"

#define AS_PORT 8080
namespace fs = std::experimental::filesystem;
sig_atomic_t volatile shutdown_signaled = 0;

void mySigIntHandler(__attribute__((unused))int sig) {
    shutdown_signaled = 1;
}

std::list<int> *descriptors = nullptr;
std::queue<int> *accept_queue = nullptr;

void *core(void *_) {
    Crypt myCrypt;
    myCrypt.load_private_key("../CryptDocs/AuthServer.key", "");
    myCrypt.add_cert("self", "../CryptDocs/AuthServer.crt");
    fs::path path;
    path = "../Certificates";
    for (auto &p : fs::directory_iterator(path)) {
        auto pth = fs::path(p);
        myCrypt.add_cert(pth.stem(), pth.c_str());
    }
    char buffer[1024];
    int max_descriptor = 0, num_clients;
    fd_set read_set, err_set;
    timeval timeout{0, 100000};
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
                if ((ret = read(fd, buffer, sizeof(buffer))) < 0) {
                    perror("read");
                } else if (ret == 0) {
                    descriptors->remove(fd);
                    printf("A client disconnected\n");
                } else {
                    printf("%s\n", buffer);
                }
            }
        }
    }
    pthread_exit(nullptr);
}

int main(int argc, char const *argv[]) {
    signal(SIGINT, mySigIntHandler);
    descriptors = new std::list<int>();
    accept_queue = new std::queue<int>();
    int server_fd, new_socket;
    sockaddr_in address{};
    int opt = 1;
    int address_len = sizeof(address);
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(AS_PORT);
    if (bind(server_fd, (struct sockaddr *) &address, sizeof(address)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 5) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    pthread_t pthread;
    pthread_create(&pthread, nullptr, core, nullptr);
    while (!shutdown_signaled) {
        if ((new_socket = accept(server_fd, (struct sockaddr *) &address, (socklen_t *) &address_len)) < 0) {
            if (shutdown_signaled)
                break;
            perror("accept");
            exit(EXIT_FAILURE);
        }
        accept_queue->push(new_socket);
    }
    pthread_join(pthread, nullptr);
    delete (descriptors);
    delete (accept_queue);
    return 0;
}

//    send(new_socket, hello.c_str(), hello.length(), 0);
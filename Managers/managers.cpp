//
// Created by crl on 2/24/22.
//

#include "managers.h"
#include <csignal>
#include <cerrno>

int Managers::SocketManager::write_n(int socket, size_t amount, void *buff) {
    size_t tot = 0;
    size_t n;
    while (tot < amount){
        n = write(socket,buff,amount);
        if(n == -1 && errno != EINTR)
            return -1;
        tot += n;
    }
    return 1;
}
int Managers::SocketManager::read_n(int socket, size_t amount, void *buff) {
    size_t tot = 0;
    size_t n;
    while (tot < amount){
        n = read(socket,buff,amount);
        if(n == -1 && errno != EINTR)
            return -1;
        tot += n;
    }
    return 1;
}

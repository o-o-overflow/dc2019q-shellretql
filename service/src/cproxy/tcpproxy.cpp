/* 
 *  A simple TCP proxy
 *  by Martin Broadhurst (www.martinbroadhurst.com)
 *  Usage: tcpproxy local_host local_port remote_host remote_port
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memset() */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>
#include <pthread.h>
#include <linux/seccomp.h>
#include <seccomp.h> /* libseccomp */

#define BACKLOG  10      /* Passed to listen() */
#define BUF_SIZE 2048    /* Buffer for  transfers */

const char *local_host, *local_port, *remote_host, *remote_port;
bool DEBUG;

unsigned int transfer(int from, int to)
{
    char buf[1337];
    unsigned int disconnected = 0;
    size_t bytes_read, bytes_written;
    bytes_read = read(from, buf, BUF_SIZE);
    if (DEBUG){
      printf("Bytes Read = %ld '%s'\n",bytes_read, buf);
    }

    if (bytes_read == 0) {
        disconnected = 1;
    }
    else {

        if (bytes_read > 1337){
            bytes_written = write(to, buf, bytes_read+16);
        } else {
            bytes_written = write(to, buf, bytes_read);
        }

        if (DEBUG){
          printf("Bytes Written = %ld \n",bytes_written);
        }

        if (bytes_written == -1) {
            disconnected = 1;
        }
    }
    return disconnected;
}
 
void *handle(void *clientptr)
{
    struct addrinfo hints, *res;
    int client = *(int*) (clientptr);
    int server = -1;
    unsigned int disconnected = 0;
    fd_set set;
    unsigned int max_sock;
 
    /* Get the address info */
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(remote_host, remote_port, &hints, &res) != 0) {
        perror("getaddrinfo");
        close(client);
        return NULL;
    }
 
    /* Create the socket */
    server = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (server == -1) {
        perror("socket");
        close(client);
        return NULL;
    }
 
    /* Connect to the host */
    if (connect(server, res->ai_addr, res->ai_addrlen) == -1) {
        perror("connect");
        close(client);
        return NULL;
    }
 
    if (client > server) {
        max_sock = client;
    }
    else {
        max_sock = server;
    }
 
    /* Main transfer loop */
    while (!disconnected) {
        FD_ZERO(&set);
        FD_SET(client, &set);
        FD_SET(server, &set);
        if (select(max_sock + 1, &set, NULL, NULL, NULL) == -1) {
            perror("select");
            break;
        }
        if (FD_ISSET(client, &set)) {
            disconnected = transfer(client, server);
        }
        if (FD_ISSET(server, &set)) {
            disconnected = transfer(server, client);
        }
    }
    close(server);
    close(client);
    return NULL;
}
 
int main(int argc, char **argv)
{
    int sock;
    struct addrinfo hints, *res;
    int reuseaddr = 1; /* True */
    pthread_t thread;
    scmp_filter_ctx ctx;
    int rc = 0;

    /* Get the local and remote hosts and ports from the command line */
    if (argc < 5) {
        fprintf(stderr, "Usage: tcpproxy local_host local_port remote_host remote_port\n");
        return 1;
    }
    local_host = argv[1];
    local_port = argv[2];
    remote_host = argv[3];
    remote_port = argv[4];

    DEBUG = getenv("DEBUG") != NULL;

    /* Get the address info */
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(local_host, local_port, &hints, &res) != 0) {
        perror("getaddrinfo");
        return 1;
    }
 
    /* Create the socket */
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == -1) {
        perror("socket");
        freeaddrinfo(res);
        return 1;
    }
 
    /* Enable the socket to reuse the address */
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int)) == -1) {
        perror("setsockopt");
        freeaddrinfo(res);
        return 1;
    }
 
    /* Bind to the address */
    if (bind(sock, res->ai_addr, res->ai_addrlen) == -1) {
        perror("bind");
        freeaddrinfo(res);
        return 1;
    }
 
    /* Listen */
    if (listen(sock, BACKLOG) == -1) {
        perror("listen");
        freeaddrinfo(res);
        return 1;
    }
 
    freeaddrinfo(res);
 
    /* Ignore broken pipe signal */
    signal(SIGPIPE, SIG_IGN);

    ctx = seccomp_init(SCMP_ACT_KILL); // default action: kill
    printf("setting seccomps\n");
    // setup strict whitelist
    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
//    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept), 0);
    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(select), 0);
    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 0);
    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0);
    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0);
    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(madvise), 0);
    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);
    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);

    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
                        SCMP_A1(SCMP_CMP_EQ, 0)
                        );

//    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
//                        SCMP_A0(SCMP_CMP_EQ, 1)
//                        );
//    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
//                        SCMP_A0(SCMP_CMP_EQ, 2)
//                        );

//    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 0);
//    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bind), 0);
//    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(listen), 0);
//    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockopt), 0);
//    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmsg), 0);
//    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg), 0);
//    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);
//    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);
//    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shutdown), 0);
//    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
//    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socketpair), 0);
//    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockname), 0);
//    rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);

    if (rc != 0) {
        perror("seccomp_rule_add failed");
        exit(-2);
    }

    // load the filter
    seccomp_load(ctx);
    if (rc != 0) {
        perror("seccomp_load failed");
        exit(-1);
    }

    /* Main loop */
    while (1) {
        socklen_t size = sizeof(struct sockaddr_in);
        struct sockaddr_in their_addr;
        int newsock = accept(sock, (struct sockaddr*)&their_addr, &size);
 
        if (newsock == -1) {
            perror("accept");
        }
        else {
            printf("Got a connection from %s on port %d\n",
                    inet_ntoa(their_addr.sin_addr), htons(their_addr.sin_port));
            int *safesock = (int *) malloc(sizeof(int));
            if (safesock) {
                *safesock = newsock;
                //handle(safesock);
                if (pthread_create(&thread, NULL, handle, safesock) != 0) {
                    fprintf(stderr, "Failed to create thread\n");
                }
            }
            else {
                perror("malloc");
            }
        }
    }
 
    close(sock);
 
    return 0;
}

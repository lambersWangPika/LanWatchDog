// raw-capture.c
// 使用 Raw Socket 捕获网络数据包
// 编译: gcc -o raw-capture.exe raw-capture.c -lws2_32 -liphlpapi
// 需要管理员权限运行

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define MAX_IPS 256

typedef struct {
    char ip[16];
    long long bytes_in;
    long long bytes_out;
    int packets;
} IP_STATS;

IP_STATS ip_stats[MAX_IPS];
int ip_count = 0;
char local_ip[16] = "";

void init_stats() {
    memset(ip_stats, 0, sizeof(ip_stats));
    ip_count = 0;
}

int find_ip_index(char* ip) {
    for (int i = 0; i < ip_count; i++) {
        if (strcmp(ip_stats[i].ip, ip) == 0) {
            return i;
        }
    }
    if (ip_count >= MAX_IPS) return -1;
    strcpy(ip_stats[ip_count].ip, ip);
    return ip_count++;
}

void parse_ip_packet(unsigned char* buffer, int len) {
    if (len < 20) return;
    
    int version = buffer[0] >> 4;
    if (version != 4) return;
    
    int header_len = (buffer[0] & 0x0F) * 4;
    if (len < header_len) return;
    
    int total_len = (buffer[2] << 8) | buffer[3];
    
    // 源IP和目标IP
    char src_ip[16], dst_ip[16];
    sprintf(src_ip, "%d.%d.%d.%d", buffer[12], buffer[13], buffer[14], buffer[15]);
    sprintf(dst_ip, "%d.%d.%d.%d", buffer[16], buffer[17], buffer[18], buffer[19]);
    
    int payload_len = total_len - header_len;
    if (payload_len <= 0) return;
    
    // 更新统计
    int src_idx = find_ip_index(src_ip);
    int dst_idx = find_ip_index(dst_ip);
    
    if (src_idx >= 0) {
        ip_stats[src_idx].bytes_out += payload_len;
        ip_stats[src_idx].packets++;
    }
    if (dst_idx >= 0) {
        ip_stats[dst_idx].bytes_in += payload_len;
        ip_stats[dst_idx].packets++;
    }
}

char* char* get_local_ip() {
    ULONG size = 15000;
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(size);
    
    if (GetAdaptersInfo(pAdapterInfo, &size) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(size);
    }
    
    if (GetAdaptersInfo(pAdapterInfo, &size) != NO_ERROR) {
        free(pAdapterInfo);
        return "";
    }
    
    PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
    while (pAdapter) {
        if (pAdapter->IpAddressList.IpAddress.String[0] != '0' && 
            strcmp(pAdapter->IpAddressList.IpAddress.String, "127.0.0.1") != 0) {
            strcpy(local_ip, pAdapter->IpAddressList.IpAddress.String);
            break;
        }
        pAdapter = pAdapter->Next;
    }
    
    free(pAdapterInfo);
    return local_ip;
}

int main(int argc, char* argv[]) {
    int duration = 10; // 默认10秒
    if (argc > 1) {
        duration = atoi(argv[1]);
    }
    
    // 初始化 Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("{}\\n\"error\": \"WSAStartup failed\\n"}\\n");
        return 1;
    }
    
    // 获取本地IP
    if (strlen(get_local_ip()) == 0) {
        printf("{}\\n\"error\": \"No local IP found\\n"}\\n");
        WSACleanup();
        return 1;
    }
    
    // 创建原始套接字
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (sock == INVALID_SOCKET) {
        printf("{}\\n\"error\": \"socket failed: %d\\n"}\\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    
    // 绑定到本地IP
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(local_ip);
    addr.sin_port = 0;
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printf("{}\\n\"error\": \"bind failed: %d\\n"}\\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    
    // 启用 SIO_RCVALL
    DWORD dwBytesReturned = 0;
    DWORD dwMode = 2; // RCVALL_IPLEVEL
    if (WSAIoctl(sock, SIO_RCVALL, &dwMode, sizeof(dwMode), NULL, 0, &dwBytesReturned, NULL, NULL) == SOCKET_ERROR) {
        dwMode = 1; // RCVALL_ON
        if (WSAIoctl(sock, SIO_RCVALL, &dwMode, sizeof(dwMode), NULL, 0, &dwBytesReturned, NULL, NULL) == SOCKET_ERROR) {
            printf("{}\\n\"error\": \"WSAIoctl failed: %d\\n"}\\n", WSAGetLastError());
            closesocket(sock);
            WSACleanup();
            return 1;
        }
    }
    
    // 设置超时
    DWORD timeout = 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    
    // 初始化统计
    init_stats();
    
    // 开始捕获
    unsigned char buffer[65535];
    time_t start_time = time(NULL);
    int packet_count = 0;
    
    printf("{}\\n\"status\": \"capturing\", \"local_ip\": \"%s\", \"duration\": %d}\\n", local_ip, duration);
    
    while (time(NULL) - start_time < duration) {
        int n = recv(sock, (char*)buffer, sizeof(buffer), 0);
        if (n > 0) {
            parse_ip_packet(buffer, n);
            packet_count++;
        }
    }
    
    // 输出JSON结果
    printf("{}\\n\"result\": {");
    printf("\"local_ip\": \"%s\",", local_ip);
    printf("\"duration\": %d,", duration);
    printf("\"packet_count\": %d,", packet_count);
    printf("\"ips\": [");
    
    int first = 1;
    for (int i = 0; i < ip_count; i++) {
        if (ip_stats[i].bytes_in > 0 || ip_stats[i].bytes_out > 0) {
            if (!first) printf(",");
            first = 0;
            printf("{}\\n\"ip\": \"%s\", \"bytes_in\": %lld, \"bytes_out\": %lld, \"packets\": %d}\\n",
                ip_stats[i].ip, ip_stats[i].bytes_in, ip_stats[i].bytes_out, ip_stats[i].packets);
        }
    }
    
    printf("]}\\n");
    printf("}}\\n");
    
    closesocket(sock);
    WSACleanup();
    
    return 0;
}

#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

using namespace std;

struct FTPPACK
{
    byte m_protocol[6]; /* protocol magic number (6 bytes) */
    byte m_type;                          /* type (1 byte) */
    byte m_status;                      /* status (1 byte) */
    uint32_t m_length;                    /* length (4 bytes) in Big endian*/
} __attribute__ ((packed));


const int MAXFILELEN = 4080;
char buffer_recv[MAXFILELEN] = {0};
char buffer_send[MAXFILELEN] = {0};
char buffer_file[MAXFILELEN] = {0};


int check(char* pro)
{
    if((pro[0]=='\xc1'&&pro[1]=='\xa1'&&pro[2]=='\x10'&&pro[3]=='f'&&pro[4]=='t'&&pro[5]=='p'))
        return 1;
    return 0;
}


int main(int argc,char** argv)
{
    
    int socketfd = socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in servaddr;
    servaddr.sin_port = htons(atoi(argv[2]));
    servaddr.sin_family = AF_INET;
    inet_pton(AF_INET,argv[1],&servaddr.sin_addr);
    bind(socketfd,(struct sockaddr *)&servaddr,sizeof(servaddr));
    listen(socketfd,128);

AGAIN:
    socklen_t clilen;
    struct sockaddr_in cliaddr;
    int client = accept(socketfd,(struct sockaddr *)&cliaddr,&clilen);
    
    while(1)
    {
        //cout << "h" << endl;
        
        memset(buffer_recv,0,sizeof(buffer_recv));
        memset(buffer_send,0,sizeof(buffer_send));

        recv(client,buffer_recv,sizeof(FTPPACK),0);
        FTPPACK recv_pack = *(FTPPACK *)buffer_recv;
        //cout << "hh" << endl;

        if (check((char*)recv_pack.m_protocol))
        {
            //open
            if(recv_pack.m_type == (byte)0xA1)
            {
                recv_pack.m_type = (byte) 0xA2;
                recv_pack.m_status = (byte) 1;
                memcpy(buffer_send, &recv_pack, sizeof(FTPPACK));

                send(client, buffer_send, sizeof(recv_pack), 0);
            }    
            //ls
            else if(recv_pack.m_type == (byte)0xA3)
            {
                //cout << "hhh" << endl;
                recv_pack.m_type = (byte)0xA4;

                FILE* fp = popen("ls","r");
                //cout << "hhhh" << endl;
                if(fp)
                {
                    char payload[2060];
                    int num = 0;
                    char* tmp = payload;
                    //cout << "hhhhh" << endl;
                    while(fgets(tmp, sizeof(tmp), fp))
                    {
                        num += strlen(tmp) ;
                        tmp += strlen(tmp) ;
                    }
                    //cout << "hhhhhh" << endl;
                    payload[num] = '\0';

                    recv_pack.m_length = htonl(12 + num + 1);
                    memcpy(buffer_send, &recv_pack, sizeof(FTPPACK));
                    memcpy(buffer_send + sizeof(FTPPACK), &payload, num + 1);
                
                    send(client, buffer_send, sizeof(FTPPACK) + num + 1, 0);

                    pclose(fp);
                }
                

            }
            //get
            else if(recv_pack.m_type == (byte)0xA5)
            {
                int filename_len = ntohl(recv_pack.m_length) - sizeof(FTPPACK);
                recv(client, buffer_recv + sizeof(FTPPACK), filename_len, 0);

                recv_pack.m_type = (byte)0xA6;
                recv_pack.m_length = htonl(12);
                char* filename = buffer_recv + sizeof(FTPPACK);

                FILE* fp = fopen(filename,"rb");

                if(fp == NULL)
                {
                    recv_pack.m_status = (byte)0;
                    memcpy(buffer_send, &recv_pack, sizeof(FTPPACK));
                    send(client, buffer_send, sizeof(FTPPACK), 0);
                }
                else
                {
                    recv_pack.m_status = (byte)1;
                    memcpy(buffer_send, &recv_pack, sizeof(FTPPACK));
                    send(client, buffer_send, sizeof(FTPPACK), 0);

                    memset(buffer_send,0,sizeof(buffer_send));
                    memset(buffer_file, 0 ,sizeof(buffer_file));

                    int cnt = 0;
                    int file_len = 0;
                    while( (cnt = fread(buffer_file, 1, MAXFILELEN, fp)) > 0 )
                    {
                        file_len += cnt;
                    }
                    fclose(fp);

                    FTPPACK datapack;
                    strcpy((char*)datapack.m_protocol,"\xc1\xa1\x10");
                    datapack.m_protocol[3] = (byte)'f';
                    datapack.m_protocol[4] = (byte)'t';
                    datapack.m_protocol[5] = (byte)'p';
                    datapack.m_type = (byte)0xFF;
                    datapack.m_status = (byte)0;
                    datapack.m_length = htonl(12 + file_len);
                    memcpy(buffer_send,&datapack, sizeof(FTPPACK));
                    send(client, buffer_send, sizeof(FTPPACK), 0);


                    FILE* fp1 = fopen(filename, "r");
                    cnt = file_len = 0;
                    while( (cnt = fread(buffer_file, 1, MAXFILELEN, fp1)) > 0 )
                    {
                        file_len += cnt;
                        memcpy(buffer_send , buffer_file, cnt);
                        send(client, buffer_send, cnt, 0);
                    }
                    fclose(fp1);

                }
            }
            //put
            else if(recv_pack.m_type == (byte)0xA7)
            {
                int filename_len = ntohl(recv_pack.m_length) - sizeof(FTPPACK);
                recv(client, buffer_recv + sizeof(FTPPACK), filename_len, 0);

                char* filename = buffer_recv + sizeof(FTPPACK);
                recv_pack.m_type = (byte)0xA8;
                recv_pack.m_length = htonl(12);

                memcpy(buffer_send, &recv_pack, sizeof(FTPPACK));
                send(client, buffer_send, sizeof(FTPPACK), 0);
                memset(buffer_file,0,sizeof(buffer_file));

                FILE* fp = fopen(filename,"wb");

                int first = 0;
                int cnt = 0;
                int file_len = 0;
                while(1)
                {
                    int bread = recv(client, buffer_file, MAXFILELEN, 0);
                    cnt += bread;

                    first ++;
                    if(first == 1)
                    {
                        FTPPACK recvp = *(FTPPACK*)buffer_file;
                        if(recvp.m_type == (byte)0xFF)
                        {
                            file_len = ntohl(recvp.m_length) - 12;
                        }
                        else
                            cout << "type error" << endl;
                        fwrite(buffer_file + sizeof(FTPPACK), 1, bread - 12, fp);
                    }
                    else
                    {
                        fwrite(buffer_file, 1, bread, fp);
                    }
                    if(cnt == file_len + sizeof(FTPPACK))
                        break;
                }
                fclose(fp);
            }
            //sha
            else if(recv_pack.m_type == (byte)0xA9)
            {
                int filename_len = ntohl(recv_pack.m_length) - sizeof(FTPPACK);
                recv(client, buffer_recv + sizeof(FTPPACK), filename_len, 0);

                recv_pack.m_type = (byte)0xAA;
                recv_pack.m_length = htonl(12);
                char* filename = buffer_recv + sizeof(FTPPACK);

                FILE* fp = fopen(filename,"rb");
                cout << filename << endl;
                if(fp == NULL)
                {
                    recv_pack.m_status = (byte)0;
                    memcpy(buffer_send, &recv_pack, sizeof(FTPPACK));
                    send(client, buffer_send, sizeof(FTPPACK), 0);
                }
                else
                {
                    fclose(fp);

                    recv_pack.m_status = (byte)1;
                    memcpy(buffer_send, &recv_pack, sizeof(FTPPACK));
                    send(client, buffer_send, sizeof(FTPPACK), 0);

                    memset(buffer_send,0,sizeof(buffer_send));
                    memset(buffer_file, 0 ,sizeof(buffer_file));

                    char cmd[2077] = "sha256sum ";
                    
                    strcat(cmd,filename);
                    
                    FILE* fp1 = popen(cmd,"r");
                    if(fp1)
                    {
                        FTPPACK datapack;
                        strcpy((char*)datapack.m_protocol,"\xc1\xa1\x10");
                        datapack.m_protocol[3] = (byte)'f';
                        datapack.m_protocol[4] = (byte)'t';
                        datapack.m_protocol[5] = (byte)'p';
                        datapack.m_type = (byte)0xFF;
                        datapack.m_status = (byte)0;

                        char payload[2060];
                        int num = 0;
                        char* tmp = payload;
                        
                        while(fgets(tmp, sizeof(tmp), fp1))
                        {
                            num += strlen(tmp) ;
                            tmp += strlen(tmp) ;
                            
                        }
                        
                        payload[num] = '\0';

                        datapack.m_length = htonl(12 + num + 1);
                        memcpy(buffer_send, &datapack, sizeof(FTPPACK));
                        memcpy(buffer_send + sizeof(FTPPACK), &payload, num + 1);
                
                        send(client, buffer_send, sizeof(FTPPACK) + num + 1, 0);

                        pclose(fp1);
                    }
                    
                }
            }
            //quit
            else if(recv_pack.m_type == (byte)0xAB)
            {
                recv_pack.m_type = (byte) 0xAC;
                memcpy(buffer_send, &recv_pack, sizeof(FTPPACK));

                send(client, buffer_send, sizeof(recv_pack), 0);

                goto AGAIN;
            }
        }
    }

    return 0;
}
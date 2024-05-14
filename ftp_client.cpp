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


enum CMD
{
    CMD_OPEN,
    CMD_LS,
    CMD_PUT,
    CMD_GET,
    CMD_SHA,
    CMD_QUIT
};

struct token
{
    int argc;
    vector<string> argv;
    CMD cmd;
};


const char prompt[] = "Client> ";
const int MAXLINE = 1024;
const int MAXARGS = 128;
const int MAXFILELEN = 4080;
string cmdline;
token tok;
int socketfd;
bool connected = 0;

char buf_send[MAXFILELEN] = {0};
char buf_read[MAXFILELEN] = {0};
char buf_file[MAXFILELEN] = {0};


int eval(string cmdline);
int parse(string cmdline,token* tok);

int open(token* tok);
int closefd();
int ls(token* tok);
int put(token* tok);
int get(token* tok);
int sha256(token* tok);
int quit();
int check(char* pro);


int main() 
{
    while (1)
    {
        cout << "(client)>>";
        getline(cin,cmdline);

        int res = eval(cmdline);
        if(res == 1)
        {
            cout << "quit client" << endl;
            break;
        }
        else if(res == -1)
        {
            cout << "cmd error" << endl;
        }
    }
    return 0;
}

int eval(string cmdline)
{
    int res = parse(cmdline,&tok);
    if(res < 0 || tok.argc == 0)
        return -1;

    if(tok.cmd == CMD_OPEN)
    {
        open(&tok);
    }
    else if(tok.cmd == CMD_LS)
    {
        ls(&tok);
    }
    else if(tok.cmd == CMD_GET)
    {
        get(&tok);
    }
    else if(tok.cmd == CMD_PUT)
    {
        put(&tok);
    }
    else if(tok.cmd == CMD_SHA)
    {
        sha256(&tok);
    }
    else if(tok.cmd == CMD_QUIT)
    {
        return quit();
    }
    else
        return -1;
    
    return 0;
}

int parse(string cmdline,token* tok)
{
    string delimeters = " \t\r\n";
    string buf = cmdline;
    int next,endbuf;

    if(cmdline.empty())
    {
        cout << "cmdline null" << endl;
        return -1;
    }

    endbuf = buf.size();
    tok->argc = 0;
    tok->argv.clear();

    
    for(size_t i = 0;i < endbuf;)
    {
        i = buf.find_first_not_of(delimeters,i);
        if(i >= endbuf || i == string::npos)
            break;
        
        next = buf.find_first_of(delimeters,i);
        //buf[next] = '\0';
        if(next == string::npos)
            next = endbuf;

        tok->argv.push_back(buf.substr(i,next-i));
        tok->argc++;

        i = next + 1;
    }

    tok->argv.push_back("");

    if(tok->argc == 0)
    {
        return 1;//不正常
    }

    if(tok->argv[0] == "open")
    {
        tok->cmd = CMD_OPEN;
    }
    else if (tok->argv[0] == "ls")
    {
        tok->cmd = CMD_LS;
    }
    else if(tok->argv[0] == "put")
    {
        tok->cmd = CMD_PUT;
    }
    else if(tok->argv[0] == "get")
    {
        tok->cmd = CMD_GET;
    }
    else if(tok->argv[0] == "sha256")
    {
        tok->cmd = CMD_SHA;
    }
    else if(tok->argv[0] == "quit")
    {
        tok->cmd = CMD_QUIT;
    }
    else
        return -1;
    
    return 0;
}


int open(token* tok)
{
    struct sockaddr_in serv_addr;
    
    if(connected)
    {
        cout << "has socket" << endl;
        return -1;
    }

    if(tok->argc != 3)
    {
        cout << "pra error" << endl;
        return -1;
    }


    socketfd = socket(AF_INET,SOCK_STREAM,0);
    if(socketfd < 0)
    {
        cout << "socket error" << endl;
        return -1;
    }


    bzero(&serv_addr,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(tok->argv[2].c_str()));
    inet_pton(AF_INET,tok->argv[1].c_str(),&serv_addr.sin_addr);


    if(connect(socketfd,(struct sockaddr*)&serv_addr,sizeof(serv_addr)) < 0)
    {
        cout << "connect error" << endl;
        return -1;
    }
    connected = 1;


    FTPPACK request;
    strcpy((char*)request.m_protocol,"\xc1\xa1\x10");
    request.m_protocol[3] = (byte)'f';
    request.m_protocol[4] = (byte)'t';
    request.m_protocol[5] = (byte)'p';
    request.m_type = (byte)0xA1;
    request.m_status = (byte)0;
    request.m_length = htonl(12);


    memset(buf_send,0,sizeof(buf_send));
    memset(buf_read,0,sizeof(buf_read));

    memcpy(buf_send, &request, sizeof(FTPPACK));
    if(send(socketfd, buf_send, sizeof(FTPPACK), 0) < 0)
    {
        cout << "send error" << endl;
        return -1;
    }

    if(recv(socketfd, buf_read, sizeof(FTPPACK), 0) < 0)
    {
        cout << "read error" << endl;
        return -1;
    }

    FTPPACK* recv_pack = (FTPPACK*) buf_read;
    if(!check((char*)recv_pack->m_protocol))
    {
        cout << "protocol error" << endl;
        return -1;
    }

    if(recv_pack->m_status != (byte)1)
    {
        return -1;
    }

    cout << "successfully connected!" << endl;
    return 0;

}

int closefd()
{
    if(connected)
    {
        close(socketfd);
        connected = 0;
        return 0;
    }
    else
        return 1;
}

int quit()
{
    if(connected == 0)
    {
        cout << "over" << endl;
        return 1;
    }

    FTPPACK request;
    strcpy((char*)request.m_protocol,"\xc1\xa1\x10");
    request.m_protocol[3] = (byte)'f';
    request.m_protocol[4] = (byte)'t';
    request.m_protocol[5] = (byte)'p';
    request.m_type = (byte)0xAB;
    request.m_status = (byte)0;
    request.m_length = htonl(12);

    memset(buf_send,0,sizeof(buf_send));
    memset(buf_read,0,sizeof(buf_read));

    memcpy(buf_send, &request, sizeof(FTPPACK));

    send(socketfd, buf_send, sizeof(FTPPACK), 0);

    recv(socketfd, buf_read, sizeof(FTPPACK), 0);
    FTPPACK* recv_pack = (FTPPACK*) buf_read;
    if(!check((char*)recv_pack->m_protocol))
    {
        cout << "protocol error" << endl;
        return -1;
    }
    if(recv_pack->m_type == (byte)0xAC)
    {
        cout << "server byebye" << endl;
        return closefd();
    }
    return 0;
}

int ls(token* tok)
{
    if(connected == 0)
    {
        cout << "You haven't opened a connection yet.\n";
        return -1;
    }
    else if(tok->argc > 1)
    {
        cout << "too many param\n";
        return -1;
    }

    FTPPACK request;
    strcpy((char*)request.m_protocol,"\xc1\xa1\x10");
    request.m_protocol[3] = (byte)'f';
    request.m_protocol[4] = (byte)'t';
    request.m_protocol[5] = (byte)'p';
    request.m_type = (byte)0xA3;
    request.m_status = (byte)0;
    request.m_length = htonl(12);

    
    memset(buf_send,0,sizeof(buf_send));
    memset(buf_read,0,sizeof(buf_read));
    memcpy(buf_send, &request, sizeof(FTPPACK));

    if(send(socketfd, buf_send, sizeof(FTPPACK), 0) < 0)
    {
        cout << "send error" << endl;
        return -1;
    }

    if(recv(socketfd, buf_read, 2060, 0) < 0)
    {
        cout << "recv error" << endl;
        return -1;
    }


    FTPPACK* recv_pack = (FTPPACK*) buf_read;
    if(!check((char*)recv_pack->m_protocol))
    {
        cout << "protocol error" << endl;
        return -1;
    }
    if(recv_pack->m_type != (byte)0xA4)
    {
        cout << "error" << endl;
        return -1;
    }

    cout<<"Get data successfully!"<<endl;

    int ls_len = ntohl(recv_pack->m_length) - sizeof(FTPPACK) - 1;
    char* ls = buf_read + sizeof(FTPPACK);

    cout<<"------------ls below------------"<<endl;
    for(int i = 0; i < ls_len; i++)
    {
        cout << ls[i];
    }
    cout<<"------------lss above------------"<<endl;
    return 0;
}

int put(token* tok)
{
    if(connected == 0)
    {
        cout << "You haven't opened a connection yet." << endl;
        return -1;
    }
    

    if(tok->argc != 2)
    {
        cout << "param error" << endl;
        return -1;
    }

    const char* filename = tok->argv[1].c_str();
    cout <<"File name : " << filename << endl;
    FILE* fp = fopen(filename, "r");
    if(fp == NULL)
    {
        cout << "open file error" << endl;
        return -1;
    }


    FTPPACK request;
    strcpy((char*)request.m_protocol,"\xc1\xa1\x10");
    request.m_protocol[3] = (byte)'f';
    request.m_protocol[4] = (byte)'t';
    request.m_protocol[5] = (byte)'p';
    request.m_type = (byte)0xA7;
    request.m_status = (byte)0;
    request.m_length = htonl(12 + strlen(filename) + 1);

    memset(buf_send,0,sizeof(buf_send));
    memset(buf_read,0,sizeof(buf_read));

    memcpy(buf_send, &request, sizeof(FTPPACK));
    memcpy(buf_send + sizeof(FTPPACK), filename, strlen(filename) + 1);

    if(send(socketfd, buf_send, sizeof(FTPPACK) + strlen(filename) + 1, 0) < 0)
    {
        cout << "send error" << endl;
        return -1;
    }

    if(recv(socketfd, buf_read, sizeof(FTPPACK), 0) < 0)
    {
        cout << "recv error" << endl;
        return -1;
    }

    FTPPACK* recv_pack = (FTPPACK*) buf_read;
    if(!check((char*)recv_pack->m_protocol))
    {
        cout << "protocol error\n" << endl;
        return -1;
    }
    if(recv_pack->m_type != (byte)0xA8)
    {
        cout << "type error" << endl;
        return -1;
    }

    memset(buf_send,0,sizeof(buf_send));
    memset(buf_file, 0 ,sizeof(buf_file));
    int cnt = 0;
    int file_len = 0;
    int first = 0;
    while( (cnt = fread(buf_file, 1, MAXFILELEN, fp)) > 0 )
    {
        file_len += cnt;
    }
    cout << "FileLen : " << file_len << endl;
    request.m_type = (byte)0xFF;
    request.m_length = htonl(12 + file_len);
    fclose(fp);

    FILE* fp1 = fopen(filename, "r");

    memcpy(buf_send,&request, sizeof(FTPPACK));
    send(socketfd, buf_send, 12, 0);

    cnt = 0;
    while( (cnt = fread(buf_file, 1, MAXFILELEN, fp1)) > 0 )
    {
        memcpy(buf_send , buf_file, cnt);
        send(socketfd, buf_send, cnt, 0);
    }
    fclose(fp1);

    cout << "Transform finished!" << endl;
    return 0;
}

int get(token* tok)
{
    if(connected == 0)
    {
        cout << "You haven't opened a connection yet." << endl;
        return -1;
    }

    if(tok->argc != 2)
    {
        cout << "param error" << endl;
        return -1;
    }

    const char* filename = tok->argv[1].c_str();

    FTPPACK request;
    strcpy((char*)request.m_protocol,"\xc1\xa1\x10");
    request.m_protocol[3] = (byte)'f';
    request.m_protocol[4] = (byte)'t';
    request.m_protocol[5] = (byte)'p';
    request.m_type = (byte)0xA5;
    request.m_status = (byte)0;
    request.m_length = htonl(12 + strlen(filename) + 1);

    memset(buf_send,0,sizeof(buf_send));
    memset(buf_read,0,sizeof(buf_read));
    memcpy(buf_send, &request, sizeof(FTPPACK));
    memcpy(buf_send + sizeof(FTPPACK), filename, strlen(filename) + 1);

    if(send(socketfd, buf_send, sizeof(FTPPACK) + strlen(filename) + 1, 0) < 0)
    {
        cout << "send error" << endl;
        return -1;
    }
    if(recv(socketfd, buf_read, sizeof(FTPPACK), 0) < 0)
    {
        cout << "recv error" << endl;
        return -1;
    }

    FTPPACK* recv_pack = (FTPPACK*) buf_read;
    if(!check((char*)recv_pack->m_protocol))
    {
        cout << "protocol error" << endl;
        return -1;
    }
    if(recv_pack->m_type != (byte)0xA6)
    {
        cout << "type error" << endl;
        return -1;
    }
    if(recv_pack->m_status == (byte)0)
    {
        cout << "no file" << endl;
        return -1;
    }

    memset(buf_file, 0 ,sizeof(buf_file));
    FILE* fp = fopen(filename, "wb");
    cout << "File name : " << filename << endl;

    int first = 0;
    int bread ;
    int cnt = 0;
    int file_len = 0;
    while(1)
    {
        bread = recv(socketfd, buf_file, MAXFILELEN, 0);
        cnt += bread;
        if(cnt == 0)
            continue;
        
        first ++;
        if(first == 1)//读取报头
        {
            recv_pack = (FTPPACK*)buf_file;
            if(recv_pack->m_type == (byte)0xFF)
            {
                file_len = ntohl(recv_pack->m_length) - 12;
                cout << "FileLen : " << file_len << endl;
            }
            else
                cout << "file error" << endl;
            fwrite(buf_file + sizeof(FTPPACK), 1, bread - 12, fp);
            
        }
        else//文件内容
        {
            fwrite(buf_file, 1, bread, fp);
        }
        if(cnt == file_len + sizeof(FTPPACK))
            break;
    }
    fclose(fp);
    cout << "Transform finished!" << endl;
    return 0;
}

int sha256(token* tok)
{
    if(connected == 0)
    {
        cout << "You haven't opened a connection yet." << endl;
        return -1;
    }

    if(tok->argc != 2)
    {
        cout << "param error" << endl;
        return -1;
    }

    const char* filename = tok->argv[1].c_str();

    FTPPACK request;
    strcpy((char*)request.m_protocol,"\xc1\xa1\x10");
    request.m_protocol[3] = (byte)'f';
    request.m_protocol[4] = (byte)'t';
    request.m_protocol[5] = (byte)'p';
    request.m_type = (byte)0xA9;
    request.m_status = (byte)0;
    request.m_length = htonl(12 + strlen(filename) + 1);

    memset(buf_send,0,sizeof(buf_send));
    memset(buf_read,0,sizeof(buf_read));
    memcpy(buf_send, &request, sizeof(FTPPACK));
    memcpy(buf_send + sizeof(FTPPACK), filename, strlen(filename) + 1);

    if(send(socketfd, buf_send, sizeof(FTPPACK) + strlen(filename) + 1, 0) < 0)
    {
        cout << "send error" << endl;
        return -1;
    }
    if(recv(socketfd, buf_read, sizeof(FTPPACK), 0) < 0)
    {
        cout << "recv error" << endl;
        return -1;
    }

    FTPPACK* recv_pack = (FTPPACK*) buf_read;
    if(!check((char*)recv_pack->m_protocol))
    {
        cout << "protocol error" << endl;
        return -1;
    }
    if(recv_pack->m_type != (byte)0xAA)
    {
        cout << "type error" << endl;
        return -1;
    }
    if(recv_pack->m_status == (byte)0)
    {
        cout << "no file" << endl;
        return -1;
    }

    memset(buf_file, 0 ,sizeof(buf_file));
    

    int first = 0;
    int cnt = 0;
    int sha_len = 0;
    while(1)
    {
        int bread = recv(socketfd, buf_file, MAXFILELEN, 0);
        cnt += bread;
        if(cnt == 0)
            continue;
    
        first ++;
        if(first == 1)//读取报头
        {
            recv_pack = (FTPPACK*)buf_file;
            if(recv_pack->m_type == (byte)0xFF)
            {
                sha_len = ntohl(recv_pack->m_length) - 12;
            }
            else
                cout << "type error" << endl;
            fwrite(buf_file + sizeof(FTPPACK), 1, bread - 12, stdout);
        }
        else//sha
        {
            fwrite(buf_file, 1, bread, stdout);
        }
        if(cnt == sha_len + sizeof(FTPPACK))
            break;
    }
    return 0;
}

int check(char* pro)
{
    if((pro[0]=='\xc1'&&pro[1]=='\xa1'&&pro[2]=='\x10'&&pro[3]=='f'&&pro[4]=='t'&&pro[5]=='p'))
        return 1;
    return 0;
}

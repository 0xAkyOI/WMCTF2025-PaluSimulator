// g++ -O3 -static-libstdc++ -static-libgcc -s pwn.cpp -o pwn
#include <iostream>
#include <limits>
#include <stdio.h>
#include <seccomp.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/unistd.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <bits/stdc++.h>
#include <algorithm>

using namespace std;

#define ULL unsigned long long
#define LL long long

void label(){
    cout<<"\033[1;32m██████╗  █████╗ ██╗     ██╗   ██╗███████╗██╗███╗   ███╗██╗   ██╗██╗      █████╗ ████████╗ ██████╗ ██████╗ \n";
    cout<<"██╔══██╗██╔══██╗██║     ██║   ██║██╔════╝██║████╗ ████║██║   ██║██║     ██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗\n";
    cout<<"██████╔╝███████║██║     ██║   ██║███████╗██║██╔████╔██║██║   ██║██║     ███████║   ██║   ██║   ██║██████╔╝\n";
    cout<<"██╔═══╝ ██╔══██║██║     ██║   ██║╚════██║██║██║╚██╔╝██║██║   ██║██║     ██╔══██║   ██║   ██║   ██║██╔══██╗\n";
    cout<<"██║     ██║  ██║███████╗╚██████╔╝███████║██║██║ ╚═╝ ██║╚██████╔╝███████╗██║  ██║   ██║   ╚██████╔╝██║  ██║\n";
    cout<<"╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝╚═╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝\n";
}

void sandbox(){
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl");
        return ;
    }
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),

        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_execve, 0, 1),  
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),          
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_execveat, 0, 1), 
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL), 

        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        perror("prctl");
        return ;
    }
}

void init(){
    setbuf(stdin,0);
    setbuf(stdout,0);
    setbuf(stderr,0);
    label();
    sandbox();
}

bool hacked=false;
LL min(LL a,LL b){
    return a<b?a:b;
}
LL max(LL a,LL b){
    return a>b?a:b;
}

void fail(){
    _exit(0);
}

LL ctf=100;
double stu_rank=5.0;
// 00000000 00000000
#define VAL_MASK 0xf0
#define OP_CTF 0x1
#define OP_STUDY 0x2
#define OP_BAILAN 0x4
#define OP_HACK 0x8


// 00000000 00000|0|0|0|   ->  ||FREEDBUF|ALLOCATEDBUF|
#define SIZE_MASK 0xfffffffffffffff8
#define ALLOCATEDBUF 0x1
#define FREEDBUF 0x2

LL op;

class Obj{
public:
    ULL hackablesize;
    ULL flags;
    ULL * buf;
    

    Obj(){
    }
    ~Obj(){
        if((flags&ALLOCATEDBUF)!=0 && (flags&FREEDBUF)==0){
            std::fill((char*)buf,(char*)buf+(flags&SIZE_MASK),0);
            flags|=FREEDBUF;
            delete buf;
        }
        else buf=NULL;
    }
    void initsize(LL &n){
        if (n==1){
            flags=8;
            return ;
        }
        buf=(ULL*)new char[n*8];
        hackablesize=((hackablesize/8+1)<(ULL)n)?hackablesize/8:(ULL)n;
        flags = n*8;
        flags |= ALLOCATEDBUF;
        flags &= ~FREEDBUF;
    }
    void initbuf(istream &stream){
        if(flags&ALLOCATEDBUF){
            stream.read((char*)buf,flags&SIZE_MASK);
        }
        else{
            stream.read((char*)&buf,8);
        }
    }
    void run(){
        for(LL i=0;i<(flags&SIZE_MASK)/8;i++){
            
            if(flags&ALLOCATEDBUF)op=buf[i];
            else op=(LL)buf;
            
            for(LL j=0;j<8;j++){
                char x=((char*)&op)[j];
                LL off=((x&VAL_MASK)/0x10);
                if(x&OP_CTF){
                    ctf+=off;
                    stu_rank-=((double)(off))/10;
                }
                else if(x&OP_STUDY){
                    ctf-=off;
                    stu_rank+=((double)(off))/10;
                    stu_rank=min(5.0,stu_rank);
                }
                else if(x&OP_BAILAN){
                    ctf-=off;
                    stu_rank-=((double)(off))/10;
                }
                else if(x&OP_HACK){
                    cout<<"You realized that you must do something..."<<endl;
                    if(hacked==false){

                        ULL readnum=read(0,buf,hackablesize);
                        if(readnum>0x100)goto ERR;
                        ctf+=off+1;
                        stu_rank-=((double)(off))/10;
                        hacked=true;
                    }
                    else {
                        ERR:
                        cout<<"You HACK action was found by Others...You was expelled..."<<endl;
                        fail();
                    }
                }
                else{
                    ctf-=off;
                    stu_rank-=((double)(off))/10;
                }
            }
        }
    }
    void showbuf(ostream &stream){
        if(flags&FREEDBUF){
            cerr<<"DAMNIT!!!"<<endl;
            return;
        }
        if(flags&ALLOCATEDBUF){
            stream.write((char*)buf,(flags&SIZE_MASK)&0xff);
        }
        else {
            stream.write((char*)&buf,8);
        }
    }
};
LL findex;
void add(){
    Obj chunk;
    LL chunk_size;
    
    cout<<"["<<"Day"<<findex<<"]"<<"How many affairs : ";

    while (!(cin >> chunk_size)) {
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        cout<<endl<<"Invalid input...Try again"<<endl;
        cout<<"["<<"Day"<<findex<<"]"<<"How many affairs : ";
    }
    if (chunk_size>0x2f8/8){
        cout<<"TOOBIG !"<<endl;
        return ;
    }
    try{
        chunk.initsize(chunk_size);
        cout<<"TodoList : ";
        chunk.initbuf(cin);
        chunk.run();
    }catch(const exception& e){
        cerr<<e.what()<<endl;
    }
    cout<<"Your TodoList: ";
    
    chunk.showbuf(cout);
    cout<<endl;
    return;
}

LL _system(const char* x){
    cout<<"[101mERROR : Unreachable Target - "<<x<<endl;
    return 0;
}

int main(){
    init();
    cout<<"Mission : Survive the examination WEEK and CTF and finally find the hidden flag"<<endl;
    for(findex=0;findex<69;findex++){
        add();
    }
    cout<<"Game OVER! Result : "<<endl;
    if(stu_rank>4.5 && ctf>95){
        cout<<"You Win, and I believe that you are a g00d PWNer!"<<endl;
        cout<<"\\o/\\o/\\o/\\o/\\o/\\o/ Now It's time to fulfill your deserved \"expectation\" \\o/\\o/\\o/\\o/\\o/\\o/";
        return _system("/bin/sh");
    }
    else {
        cout<<"Unfortunately you won the bottom rank of the class's moral score."<<endl;
        cout<<"However those thing happen everywhere in reality.You're not alone."<<endl;
        cout<<"Try again. Maybe you can hack your other's computer and Change the ranking to the first in the class♿♿♿"<<endl;
    }
    return 0;
}

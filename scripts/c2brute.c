// C2 タイトル鍵 総当たり。判定: .sb1ユニットを復号すると offset 196,388,580,772,964,1156 が TS同期0x47。
// usage: c2brute <dumpfile> [step]
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static uint8_t S[256];
static uint8_t basis[64][64];
static uint64_t contrib[8][256][8];   // 鍵スケジュール高速化: pos,val -> 64byte寄与

// ROUND_OPS: 0=XOR,1=ADD,2=SUB
static const int OPS[16][3]={
 {0,2,1},{1,1,0},{1,0,1},{0,1,1},{2,0,1},{2,2,0},{2,1,0},{1,2,0},
 {2,1,1},{1,1,1},{1,2,1},{2,1,2},{1,1,2},{2,2,1},{1,2,2},{2,2,2}};

// 判定用 ciphertext ブロック。コンパイル時選択: -DPRG=012 など
// デフォルト=PRG011 (NHKニュース7)
#if defined(PRG012)
// PRG012 (鉄腕ダッシュ) unit0, offset n*192, n=1..6
static const uint8_t CT[6][8]={
 {0xb2,0xc6,0x81,0x3d,0x5b,0x36,0x7e,0x7f},
 {0x1f,0xee,0x98,0xb8,0x8e,0x35,0x5b,0xd1},
 {0x54,0x47,0xca,0xbe,0xe5,0x94,0x89,0x40},
 {0x1f,0x94,0xd5,0x16,0xfb,0xc4,0x81,0x30},
 {0xa4,0xa6,0x5b,0xe0,0x6f,0x04,0xf3,0xc2},
 {0x5d,0x14,0xab,0x7f,0xcf,0x00,0xca,0x50}};
#else
// PRG011 (NHKニュース7) unit0, offset n*192, n=1..6
static const uint8_t CT[6][8]={
 {0x7f,0x78,0x2f,0x4a,0x9f,0xed,0x30,0xae},
 {0x2d,0x73,0xf6,0x27,0x05,0x6b,0xa8,0xb3},
 {0x4f,0xa1,0xaa,0xcf,0xb6,0x2a,0xc0,0xa1},
 {0x6a,0xdf,0x06,0x84,0x46,0xe5,0x0c,0x3e},
 {0x88,0x4b,0x7d,0xf2,0x51,0xe2,0xce,0xb4},
 {0xf6,0x21,0x32,0x79,0xec,0x00,0x31,0x30}};
#endif

static inline uint8_t mix(int op,uint8_t w,uint8_t w0){
  if(op==0) return w^w0;
  if(op==1) return (uint8_t)(w+w0);
  return (uint8_t)(w-w0);
}
static inline void Ffun(uint8_t*W,const uint8_t*K,const int*op){
  W[0]^=K[0];W[1]^=K[1];W[2]^=K[2];W[3]^=K[3];
  W[0]=S[W[0]];W[1]=S[W[1]];W[2]=S[W[2]];W[3]=S[W[3]];
  W[0]^=W[1]^W[2]^W[3];
  W[0]=S[W[0]];
  W[1]=mix(op[0],W[1],W[0]);
  W[2]=mix(op[1],W[2],W[0]);
  W[3]=mix(op[2],W[3],W[0]);
}
// 1ブロック復号して out[4] を返す(=sync候補)。rk: 64byte
static inline uint8_t dec_sync(const uint8_t*ct,const uint8_t*rk){
  uint8_t L[4],R[4],oldR[4],Fr[4];
  L[0]=ct[0];L[1]=ct[1];L[2]=ct[2];L[3]=ct[3];
  R[0]=ct[4];R[1]=ct[5];R[2]=ct[6];R[3]=ct[7];
  for(int r=0;r<16;r++){
    oldR[0]=R[0];oldR[1]=R[1];oldR[2]=R[2];oldR[3]=R[3];
    Fr[0]=R[0];Fr[1]=R[1];Fr[2]=R[2];Fr[3]=R[3];
    Ffun(Fr,rk+r*4,OPS[r]);
    R[0]=Fr[0]^L[0];R[1]=Fr[1]^L[1];R[2]=Fr[2]^L[2];R[3]=Fr[3]^L[3];
    L[0]=oldR[0];L[1]=oldR[1];L[2]=oldR[2];L[3]=oldR[3];
  }
  // out = R||L  → out[4] = L[0]
  return L[0];
}
static inline void ksched(const uint8_t*key,uint64_t*rk /*8 uint64*/){
  const uint64_t*c0=contrib[0][key[0]],*c1=contrib[1][key[1]],*c2=contrib[2][key[2]],*c3=contrib[3][key[3]];
  const uint64_t*c4=contrib[4][key[4]],*c5=contrib[5][key[5]],*c6=contrib[6][key[6]],*c7=contrib[7][key[7]];
  for(int i=0;i<8;i++) rk[i]=c0[i]^c1[i]^c2[i]^c3[i]^c4[i]^c5[i]^c6[i]^c7[i];
}

static void load_tables(){
  FILE*f=fopen("doc/_migration_kit/c2_sbox.bin","rb"); if(!f){perror("sbox");exit(1);} fread(S,1,256,f);fclose(f);
  f=fopen("scripts/c2_basis.bin","rb"); if(!f){perror("basis");exit(1);} fread(basis,1,4096,f);fclose(f);
  for(int pos=0;pos<8;pos++)for(int val=0;val<256;val++){
    uint8_t acc[64]; memset(acc,0,64);
    for(int b=0;b<8;b++) if((val>>b)&1){ uint8_t*row=basis[pos*8+b]; for(int j=0;j<64;j++)acc[j]^=row[j]; }
    memcpy(contrib[pos][val],acc,64);
  }
}
int main(int argc,char**argv){
  if(argc<2){fprintf(stderr,"usage: %s dump [step] | -t <16hexkey>\n",argv[0]);return 1;}
  load_tables();
  if(strcmp(argv[1],"-t")==0){           // 自己テスト: 鍵で1ブロック復号(out全体)
    uint8_t key[8]; for(int k=0;k<8;k++)sscanf(argv[2]+k*2,"%2hhx",&key[k]);
    uint64_t rk[8]; ksched(key,rk); const uint8_t*RK=(const uint8_t*)rk;
    for(int n=0;n<6;n++){
      uint8_t L[4],R[4],oldR[4],Fr[4];
      L[0]=CT[n][0];L[1]=CT[n][1];L[2]=CT[n][2];L[3]=CT[n][3];
      R[0]=CT[n][4];R[1]=CT[n][5];R[2]=CT[n][6];R[3]=CT[n][7];
      for(int r=0;r<16;r++){ for(int i=0;i<4;i++)oldR[i]=R[i],Fr[i]=R[i]; Ffun(Fr,RK+r*4,OPS[r]);
        for(int i=0;i<4;i++)R[i]=Fr[i]^L[i]; for(int i=0;i<4;i++)L[i]=oldR[i]; }
      printf("n=%d out=%02x%02x%02x%02x%02x%02x%02x%02x sync[4]=%02x\n",n+1,R[0],R[1],R[2],R[3],L[0],L[1],L[2],L[3],L[0]);
    }
    return 0;
  }
  // mode: 0=8byte通常, 1=7byteゼロパッド(56bit鍵), 2=8byte逆順(big-endian鍵)
  int step=1, mode=0;
  if(argc>=3){ int a=atoi(argv[2]); if(a<0){mode=-a;step=1;}else{step=a;} }
  if(argc>=4){ mode=atoi(argv[3]); }
  // dump読み込み
  FILE*f=fopen(argv[1],"rb"); if(!f){perror("dump");return 1;}
  fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
  uint8_t*D=malloc(sz); fread(D,1,sz,f); fclose(f);
  fprintf(stderr,"dump %s : %ld bytes, step=%d mode=%d\n",argv[1],sz,step,mode);
  long hits=0;
  uint64_t rk[8];
  long lim=(mode==1)?(sz-6):(sz-7);
  for(long i=0;i+7<=sz;i+=step){
    uint8_t key8[8];
    if(mode==2){   // 逆順(big-endian候補)
      if(i+8>sz) break;
      for(int k=0;k<8;k++) key8[k]=D[i+7-k];
    } else if(mode==1){ // 7byteゼロパッド(56bit鍵)
      memcpy(key8,D+i,7); key8[7]=0;
    } else {       // 通常8byte
      if(i+8>sz) break;
      memcpy(key8,D+i,8);
    }
    ksched(key8,rk);
    const uint8_t*RK=(const uint8_t*)rk;
    if(dec_sync(CT[0],RK)!=0x47) continue;
    if(dec_sync(CT[1],RK)!=0x47) continue;
    if(dec_sync(CT[2],RK)!=0x47) continue;
    if(dec_sync(CT[3],RK)!=0x47) continue;
    if(dec_sync(CT[4],RK)!=0x47) continue;
    if(dec_sync(CT[5],RK)!=0x47) continue;
    printf("HIT off=%ld key=",i);
    for(int k=0;k<8;k++) printf("%02x",key8[k]);
    printf(" (raw@%ld:",i);
    int pr=(mode==1)?7:8;
    for(int k=0;k<pr;k++) printf("%02x",D[i+k]);
    printf(")\n"); fflush(stdout); hits++;
  }
  fprintf(stderr,"done. hits=%ld\n",hits);
  return 0;
}

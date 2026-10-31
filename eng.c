/* eng.c -- Profanity seed-index build + reverse-walk find, optimized for CI runners.
 *
 *   priv = mt19937_64(seed)[0..3] (limbs: s3,s2,s1,s0 BE) ; then
 *   limb0 += (round-2) ; limb3 += foundId        (rebryk restorePrivateKey)
 *
 * build  <lo> <hi> <out> <threads>     -> <out> : 16-bucket sorted (key64,seed32) records, 12B each
 * find   <pub65hex> <lo_id> <hi_id> <steps> <dir_or_file> <threads> [chunk] [outjson]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "secp256k1.c"
extern void keccak256(const uint8_t*, size_t, uint8_t*);

static double now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+1e-9*t.tv_nsec; }

/* ---------------- mt19937_64 ---------------- */
#define MTNN 312
#define MTMM 156
#define MTMATRIX 0xB5026F5AA96619E9ULL
#define MTUM 0xFFFFFFFF80000000ULL
#define MTLM 0x7FFFFFFFULL
static void mt_seed(uint64_t st[MTNN],uint64_t seed){ st[0]=seed; for(int i=1;i<MTNN;i++) st[i]=6364136223846793005ULL*(st[i-1]^(st[i-1]>>62))+(uint64_t)i; }
static inline uint64_t mt_next(uint64_t st[MTNN],int*ip){
  static const uint64_t mag[2]={0ULL,MTMATRIX};
  int mti=*ip; uint64_t y; int kk;
  if(mti>=MTNN){
    for(kk=0;kk<MTNN-MTMM;kk++){ y=(st[kk]&MTUM)|(st[kk+1]&MTLM); st[kk]=st[kk+MTMM]^(y>>1)^mag[y&1]; }
    for(;kk<MTNN-1;kk++){ y=(st[kk]&MTUM)|(st[kk+1]&MTLM); st[kk]=st[kk+(MTMM-MTNN)]^(y>>1)^mag[y&1]; }
    y=(st[MTNN-1]&MTUM)|(st[0]&MTLM); st[MTNN-1]=st[MTMM-1]^(y>>1)^mag[y&1]; mti=0;
  }
  y=st[mti++]; *ip=mti;
  y^=(y>>29)&0x5555555555555555ULL; y^=(y<<17)&0x71D67FFFEDA60000ULL; y^=(y<<37)&0xFFF7EEE000000000ULL; y^=y>>43;
  return y;
}
static inline void seed_to_sk(uint64_t seed,unsigned char sk[32]){
  uint64_t st[MTNN]; int ip=MTNN+1; mt_seed(st,seed);
  uint64_t l[4]; for(int q=0;q<4;q++) l[q]=mt_next(st,&ip);   /* l[0]=s0 ... l[3]=s3 */
  for(int q=0;q<4;q++){ uint64_t w=l[3-q]; for(int k=0;k<8;k++) sk[q*8+k]=(unsigned char)(w>>(8*(7-k))); }
}
/* restorePrivateKey: sk_limbs[s0..s3] += round (with carry) then s3 += id */
static void restore_sk(uint64_t seed,uint32_t id,uint32_t round,unsigned char sk[32]){
  uint64_t st[MTNN]; int ip=MTNN+1; mt_seed(st,seed);
  uint64_t s[4]; for(int q=0;q<4;q++) s[q]=mt_next(st,&ip);
  uint64_t c=0;
  s[0]+=round; c = (s[0] < (uint64_t)round);
  s[1]+=c;     c = (s[1]==0 && c);
  s[2]+=c;     c = (s[2]==0 && c);
  s[3]+= c + (uint64_t)id;
  for(int q=0;q<4;q++){ uint64_t w=s[3-q]; for(int k=0;k<8;k++) sk[q*8+k]=(unsigned char)(w>>(8*(7-k))); }
}

/* ---------------- generator windows ---------------- */
static secp256k1_ge *WT[16];
static secp256k1_context *g_ctx=NULL;
static secp256k1_context* getctx(void){ if(!g_ctx) g_ctx=secp256k1_context_create(SECP256K1_CONTEXT_SIGN); return g_ctx; }
static void neg_ge(secp256k1_ge*o,const secp256k1_ge*i){ *o=*i; secp256k1_fe_negate(&o->y,&i->y,1); secp256k1_fe_normalize_var(&o->y); }
static void build_wtab(void){
  secp256k1_gej base; secp256k1_gej_set_ge(&base,&secp256k1_ge_const_g);
  for(int w=15; w>=0; w--){
    WT[w]=malloc(65536*sizeof(secp256k1_ge));
    secp256k1_gej b=base,c=base; secp256k1_ge t; secp256k1_ge_set_gej(&t,&c); WT[w][1]=t;
    for(int v=2; v<65536; v++){ secp256k1_gej_add_var(&c,&c,&b,NULL); secp256k1_ge tt; secp256k1_ge_set_gej(&tt,&c); WT[w][v]=tt; }
    for(int i=0;i<16;i++) secp256k1_gej_double_var(&base,&base,NULL);
  }
}
static inline void keygen_j(const unsigned char sk[32], secp256k1_gej*out){
  secp256k1_gej_set_infinity(out);
  for(int w=0; w<16; w++){ unsigned v=((unsigned)sk[2*w]<<8)|(unsigned)sk[2*w+1]; if(v) secp256k1_gej_add_ge_var(out,out,&WT[w][v],NULL); }
}
static inline uint64_t xkey(const secp256k1_fe*x){
  unsigned char b[32]; secp256k1_fe_get_b32(b,x); uint64_t v=0; for(int i=20;i<28;i++) v=(v<<8)|b[i]; return v;
}
static void pub_from_sk(const unsigned char sk[32],unsigned char unc[65]){
  secp256k1_pubkey pk; size_t ol=65; secp256k1_context*c=getctx();
  if(!secp256k1_ec_pubkey_create(c,&pk,sk)){ unc[0]=0; return; }
  secp256k1_ec_pubkey_serialize(c,unc,&ol,&pk,2);
}
static void addr_of(const unsigned char unc[65],unsigned char a[20]){ unsigned char h[32]; keccak256(unc+1,64,h); memcpy(a,h+12,20); }

/* ---------------- build ---------------- */
static uint64_t g_lo,g_hi; static int g_nth; static const char*g_out;
typedef struct { uint64_t key; uint32_t seed; } rk_t;
#define NBK 16
static int cmp_rk(const void*a,const void*b){ uint64_t x=((const rk_t*)a)->key,y=((const rk_t*)b)->key; return x<y?-1:(x>y?1:0); }
/* each thread writes 16 bucket files */
static void* bw(void*a){
  long th=(long)a; uint64_t span=(g_hi-g_lo)/(uint64_t)g_nth;
  uint64_t lo=g_lo+(uint64_t)th*span, hi=(th==g_nth-1)?g_hi:(lo+span);
  const size_t CAP=1<<16;
  rk_t*buf[NBK]; size_t cnt[NBK]; FILE*fp[NBK]; char fn[512];
  for(int b=0;b<NBK;b++){ buf[b]=malloc(CAP*sizeof(rk_t)); cnt[b]=0;
    snprintf(fn,sizeof fn,"%s.t%02ld.b%02d",g_out,th,b); fp[b]=fopen(fn,"wb");
    if(!fp[b]){ fprintf(stderr,"open %s fail\n",fn); exit(2);} }
  unsigned char sk[32];
  const int BB=512; secp256k1_gej jb[512]; secp256k1_ge ab[512]; uint32_t sdb[512]; int nb=0;
  for(uint64_t s=lo;s<hi;s++){
    seed_to_sk(s,sk); keygen_j(sk,&jb[nb]); sdb[nb]=(uint32_t)s; nb++;
    if(nb==BB){ secp256k1_ge_set_all_gej_var(ab,jb,BB);
      for(int i=0;i<BB;i++){ uint64_t k=xkey(&ab[i].x); int b=(int)(k>>60);
        buf[b][cnt[b]].key=k; buf[b][cnt[b]].seed=sdb[i]; cnt[b]++;
        if(cnt[b]==CAP){ fwrite(buf[b],sizeof(rk_t),cnt[b],fp[b]); cnt[b]=0; } }
      nb=0; }
  }
  if(nb){ secp256k1_ge_set_all_gej_var(ab,jb,nb);
    for(int i=0;i<nb;i++){ uint64_t k=xkey(&ab[i].x); int b=(int)(k>>60);
      buf[b][cnt[b]].key=k; buf[b][cnt[b]].seed=sdb[i]; cnt[b]++;
      if(cnt[b]==CAP){ fwrite(buf[b],sizeof(rk_t),cnt[b],fp[b]); cnt[b]=0; } } }
  for(int b=0;b<NBK;b++){ if(cnt[b]) fwrite(buf[b],sizeof(rk_t),cnt[b],fp[b]); fclose(fp[b]); free(buf[b]); }
  return NULL;
}
static int mode_build(void){
  double t0=now();
  pthread_t th[128]; if(g_nth>128) g_nth=128;
  for(long i=0;i<g_nth;i++) pthread_create(&th[i],NULL,bw,(void*)i);
  for(int i=0;i<g_nth;i++) pthread_join(th[i],NULL);
  double tk=now()-t0;
  /* merge buckets */
  FILE*out=fopen(g_out,"wb"); if(!out){ fprintf(stderr,"cannot create %s\n",g_out); return 2; }
  uint64_t hdr[2]={g_lo,g_hi}; fwrite(hdr,8,2,out);
  long hdrpos=ftell(out); uint64_t offs[NBK+1]; fwrite(offs,8,NBK+1,out);
  uint64_t total=0; char fn[512];
  for(int b=0;b<NBK;b++){
    size_t cap=1<<22,n=0; rk_t*v=malloc(cap*sizeof(rk_t));
    for(long t=0;t<g_nth;t++){ snprintf(fn,sizeof fn,"%s.t%02ld.b%02d",g_out,t,b);
      FILE*f=fopen(fn,"rb"); if(!f) continue; rk_t x;
      while(fread(&x,sizeof x,1,f)==1){ if(n==cap){ cap<<=1; v=realloc(v,cap*sizeof(rk_t)); } v[n++]=x; }
      fclose(f); unlink(fn); }
    qsort(v,n,sizeof(rk_t),cmp_rk);
    offs[b]=total;
    unsigned char*o=malloc(n*12+16); size_t p=0;
    for(size_t i=0;i<n;i++){ uint64_t k=v[i].key; uint32_t s=v[i].seed;
      for(int j=0;j<8;j++) o[p++]=(unsigned char)(k>>(8*j));
      for(int j=0;j<4;j++) o[p++]=(unsigned char)(s>>(8*j)); }
    fwrite(o,1,p,out); total+=n; free(o); free(v);
  }
  offs[NBK]=total;
  fseek(out,hdrpos,SEEK_SET); fwrite(offs,8,NBK+1,out); fclose(out);
  fprintf(stderr,"[build] %llu keys in %.0fs keygen=%.0fs -> %s (%.2f GB)\n",
    (unsigned long long)total, now()-t0, tk, g_out, total*12.0/1073741824.0);
  return 0;
}

/* ---------------- find : reverse walk with batch inversion ---------------- */
#define MAXT 256
typedef struct { unsigned char*map; size_t len; uint64_t lo,hi; uint64_t*offs; } tab_t;
static tab_t g_tab[MAXT]; static int g_ntab=0;
static unsigned char g_addr[20]; static secp256k1_ge gP;
static volatile int g_found=0;
static uint32_t g_lo_id,g_hi_id,g_steps; static int g_nth_f=1;
static double g_t0; static const char*g_hitfile="HITS.json";
static pthread_mutex_t g_wmu=PTHREAD_MUTEX_INITIALIZER;

static inline int lookup(const tab_t*t,uint64_t key,uint32_t*seed){
  int b=(int)(key>>60); uint64_t lo=t->offs[b],hi=t->offs[b+1];
  const unsigned char*base=t->map+16+(NBK+1)*8;
  while(lo<hi){
    uint64_t mid=(lo+hi)>>1; const unsigned char*r=base+mid*12;
    uint64_t k=0; for(int j=7;j>=0;j--) k=(k<<8)|r[j];
    if(k<key) lo=mid+1; else if(k>key) hi=mid;
    else { *seed=(uint32_t)r[8]|((uint32_t)r[9]<<8)|((uint32_t)r[10]<<16)|((uint32_t)r[11]<<24); return 1; }
  }
  return 0;
}
static void report(uint32_t seed,uint32_t id,uint32_t r,uint32_t rlo,uint32_t rhi){
  unsigned char sk[32]; restore_sk(seed,id,r,sk);
  unsigned char unc[65],a[20]; pub_from_sk(sk,unc); if(!unc[0]) return; addr_of(unc,a);
  int ok=memcmp(a,g_addr,20)==0;
  char pv[80]; for(int i=0;i<32;i++) sprintf(pv+2*i,"%02x",sk[i]);
  pthread_mutex_lock(&g_wmu);
  FILE*f=fopen(g_hitfile,"a");
  fprintf(f,"{\"seed\":%u,\"id\":%u,\"r\":%u,\"rlo\":%u,\"rhi\":%u,\"priv\":\"0x%s\",\"addr\":\"0x",seed,id,r,rlo,rhi,pv);
  for(int i=0;i<20;i++) fprintf(f,"%02x",a[i]);
  fprintf(f,"\",\"match\":%d}\n",ok); fclose(f);
  printf("\n*** %s seed=%u id=%u r=%u priv=0x%s match=%d\n",ok?"HIT":"XMATCH",seed,id,r,pv,ok); fflush(stdout);
  if(ok) g_found=1;
  pthread_mutex_unlock(&g_wmu);
}
/* window table for P - id*H  (H = 2^192 G): table of 2^16 multiples of H, 16 windows would be 2^32 entries,
   too big -> instead we compute id*H incrementally per thread: each thread strides by g_nth_f ids. */
static secp256k1_ge H_AFF, HNEG_AFF, G_AFF, GNEG_AFF;
static uint32_t g_id_stride=1;
static uint32_t g_r0=0;

static void* fw(void*a){
  long t=(long)a;
  /* thread t handles ids: lo + t*chunk .. and then += g_nth_f*chunk  (interleaved blocks for load balance) */
  uint64_t block = ((uint64_t)(g_hi_id-g_lo_id) + g_nth_f - 1)/g_nth_f;
  uint64_t idlo = g_lo_id + (uint64_t)t*block, idhi = idlo+block; if(idhi>g_hi_id) idhi=g_hi_id;
  if(idlo>=g_hi_id) return NULL;
  secp256k1_gej cur;
  /* cur = P - idlo*H : compute idlo*H via scalar mul on H (cheap: one ecmult) */
  {
    unsigned char kb[32]; memset(kb,0,32);
    /* scalar = idlo << 192 -> occupies bytes 4..7 */
    uint64_t v=idlo; for(int k=0;k<4;k++) kb[4+k]=(unsigned char)((v>>(8*(3-k)))&0xFF);
    secp256k1_pubkey pk; secp256k1_context*cx=getctx();
    if(v && secp256k1_ec_pubkey_create(cx,&pk,kb)){
      secp256k1_ge ge2; secp256k1_pubkey_load(cx,&ge2,&pk);
      secp256k1_ge ng; neg_ge(&ng,&ge2);
      secp256k1_gej_set_ge(&cur,&gP); secp256k1_gej_add_ge_var(&cur,&cur,&ng,NULL);
    } else secp256k1_gej_set_ge(&cur,&gP);
  }
  if(g_r0){
    unsigned char kb[32]; memset(kb,0,32); uint64_t v=g_r0;
    for(int k=0;k<4;k++) kb[28+k]=(unsigned char)((v>>(8*(3-k)))&0xFF);
    secp256k1_pubkey pk2; secp256k1_context*cx=getctx();
    if(secp256k1_ec_pubkey_create(cx,&pk2,kb)){
      secp256k1_ge ge3; secp256k1_pubkey_load(cx,&ge3,&pk2);
      secp256k1_ge ng2; neg_ge(&ng2,&ge3);
      secp256k1_gej_add_ge_var(&cur,&cur,&ng2,NULL);
    }
  }
  /* batch: generate B walk points, batch-normalize, look them up */
  const int B=64;
  secp256k1_gej jb[64]; secp256k1_ge ab[64];
  for(uint64_t id=idlo; id<idhi && !g_found; id++){
    secp256k1_gej c=cur;
    for(uint32_t r=0;r<g_steps;r+=B){
      int n=0;
      for(int i=0;i<B && (uint32_t)(r+i)<g_steps;i++){ jb[n++]=c; secp256k1_gej_add_ge_var(&c,&c,&GNEG_AFF,NULL); }
      secp256k1_ge_set_all_gej_var(ab,jb,n);
      for(int i=0;i<n;i++){
        uint64_t k=xkey(&ab[i].x); uint32_t sd;
        for(int tb=0;tb<g_ntab;tb++) if(lookup(&g_tab[tb],k,&sd)){ report(sd,(uint32_t)id,g_r0+r+i,g_lo_id,g_hi_id); break; }
        if(g_found) return NULL;
      }
    }
    secp256k1_gej_add_ge_var(&cur,&cur,&HNEG_AFF,NULL);
  }
  return NULL;
}
static int mode_find(char**argv,int argc){
  /* find <pub> <lo_id> <hi_id> <steps> <dir> <nth> [hitfile] */
  unsigned char pub[65];
  { const char*h=argv[2]; if(h[0]=='0'&&(h[1]=='x'||h[1]=='X')) h+=2;
    for(int i=0;i<65;i++){ unsigned v; if(sscanf(h+2*i,"%2x",&v)!=1){ printf("bad pub\n"); return 2;} pub[i]=(unsigned char)v; } }
  g_lo_id=(uint32_t)strtoul(argv[3],0,10); g_hi_id=(uint32_t)strtoul(argv[4],0,10);
  g_steps=(uint32_t)strtoul(argv[5],0,10); const char*dir=argv[6]; g_nth_f=atoi(argv[7]);
  if(argc>8) g_hitfile=argv[8];
  if(argc>9) g_r0=(uint32_t)strtoul(argv[9],0,10);
  secp256k1_context*c=getctx(); secp256k1_pubkey pk; secp256k1_ge Pg;
  if(!secp256k1_ec_pubkey_parse(c,&pk,pub,65)){ printf("pub parse fail\n"); return 2; }
  secp256k1_pubkey_load(c,&Pg,&pk); gP=Pg; addr_of(pub,g_addr);
  build_wtab();
  secp256k1_gej h; secp256k1_gej_set_ge(&h,&secp256k1_ge_const_g);
  for(int i=0;i<192;i++) secp256k1_gej_double_var(&h,&h,NULL);
  secp256k1_ge_set_gej(&H_AFF,&h); neg_ge(&HNEG_AFF,&H_AFF);
  secp256k1_gej_set_ge(&h,&secp256k1_ge_const_g); secp256k1_ge_set_gej(&G_AFF,&h); neg_ge(&GNEG_AFF,&G_AFF);
  /* open tables */
  struct stat st;
  if(stat(dir,&st)==0 && S_ISDIR(st.st_mode)){
    DIR*d=opendir(dir); struct dirent*e;
    while((e=readdir(d)) && g_ntab<MAXT){ size_t L=strlen(e->d_name); if(L<4||strcmp(e->d_name+L-4,".bin")) continue;
      char p[700]; snprintf(p,sizeof p,"%s/%s",dir,e->d_name);
      int fd=open(p,O_RDONLY); if(fd<0) continue; struct stat s2; if(fstat(fd,&s2)){ close(fd); continue; }
      unsigned char*m=mmap(NULL,s2.st_size,PROT_READ,MAP_SHARED,fd,0); if(m==MAP_FAILED){ close(fd); continue; }
      uint64_t*lohi=(uint64_t*)m; g_tab[g_ntab].map=m; g_tab[g_ntab].len=s2.st_size;
      g_tab[g_ntab].lo=lohi[0]; g_tab[g_ntab].hi=lohi[1]; g_tab[g_ntab].offs=(uint64_t*)(m+16);
      g_ntab++; close(fd); }
    closedir(d);
  } else {
    int fd=open(dir,O_RDONLY); if(fd<0){ printf("no table\n"); return 2; }
    struct stat s2; fstat(fd,&s2);
    unsigned char*m=mmap(NULL,s2.st_size,PROT_READ,MAP_SHARED,fd,0);
    uint64_t*lohi=(uint64_t*)m; g_tab[0].map=m; g_tab[0].len=s2.st_size; g_tab[0].lo=lohi[0]; g_tab[0].hi=lohi[1];
    g_tab[0].offs=(uint64_t*)(m+16); g_ntab=1; close(fd);
  }
  if(!g_ntab){ printf("no chunk tables in %s\n",dir); return 2; }
  uint64_t keys=0; for(int i=0;i<g_ntab;i++) keys+=(g_tab[i].len-16-(NBK+1)*8)/12;
  printf("find: %d chunks %llu keys target=0x",g_ntab,(unsigned long long)keys);
  for(int i=0;i<20;i++) printf("%02x",g_addr[i]);
  printf(" ids=[%u,%u) steps=%u r0=%u nth=%d\n",g_lo_id,g_hi_id,g_steps,g_r0,g_nth_f); fflush(stdout);
  g_t0=now();
  pthread_t th[256]; for(long i=0;i<g_nth_f;i++) pthread_create(&th[i],NULL,fw,(void*)i);
  for(int i=0;i<g_nth_f;i++) pthread_join(th[i],NULL);
  printf("find done in %.0fs found=%d\n",now()-g_t0,g_found);
  return g_found?0:1;
}
static int mode_addr(const char*h){
  unsigned char pub[65];
  if(h[0]=='0'&&(h[1]=='x'||h[1]=='X')) h+=2;
  if(strlen(h)<130){ printf("short pub\n"); return 2; }
  for(int i=0;i<65;i++){ unsigned v; if(sscanf(h+2*i,"%2x",&v)!=1){ printf("bad pub\n"); return 2;} pub[i]=(unsigned char)v; }
  unsigned char a[20]; addr_of(pub,a);
  printf("0x"); for(int i=0;i<20;i++) printf("%02x",a[i]); printf("\n"); return 0;
}
int main(int ac,char**av){
  if(ac<2){ printf("usage: eng build <lo> <hi> <out> <nth> | find <pub> <lo> <hi> <steps> <dir> <nth> [hitfile] [r0] | addr <pub>\n"); return 2; }
  if(!strcmp(av[1],"addr")){ if(ac<3) return 2; return mode_addr(av[2]); }
  if(!strcmp(av[1],"build")){ if(ac<6) return 2;
    g_lo=strtoull(av[2],0,10); g_hi=strtoull(av[3],0,10); g_out=av[4]; g_nth=atoi(av[5]); build_wtab(); return mode_build(); }
  if(!strcmp(av[1],"find")){ if(ac<7) return 2; return mode_find(av,ac); }
  return 2;
}

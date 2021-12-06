#include <stdio.h>
#include <atomic>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>

#include <stddef.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/mman.h>

#if defined(__linux__)
  #include <cassert>
  #include <sys/syscall.h>
  #include <sys/wait.h>
  #include <sys/personality.h>
  #include <dlfcn.h>
  #define __STDC_FORMAT_MACROS
#elif defined(__APPLE__)
  #include <pthread.h>
  #include <mach/mach.h>
  #include <mach-o/dyld_images.h>
  //#include <mach/task_info.h>
  #include <dlfcn.h>
#endif


// TODO: current version only works on Mac OSX, can be adapted to Linux, need more investigation for Windows

int debug = 0;

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

typedef struct library_list {
  const char *name;
  uint64_t addr_start, addr_end;
} library_list_t;

#define MAX_LIB_COUNT 1024
static library_list_t liblist[MAX_LIB_COUNT];
static u32            liblist_cnt;

//
//
// C++  part

#include <iostream>
#include <fstream>
#include <algorithm>

/*
 * https://github.com/open-source-parsers/jsoncpp
 * The json c++ lib works fucking well under C++ 98
 */
#include "json/json.h"

#include <set>
#include <map>
#include <vector>
#include <cerrno>
#include <string>
#include <mutex>

static size_t my_safeCopy(void *dst, const void *src, size_t size);

std::string workdir("./");
//std::string workdir("/Users/kvmmac/Downloads/0xlib_harness/0xlib_harness/workdir/dylib-hook/");
//std::string workdir("/root/zhangcen/workspace/osfuzzlib/0xlib_harness/workdir/dylib-hook/");

//// TODO: here needs to be improved
//static std::string NameDemangling(std::string s)
//{
//    // here only provides part of obj-c logic
//    if (s.find("_") == 0)
//        return s.replace(0,1,"");
//    else
//        return s;
//}

struct ArgInfo {
	std::string funcName;
	bool is_in;
	std::string argTag;
	const void *argAddr;
	uint32_t argSize;

	ArgInfo(std::string _func, bool _is_in, std::string _tag, const void *_addr, uint32_t _size) 
	: funcName(_func), is_in(_is_in), argTag(_tag), argAddr(_addr), argSize(_size) {}
};

struct FuncArgs {
	// (func name, in/out, arg tag, arg address, arg size)
	std::map<std::string, ArgInfo> infos;
    std::map<std::string, uint64_t> vals;

    FuncArgs() {infos.clear(); vals.clear();}

	void addInfo(const char *_func, bool _is_in, const char *_tag, const void *_addr, uint32_t _size) {
		std::string *func = new std::string(_func);
		std::string *tag = new std::string(_tag);
		infos.insert(std::pair<std::string, ArgInfo>(*tag, ArgInfo(*func, _is_in, *tag, _addr, _size)));
	}
};

struct JsonArg {
    std::string tag;
    std::string tkey;
};

struct JsonFunc {
    // parsed
    std::string name;
    std::string tspell;
    std::string ctspell;
    std::map<std::string, JsonArg> in;
    std::map<std::string, JsonArg> out;
    std::vector<int> arg_sizes;

    // calculated
    std::map<std::string, std::vector<int> > arg2slots;

    void debug() {
        std::cerr << name << " ," <<  tspell << " ,";

        std::cerr << "argsizes: (";
        for (std::vector<int>::iterator it = arg_sizes.begin(); it != arg_sizes.end(); it++)
            std::cerr << (int)*it << " ";
        std::cerr << ") ,";

        for (std::map<std::string, std::vector<int> >::iterator it = arg2slots.begin(); it != arg2slots.end(); it++) {
            std::cerr << it->first << ": [";
            for (std::vector<int>::iterator jt = it->second.begin(); jt != it->second.end(); jt++)
                std::cerr << (int)*jt << " ";
            std::cerr << "] ";
        }
        std::cerr << std::endl;
    }
};

struct Pointee {
    uint32_t offset;
    std::string tkey;
};

struct JsonType {
    long size;
    std::vector<Pointee> pointees;
};

struct funcInfo;

std::vector<funcInfo*> funcs;

// init input json
std::map<std::string, JsonFunc> fmap;
std::map<std::string, JsonType> tmap;


struct threadInfo {
    uint32_t lvl;
    std::map< std::pair<const char *, int>, funcInfo *> pairMap;

    threadInfo() : lvl(0) {}
};

enum ArgDumpType {
    ArgDumpDummy,
    ArgDumpSucc,
    ArgDumpFail,
};

struct ArgDumpNode {
    ArgDumpType ty;
    std::vector<uint8_t> cnt;
    // in bits
    uint32_t len;

    ArgDumpNode() : ty(ArgDumpDummy), len(0) { }

    std::string ty_to_str() {
        switch(ty) {
            case ArgDumpSucc:
                return "succ";
            case ArgDumpFail:
                return "fail";
            default:
                assert(false && "invalid ArgDumpType");
        }
    }

    void out_as_csv(std::ofstream &of) {
        char tmp[10];
        of << ty_to_str() << ",";
        for (std::vector<uint8_t>::iterator it = cnt.begin(); it != cnt.end(); it++) {
            sprintf(tmp, "%02X", (uint8_t)(*it));
            of << tmp;
        }
        of << "," << len;
    }

    Json::Value out_as_json() {
        Json::Value arg(Json::objectValue);

        Json::Value _cnt(Json::arrayValue);
        char tmp[10];
        for (std::vector<uint8_t>::iterator it = cnt.begin(); it != cnt.end(); it++) {
            sprintf(tmp, "%02X", (uint8_t)(*it));
            _cnt.append(Json::Value(tmp));
        }

        arg["type"] = Json::Value(ty_to_str());
        arg["cnt"] = _cnt;
        return arg;
    }
};

struct MemDumpMap {
    std::map<uint64_t, uint8_t > map;

    std::vector<uint8_t> dump_cnt(uint64_t addr, uint32_t size, bool &is_dumped) {
        uint8_t buf[size];
        std::vector<uint8_t> cnt;
        bool dumped = true;

        for (uint64_t i = 0; i < size; i++)
            if (map.find(addr + i) == map.end())
                dumped = false;

        if (!dumped) {
            //cerr << "buf: " << (uint64_t)buf << " addr: " << (uint64_t) addr << " size: " << size << endl;
            //printf("buf: %p, addr:%p\n", (void *)buf, (void *)addr);
            // TODO: maybe add pointer check result for whether it is a valid pointer?
            //       what's the usage scenario besides the null pointer?
            //PIN_SafeCopy((void *)buf, (void *)(0xabcdef00), size);
            my_safeCopy((void *)buf, (const void *)addr, (size_t)size);
            for (uint64_t i = 0; i < size; i++) {
                map[addr + i] = buf[i];
                cnt.push_back(buf[i]);
            }
        }

        is_dumped = dumped;
        return cnt;
    }

    uint64_t get_pointer(std::vector<uint8_t> cnt, int off) {
        uint64_t addr = 0;
        int i = 0, len = sizeof(void *);

        assert(off + len <= cnt.size() && "pointer over the cnt's boundary");
        //printf("get_pointer cnt size %lu, off %d, len %d\n", cnt.size(), off, len);

        std::vector<uint8_t>::iterator it = cnt.begin();
        it += off;
        for (; i < len; it++, i++) {
            addr = addr | (((uint64_t)(*it)) << (i * 8));
            //printf("i: %d len: %d byte: %02x addr: %p\n", i, len, *it, (void *)addr);
        }
        
        //printf("get_pointer addr %p\n", (void *)addr);
        return addr;
    }

    void dump_a_type(std::string tkey, std::vector<uint8_t> cnt) {
        for (std::vector<Pointee>::iterator it = tmap[tkey].pointees.begin(); 
            it != tmap[tkey].pointees.end();
            it++) {
                bool is_dumped = false;
                std::string sub_tkey = it->tkey;
                uint64_t sub_addr = get_pointer(cnt, it->offset / 8);

                if (tmap[sub_tkey].size <= 0)
                    continue;
                
                // no need to dump the cnt of address zero
                if (sub_addr == 0)
                    continue;

                uint32_t sub_size = tmap[sub_tkey].size / 8;
                //cerr << "subtkey: " << sub_tkey << " subaddr: " << sub_addr << " sub_size: " << sub_size << " is_dumped: " << is_dumped << endl;
                //printf("subtkey: %s, subaddr: %p, sub_size %u\n", sub_tkey.c_str(), (void *)sub_addr, sub_size);
                std::vector<uint8_t> sub_cnt = dump_cnt(sub_addr, sub_size, is_dumped);
                if (!is_dumped)
                    dump_a_type(sub_tkey, sub_cnt);
        }
    }

    void out_as_csv(std::ofstream &of) {
        char tmp[64];
        for (std::map<uint64_t, uint8_t >::iterator it = map.begin();
             it != map.end();
             it++) {
            sprintf(tmp, "0x%" PRIx64 "", (uint64_t)(it->first));
            of << tmp << ",";
            sprintf(tmp, "%02X", (uint8_t)(it->second));
            of << tmp << " ";
        }
    }

    Json::Value out_as_json() {
        Json::Value memdump(Json::objectValue);

        char tmp1[64], tmp2[64];
        for (std::map<uint64_t, uint8_t >::iterator it = map.begin();
             it != map.end();
             it++) {
            sprintf(tmp1, "0x%" PRIx64 "", (uint64_t)(it->first));
            sprintf(tmp2, "%02X", (uint8_t)(it->second));
            memdump[tmp1] = tmp2;
        }

        return memdump;

    }
};

static bool open_trace = false;

struct funcInfo {
    // common map
    static std::map<uint64_t, threadInfo *> tMap;

    static funcInfo * enter(uint64_t _tid, const char *_name, FuncArgs *funcArgs, void *caller0, void *caller1, int _run_idx) {
        uint32_t lvl;
        funcInfo *fi;

        if (tMap.find(_tid) != tMap.end()) {
            lvl = tMap[_tid]->lvl + 1;
        } else {
            tMap[_tid] = new threadInfo();
            lvl = 1;
        }

        tMap[_tid]->lvl = lvl;

        if (lvl == 1) {
            fi = new funcInfo(_tid, lvl, _name, caller0, caller1, _run_idx);
            fi->enter_dump(funcArgs);

            std::pair< const char *, int> key(_name, _run_idx);
            tMap[_tid]->pairMap[key] = fi;

            return fi;
        } else {
            return NULL;
        }
    }

    static void leave(uint64_t _tid, const char *_name, FuncArgs *funcArgs, int _run_idx) {
        uint32_t lvl;
        (tMap[_tid]->lvl)--;

        lvl = tMap[_tid]->lvl;

        if (lvl == 0) {
            std::pair< const char *, int> key(_name, _run_idx);
            funcInfo *fi = tMap[_tid]->pairMap[key];

            fi->set_paired();
            fi->leave_dump(funcArgs);
        }
    }

    // members
    uint64_t tid;
    uint32_t lvl;
    int run_idx;
    const char *name;
    std::string demangled_name;
    bool paired;
    void *caller0;
    void *caller1;

    std::map<std::string, ArgDumpNode > inArgDump;
    MemDumpMap inMemDump;
    std::map<std::string, ArgDumpNode > outArgDump;
    MemDumpMap outMemDump;

    funcInfo (uint64_t _tid, uint32_t _lvl, const char *_name, void *caller0, void *caller1, int _run_idx) 
        : tid(_tid), lvl(_lvl), name(_name), paired(false), caller0(caller0), caller1(caller1), run_idx(_run_idx)
    {
        //demangled_name = NameDemangling(std::string(_name));
        // we use libhook which can directly get demangled name now, not like in PIN
        demangled_name = std::string(_name);
    }

    void set_paired() { paired = true; }

    void enter_dump(FuncArgs *funcArgs) {
        //if (demangled_name == "my_CGFontCreateWithDataProvider") {
        //    open_trace = true;
        //}

        //cerr << "** enter " << name << endl;

        if (fmap.find(demangled_name) != fmap.end()) {
            JsonFunc *func = &fmap[demangled_name];
			for (std::map<std::string, ArgInfo>::iterator it = funcArgs->infos.begin(); it != funcArgs->infos.end(); it++) {
                ArgDumpNode node;
				std::string tag = it->second.argTag;
				std::string tkey = func->in[tag].tkey;
				long size = it->second.argSize;

                assert( ( (tmap[tkey].size < 0) || (size == (tmap[tkey].size / 8)) ) && "func enter arg size must be aligned with bytes boundary");

				unsigned char dst[size];
				my_safeCopy(dst, it->second.argAddr, size);

				std::vector<uint8_t> cnt;
                //printf("cnt:");
				for (int i = 0; i < size; i++) {
					cnt.push_back(dst[i]);
                    //printf(" %02X", dst[i]);
				}
                //printf(", len %lu\n", cnt.size());

                node.ty = ArgDumpSucc;
                node.len = size;
                node.cnt = cnt;
                inArgDump[tag] = node;
                inMemDump.dump_a_type(tkey, cnt);
			}
        }
    }

    void leave_dump(FuncArgs *funcArgs) {
        //if (demangled_name == "my_CGFontCreateWithDataProvider") {
        //    open_trace = false;
        //}

        //cerr << "** leave " << name << endl;

        if (fmap.find(demangled_name) != fmap.end()) {
            JsonFunc *func = &fmap[demangled_name];
			for (std::map<std::string, ArgInfo>::iterator it = funcArgs->infos.begin(); it != funcArgs->infos.end(); it++) {
                ArgDumpNode node;
				std::string tag = it->second.argTag;
				std::string tkey = func->out[tag].tkey;
				long size = it->second.argSize;

                assert( ( (tmap[tkey].size < 0) || (size == (tmap[tkey].size / 8)) ) && "func enter arg size must be aligned with bytes boundary");

				unsigned char dst[size];
				my_safeCopy(dst, it->second.argAddr, size);

				std::vector<uint8_t> cnt;
                //printf("cnt:");
				for (int i = 0; i < size; i++) {
					cnt.push_back(dst[i]);
                    //printf(" %02X", dst[i]);
				}
                //printf(", len %lu\n", cnt.size());

                node.ty = ArgDumpSucc;
                node.len = size;
                node.cnt = cnt;
                outArgDump[tag] = node;
                outMemDump.dump_a_type(tkey, cnt);
			}
        }
    }

    void out_as_csv(std::ofstream& of) {
        of << "INARGS ";
        for (std::map<std::string, ArgDumpNode >::iterator it = inArgDump.begin();
             it != inArgDump.end();
             it++) {
            of << it->first << ",";
            it->second.out_as_csv(of);
            of << " ";
        }
        of << std::endl;

        of << "INMEMDUMP ";
        inMemDump.out_as_csv(of);
        of << std::endl;

        of << "OUTARGS ";
        for (std::map<std::string, ArgDumpNode >::iterator it = outArgDump.begin();
             it != outArgDump.end();
             it++) {
            of << it->first << ",";
            it->second.out_as_csv(of);
            of << " ";
        }
        of << std::endl;

        of << "OUTMEMDUMP ";
        outMemDump.out_as_csv(of);
        of << std::endl;
    }

    Json::Value out_as_json() {
        Json::Value oneFuncTrace(Json::objectValue);

        // basic info
        {
            Json::Value basicInfo(Json::objectValue);
            basicInfo["tid"] = Json::Value((Json::UInt64)tid);
            // WARN: this will be updated with shift value in the outside
            basicInfo["lvl"] = Json::Value((Json::UInt)lvl);
            basicInfo["paired"] = Json::Value((Json::UInt)paired);
            basicInfo["name"] = Json::Value(name);
            basicInfo["demangled_name"] = Json::Value(demangled_name.c_str());
            basicInfo["caller0"] = Json::Value((Json::UInt64)caller0);
            basicInfo["caller1"] = Json::Value((Json::UInt64)caller1);
            oneFuncTrace["basic"] = basicInfo;
        }

        // in args & memdump info
        {
            Json::Value in(Json::objectValue);
            Json::Value inargs(Json::objectValue);
            for (std::map<std::string, ArgDumpNode >::iterator it = inArgDump.begin();
                 it != inArgDump.end();
                 it++) {
                    Json::Value arg = it->second.out_as_json();
                    arg["tag"] = it->first.c_str();
                    inargs[it->first.c_str()] = arg;
                }

            in["args"] = inargs;
            in["memdump"] = inMemDump.out_as_json();
            oneFuncTrace["in"] = in;
        }

        // out args & memdump info
        {
            Json::Value out(Json::objectValue);
            Json::Value outargs(Json::objectValue);
            for (std::map<std::string, ArgDumpNode >::iterator it = outArgDump.begin();
                 it != outArgDump.end();
                 it++) {
                    Json::Value arg = it->second.out_as_json();
                    arg["tag"] = it->first.c_str();
                    outargs[it->first.c_str()] = arg;
                 }

            out["args"] = outargs;
            out["memdump"] = outMemDump.out_as_json();
            oneFuncTrace["out"] = out;
        }

        return oneFuncTrace;
    }

};

std::map<uint64_t, threadInfo *> funcInfo::tMap;
std::mutex mtx;

static void func_enter(const char *funcName, FuncArgs *args, void *caller0, void *caller1, int run_idx)
{
    //printf("begin enter %s\n", funcName);
    mtx.lock();
#if defined(__linux__)
    uint64_t tid = syscall(SYS_gettid);
#elif defined(__APPLE__)
	uint64_t tid;
	pthread_threadid_np(NULL, &tid);
#endif
    funcInfo *fi = funcInfo::enter(tid, funcName, args, caller0, caller1, run_idx);
    if (fi != NULL) {
        // fi != NULL means top level funcInfo
        funcs.push_back(fi);
    }
    mtx.unlock();
    //printf("end enter %s\n", funcName);
}

static void func_leave(const char *funcName, FuncArgs *args, int run_idx)
{
    //printf("begin leave %s\n", funcName);
    mtx.lock();
#if defined(__linux__)
    uint64_t tid = syscall(SYS_gettid);
#elif defined(__APPLE__)
	uint64_t tid;
	pthread_threadid_np(NULL, &tid);
#endif
    funcInfo::leave(tid, funcName, args, run_idx);
    mtx.unlock();
    //printf("end leave %s\n", funcName);
}

static void read_library_information() 
{
#if defined(__linux__)
  FILE *f;
  char    buf[1024], *b, *m, *e, *n;

  if ((f = fopen("/proc/self/maps", "r")) == NULL) {

    fprintf(stderr, "Error: cannot open /proc/self/maps\n");
    exit(-1);

  }

  if (debug) fprintf(stderr, "Library list:\n");
  while (fgets(buf, sizeof(buf), f)) {

    if (strstr(buf, " r-x")) {

      if (liblist_cnt >= MAX_LIB_COUNT) {

        fprintf(
            stderr,
            "Warning: too many libraries to old, maximum count of %d reached\n",
            liblist_cnt);
        return;

      }

      b = buf;
      m = index(buf, '-');
      e = index(buf, ' ');
      if ((n = rindex(buf, '/')) == NULL) n = rindex(buf, ' ');
      if (n &&
          ((*n >= '0' && *n <= '9') || *n == '[' || *n == '{' || *n == '('))
        n = NULL;
      else
        n++;
      if (b && m && e && n && *n) {

        *m++ = 0;
        *e = 0;
        if (n[strlen(n) - 1] == '\n') n[strlen(n) - 1] = 0;

        if (rindex(n, '/') != NULL) {

          n = rindex(n, '/');
          n++;

        }

        liblist[liblist_cnt].name = strdup(n);
        liblist[liblist_cnt].addr_start = strtoull(b, NULL, 16);
        liblist[liblist_cnt].addr_end = strtoull(m, NULL, 16);
        if (debug)
          fprintf(
              stderr, "%s:%" PRIx64 " (%" PRIx64 "-%" PRIx64 ")\n", liblist[liblist_cnt].name,
              liblist[liblist_cnt].addr_end - liblist[liblist_cnt].addr_start,
              liblist[liblist_cnt].addr_start,
              liblist[liblist_cnt].addr_end - 1);
        liblist_cnt++;

      }

    }

  }

  if (debug) fprintf(stderr, "\n");

#elif defined(__FreeBSD__)
  int    mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, getpid()};
  char * buf, *start, *end;
  size_t miblen = sizeof(mib) / sizeof(mib[0]);
  size_t len;

  if (debug) fprintf(stderr, "Library list:\n");
  if (sysctl(mib, miblen, NULL, &len, NULL, 0) == -1) { return; }

  len = len * 4 / 3;

  buf = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
  if (buf == MAP_FAILED) { return; }
  if (sysctl(mib, miblen, buf, &len, NULL, 0) == -1) {

    munmap(buf, len);
    return;

  }

  start = buf;
  end = buf + len;

  while (start < end) {

    struct kinfo_vmentry *region = (struct kinfo_vmentry *)start;
    size_t                size = region->kve_structsize;

    if (size == 0) { break; }

    if ((region->kve_protection & KVME_PROT_READ) &&
        !(region->kve_protection & KVME_PROT_EXEC)) {

      liblist[liblist_cnt].name =
          region->kve_path[0] != '\0' ? strdup(region->kve_path) : 0;
      liblist[liblist_cnt].addr_start = region->kve_start;
      liblist[liblist_cnt].addr_end = region->kve_end;

      if (debug) {

        fprintf(stderr, "%s:%x (%lx-%lx)\n", liblist[liblist_cnt].name,
                liblist[liblist_cnt].addr_end - liblist[liblist_cnt].addr_start,
                liblist[liblist_cnt].addr_start,
                liblist[liblist_cnt].addr_end - 1);

      }

      liblist_cnt++;

    }

    start += size;

  }

#endif
}

static Json::Value dump_library(library_list_t *lib)
{
    //printf("Lib %s 0x%p 0x%p\n", lib->name, (void *)lib->addr_start, (void *)lib->addr_end);
    Json::Value oneLibMap(Json::objectValue);
    oneLibMap["name"] = Json::Value((const char*)(lib->name));
    oneLibMap["addr_start"] = Json::Value((Json::UInt64)lib->addr_start);
    oneLibMap["addr_end"] = Json::Value((Json::UInt64)lib->addr_end);
    return oneLibMap;
}

static Json::Value dump_libraries() 
{
  Json::Value libMapList(Json::arrayValue);

#if defined(__linux__)
  u32 i;
  read_library_information();
  for (i = 0; i < liblist_cnt; i++)
    libMapList.append( dump_library(&liblist[i]) );
#elif defined(__APPLE__) && defined(__LP64__)
  kern_return_t         err;

  // get the list of all loaded modules from dyld
  // the task_info mach API will get the address of the dyld all_image_info
  // struct for the given task from which we can get the names and load
  // addresses of all modules
  task_dyld_info_data_t  task_dyld_info;
  mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
  err = task_info(mach_task_self(), TASK_DYLD_INFO,
                  (task_info_t)&task_dyld_info, &count);

  const struct dyld_all_image_infos *all_image_infos =
      (const struct dyld_all_image_infos *)task_dyld_info.all_image_info_addr;
  const struct dyld_image_info *image_infos = all_image_infos->infoArray;

  for (size_t i = 0; i < all_image_infos->infoArrayCount; i++) {

    const char *      image_name = image_infos[i].imageFilePath;
    mach_vm_address_t image_load_address =
        (mach_vm_address_t)image_infos[i].imageLoadAddress;

    library_list_t lib;
    lib.name = (const char *)image_name;
    lib.addr_start = (u64)image_load_address;
    lib.addr_end = 0;

    libMapList.append( dump_library(&lib) );

  }
#endif

  return libMapList;
}

static void dump_func_trace_as_json(const char *out_file)
{
	std::ofstream FuncTraceOut;
	FuncTraceOut.open(out_file);
    FuncTraceOut.setf(std::ios::showbase);
    //FuncTraceOut << "// dump as func trace as json" << std::endl;

    Json::Value fullDump(Json::objectValue);

    fullDump["libs"] = dump_libraries();

    Json::Value funcTraceList(Json::arrayValue);

    //std::map<uint64_t, uint32_t> shiftMap;
    uint32_t idx = 0;

    for (std::vector<funcInfo*>::iterator vit = funcs.begin(); vit != funcs.end(); ++vit) {
        uint64_t tid = (*vit)->tid;
        uint32_t lvl = (*vit)->lvl;
        bool paired = (*vit)->paired;

        //if (shiftMap.find(tid) == shiftMap.end())
        //    shiftMap[tid] = 0;

        Json::Value oneFuncTrace = (*vit)->out_as_json();
        // fix lvl with the shift
        //oneFuncTrace["basic"]["lvl"] = Json::Value((Json::UInt)(lvl - shiftMap[tid]));
        oneFuncTrace["basic"]["lvl"] = Json::Value((Json::UInt)(lvl));
        oneFuncTrace["basic"]["idx"] = Json::Value((Json::UInt)(idx));

        if (!paired) {
            // TODO: actually we don't need the shiftMap now
            //shiftMap[tid]++;
            // add assert check for not paired function
            std::cerr << (*vit)->demangled_name << " " << (*vit)->run_idx << " not paired" << std::endl;
            abort();
        }

        funcTraceList.append(oneFuncTrace);
        idx++;
    }

    fullDump["traces"] = funcTraceList;

    FuncTraceOut << fullDump;
    FuncTraceOut.close();
}

static int GlobalInit(const char *input_file)
{
    tmap.clear();
    fmap.clear();
    // parse lib info from headers
    std::ifstream inFile;
    inFile.open(input_file);
    if (!inFile) {
        std::cerr << "open \"" << input_file << "\" failed with error code:" << strerror(errno) << std::endl;
        return -1;
    }

    Json::Value jsonInfo;
    inFile >> jsonInfo;

    Json::Value _fmap = jsonInfo["fmap"];
    std::vector<std::string> _fmembers = _fmap.getMemberNames();
    for (std::vector<std::string>::iterator fi = _fmembers.begin(); fi != _fmembers.end(); fi++) {
        JsonFunc func;
        func.name = *fi;

        Json::Value in_info = _fmap[*fi]["in"];
        for (Json::Value::iterator ii = in_info.begin(); ii != in_info.end(); ii++) {
            // in args dump
            JsonArg arg;
            std::string tag = (*ii)["tag"].asString();
            std::string tkey = (*ii)["tkey"].asString();
            arg.tag = tag;
            arg.tkey = tkey;
            func.in[tag] = arg;
            //cerr << "in" << "::" << tag << "::" << tkey << endl;
        }

        Json::Value out_info = _fmap[*fi]["out"];
        for (Json::Value::iterator ii = out_info.begin(); ii != out_info.end(); ii++) {
            // in args dump
            JsonArg arg;
            std::string tag = (*ii)["tag"].asString();
            std::string tkey = (*ii)["tkey"].asString();
            arg.tag = tag;
            arg.tkey = tkey;
            func.out[tag] = arg;
            //cerr << "out" << "::" << tag << "::" << tkey << endl;
        }

        func.tspell = _fmap[*fi]["tspell"].asString();
        func.ctspell = _fmap[*fi]["ctspell"].asString();

        for (Json::Value::iterator ii = _fmap[*fi]["arg_sizes"].begin(); ii != _fmap[*fi]["arg_sizes"].end(); ii++)
            func.arg_sizes.push_back(ii->asInt());
        
        //func.debug();

        fmap[*fi] = func;
    }

    Json::Value _tmap = jsonInfo["tmap"];
    std::vector<std::string> _tmembers = _tmap.getMemberNames();

    for (std::vector<std::string>::iterator ti = _tmembers.begin(); ti != _tmembers.end(); ti++) {
        JsonType ty;
        Json::Value ty_info = _tmap[*ti];
        long size = ty_info["size"].asInt64();

        Json::Value pointees = ty_info["pointees"];
        for (Json::Value::iterator pi = pointees.begin(); pi != pointees.end(); pi++) {
            Pointee pee;
            uint32_t offset = (*pi)["offset"].asUInt64();
            std::string tkey = (*pi)["tkey"].asString();
            pee.offset = offset;
            pee.tkey = tkey;
            //cerr << size << "::" << offset << "::" << tkey << endl;
            ty.pointees.push_back(pee);
        }

        ty.size = size;
        tmap[*ti] = ty;
    }

    inFile.close();

    return 0;
}



//
// Hook part

#define PRINT(...) printf(__VA_ARGS__)
//#define PRINT(...) 

#define FUZZY_FUNCSIZE 0x100    // we use fuzzy function size here

std::atomic_int signal_installed(0);
std::atomic_int has_dumped(0);
volatile sig_atomic_t needs_dump = 0;

typedef struct {
    unsigned char ret_ch;
    bool flag;
} safeRead_stu;

int g_nop_pattern_offset = 0;

static safeRead_stu my_safeRead(const unsigned char *src);

static int get_nop_pattern_offset(unsigned char *ptr, int size) 
{
	int i, j, found = 0;

	unsigned char nop_arr[8] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
	int nop_arr_size = sizeof(nop_arr);

	for (i = 0; i < size; i++) {
		if (ptr[i] == nop_arr[0]) {
			found = 1;
			for (j = 1; j < nop_arr_size; j++) {
				if (ptr[i + j] != nop_arr[j]) {
					found = 0;
					break;
				}
			}
		}
		if (found == 1) {
			break;
		}
	}
	if (found != 1) {
		PRINT("Cannot find nop pattern\n");
		abort();
	}
	else
	{
		//PRINT("nop pattern offset: 0x%x\n", i);
	}

	return i;
}

static void sigsegv_handler(int signo, siginfo_t *si, void *arg)
{
	unsigned char *pc, *my_safeRead_start_addr, *my_safeRead_end_addr;
	ucontext_t *context;

	my_safeRead_start_addr = (unsigned char *)(&my_safeRead);
	my_safeRead_end_addr = my_safeRead_start_addr + FUZZY_FUNCSIZE;

	context = (ucontext_t *)arg;

#if defined(__linux__)
    pc = (unsigned char*)context->uc_mcontext.gregs[REG_RIP];
	if ((my_safeRead_start_addr <= pc) && (my_safeRead_end_addr >= pc)) {
		context->uc_mcontext.gregs[REG_RIP] = (uint64_t)(&my_safeRead) + g_nop_pattern_offset;
	}
#elif defined(__APPLE__)
	pc = (unsigned char *)context->uc_mcontext->__ss.__rip;
	if ((my_safeRead_start_addr <= pc) && (my_safeRead_end_addr >= pc)) {
		context->uc_mcontext->__ss.__rip = (uint64_t)(&my_safeRead) + g_nop_pattern_offset;
	}
#endif
	else
	{
		//PRINT("Program segv occurred\n");  // for debug
		abort();
	}

}

static void sigusr2_handler(int signo, siginfo_t *si, void *arg)
{
    needs_dump = 1;
}

static void signal_installer(void) 
{
	// compute the nop pattern offset
	unsigned char *my_safeRead_start_addr = (unsigned char *)(&my_safeRead);
	g_nop_pattern_offset = get_nop_pattern_offset(my_safeRead_start_addr, FUZZY_FUNCSIZE);

	// TODO: here should consider Windows solution
	struct sigaction segv_act;
	memset(&segv_act, 0, sizeof(struct sigaction));
	segv_act.sa_sigaction = &sigsegv_handler;
	segv_act.sa_flags = SA_SIGINFO;

	if (sigaction(SIGSEGV, &segv_act, NULL)) {
		PRINT("installing SIGSEGV handler error\n");
		abort();
	}

	struct sigaction usr2_act;
	memset(&usr2_act, 0, sizeof(struct sigaction));
	usr2_act.sa_sigaction = &sigusr2_handler;
	usr2_act.sa_flags = SA_SIGINFO;

	if (sigaction(SIGUSR2, &usr2_act, NULL)) {
		PRINT("installing SIGUSR2 handler error\n");
		abort();
	}

	//PRINT("SIGINT handler installed\n");
	//PRINT("SIGSEGV handler installed\n");
}

#pragma GCC push_options
#pragma GCC optimize ("O0")
#pragma clang optimize off

// make compiler compile all code of unsafe_read
static int never_changed = 1;

static safeRead_stu my_safeRead(const unsigned char *src) 
{
	unsigned char ret_ch;
	safeRead_stu ret_stu;

	ret_ch = *src;  // may segment fault here
	if (never_changed) {
		ret_stu.ret_ch = ret_ch;
		ret_stu.flag = true;
		return ret_stu;
	}

	asm(
			"nop\n\t"
			"nop\n\t"
			"nop\n\t"
			"nop\n\t"
			"nop\n\t"
			"nop\n\t"
			"nop\n\t"
			"nop\n\t"
			"nop\n\t"
			"nop\n\t"
			"nop\n\t"
			"nop\n\t"
			"nop\n\t"
			"nop\n\t"
			:
	   );

	//PRINT("src addr: 0x%p\n", (void*)src);
	ret_stu.ret_ch = '\x00';
	ret_stu.flag = false;
	return ret_stu;
}

#pragma GCC pop_options
#pragma clang optimize on

static size_t my_safeCopy(void *dst, const void *src, size_t size) 
{

	safeRead_stu safeRead_ret;
	size_t copied_size = 0;
	unsigned char *d = (unsigned char *)dst;
	const unsigned char *s = (const unsigned char *)src;
	while (size--) {
		safeRead_ret = my_safeRead(s);
		*d = safeRead_ret.ret_ch;
		if (safeRead_ret.flag) {
			copied_size++;
		}
		s++;
		d++;
	}

	return copied_size;
}

static void print_real_path(const char *tag, const char *path)
{
#if defined(__linux__) or defined(__APPLE__)
    char tmp[4096];
    char * ret = realpath(path, tmp);
    if (ret == NULL) {
        fprintf(stderr, "failed to resolve path of %s, errcode: %s\n", tag, strerror(errno));
    } else {
        fprintf(stderr, "realpath of %s is %s\n", tag, ret);
    }
#endif
}

static void init_libhook()
{
	int expected_signal_installed = 0;
	if (atomic_compare_exchange_strong(&signal_installed, &expected_signal_installed, 1)) {
        fprintf(stderr, ">>> BEGIN LIBHOOK INIT <<<\n");
        fprintf(stderr, ">>> pid is %u <<<\n", getpid());
        const char *input = (workdir + "./input.json").c_str();
        print_real_path("INPUT", input);
        if (GlobalInit(input) != 0)
            exit(-1);
	    signal_installer();
        fprintf(stderr, ">>> END LIBHOOK INIT <<<\n");
	}
}

// WARN: we cannot use ctor (cause SIGSEGV), maybe because some global variables are not correctly initilized at this time?
//    __attribute__((constructor))
//static void ctor(void)
//{
//    init_libhook();
//}

static void dump_trace()
{
	int expected_has_dumped = 0;
	if (atomic_compare_exchange_strong(&has_dumped, &expected_has_dumped, 1)) {
        fprintf(stderr, ">>> BEGIN LIBHOOK DUMP <<<\n");
        //const char *output = (workdir + "./output.json").c_str();
        const char *output = "./output.json";
        dump_func_trace_as_json(output);
        print_real_path("OUTPUT", output);
        fprintf(stderr, ">>> WARN: The path might be sandboxed <<<\n");
        fprintf(stderr, ">>> END LIBHOOK DUMP <<<\n");
	}
}

    __attribute__((destructor))
static void dctor(void)
{
	needs_dump = 1;
	dump_trace();
}

//int main()
//{
//    init_libhook();
//    dump_trace();
//    return 0;
//}

/*
 * INTERPOSE related, reference: https://github.com/ccurtsinger/interpose
 */

#if !defined(__INTERPOSE_HH)
#define __INTERPOSE_HH

#include <cstdint>
#include <functional>
#include <type_traits>

/// Function type inspection utility for interpose
template<typename F> struct fn_info {
  using type = F;
  using ret_type = void;
};

/// Specialize the fn_info template for functions with non-void return types
template<typename R, typename... Args> struct fn_info<R(Args...)> {
  using type = R(Args...);
  using ret_type = R;
};

#if defined(__linux__)

/**
 * The linux interposition process uses weak aliases to replace the original function
 * and creates a real::___ function that will perform dynamic symbol resolution on the
 * first call. Be careful when interposing on memory allocation functions in particular;
 * simple operations like printing or symbol resolution could trigger another call to
 * malloc or calloc, which can cause unbounded recursion.
 */
#define INTERPOSE(NAME) \
  namespace real { \
    template<typename... Args> \
    auto NAME(Args... args) -> decltype(::NAME(args...)) { \
      static decltype(::NAME)* real_##NAME; \
      decltype(::NAME)* func = __atomic_load_n(&real_##NAME, __ATOMIC_CONSUME); \
      if(!func) { \
        func = reinterpret_cast<decltype(::NAME)*>( \
          reinterpret_cast<uintptr_t>(dlsym(RTLD_NEXT, #NAME))); \
        __atomic_store_n(&real_##NAME, func, __ATOMIC_RELEASE); \
      } \
      return func(std::forward<Args>(args)...); \
    } \
  } \
  extern "C" decltype(::NAME) NAME __attribute__((weak, alias("__interpose_" #NAME))); \
  extern "C" fn_info<decltype(::NAME)>::ret_type __interpose_##NAME


//  TODO: C++, still has problem
//  decltype(::NAME) NAME;  \
//  fn_info<decltype(::NAME)>::ret_type NAME

//  C
//  extern "C" decltype(::NAME) NAME __attribute__((weak, alias("__interpose_" #NAME))); \
//  extern "C" fn_info<decltype(::NAME)>::ret_type __interpose_##NAME

#elif defined(__APPLE__)

/// Structure exposed to the linker for interposition
struct __osx_interpose {
	const void* new_func;
	const void* orig_func;
};

/**
 * Generate a macOS interpose struct
 * Types from: http://opensource.apple.com/source/dyld/dyld-210.2.3/include/mach-o/dyld-interposing.h
 */
#define OSX_INTERPOSE_STRUCT(NEW, OLD) \
  static const __osx_interpose __my_osx_interpose_##OLD \
    __attribute__((used, section("__DATA, __interpose"))) = \
    { reinterpret_cast<const void*>(reinterpret_cast<uintptr_t>(&(NEW))), \
      reinterpret_cast<const void*>(reinterpret_cast<uintptr_t>(&(OLD))) }

/**
  * The OSX interposition process is much simpler. Just create an OSX interpose struct,
  * include the actual function in the `real` namespace, and declare the beginning of the
  * replacement function with the appropriate return type.
  */
#define INTERPOSE(NAME) \
  namespace real { \
    using ::NAME; \
  } \
  decltype(::NAME) __my_interpose_##NAME; \
  OSX_INTERPOSE_STRUCT(__my_interpose_##NAME, NAME); \
  fn_info<decltype(::NAME)>::ret_type __my_interpose_##NAME

#endif

//  TODO: C style API in mac still needs work
//  extern "C" decltype(::NAME) __my_interpose_##NAME; \
//  OSX_INTERPOSE_STRUCT(__my_interpose_##NAME, NAME); \
//  extern "C" fn_info<decltype(::NAME)>::ret_type __my_interpose_##NAME

#endif

//
//
// auto generation starts from here


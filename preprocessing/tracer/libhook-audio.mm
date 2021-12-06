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
	std::string path(workdir + "./input.json");
        const char *input = path.c_str();
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
	//std::string path(workdir + "./output.json");
        //const char *output = path.c_str();
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



#include <unistd.h>
#include <fcntl.h>
#import <CoreGraphics/CoreGraphics.h>
#import <AudioToolbox/AudioToolbox.h>
#import <VideoToolbox/VideoToolbox.h>
#import <CoreText/CoreText.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <CoreAudio/CoreAudio.h>
#import <CoreAudio/AudioDriverPlugIn.h>
#import <Security/SecureDownload.h>
#import <Security/SecAsn1Coder.h>
#import <Security/SecAsn1Templates.h>
#import <Security/AuthorizationPlugin.h>

// win test 
//#include "foo.h"
// png
//#include "png.h"
// jpeg
//#include "jpeglib.h"
// xml
//#include "libxml/xmlmemory.h"
//#include "libxml/parser.h"
// freetype
//#include "freetype/freetype.h"
// libavcodec
//#include "libavcodec/avcodec.h"
// libmpg123
//#include "mpg123.h"
//#include "out123.h"
//#include "syn123.h"
// libmupdf
//#include "mupdf/fitz.h"
//#include "mupdf/pdf.h"
//#include "mupdf/memento.h"
//#include "mupdf/ucdn.h"



void dump_arg(FuncArgs *funcArgs, const char *funcName, bool isIn, const char *tag, unsigned char *argp, size_t len)
{
    funcArgs->addInfo(funcName, isIn, tag, argp, len);
}

#define DUMP_ARG(funcArgs, func, isin, arg) dump_arg(funcArgs, func, isin, #arg, (unsigned char *)(&arg), sizeof(arg))


/////////////////////

#define FUNC_ID "AUGraphGetInteractionInfo"
#pragma push_macro(FUNC_ID)
#undef AUGraphGetInteractionInfo
// extra usings

INTERPOSE(AUGraphGetInteractionInfo)(AUGraph arg0, uint32_t arg1, AUNodeInteraction * arg2)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphGetInteractionInfo(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentOpenFile"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentOpenFile
// extra usings

INTERPOSE(AudioFileComponentOpenFile)(AudioComponentInstance arg0, const FSRef * arg1, int8_t arg2, int16_t arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentOpenFile(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphGetNodeConnections"
#pragma push_macro(FUNC_ID)
#undef AUGraphGetNodeConnections
// extra usings

INTERPOSE(AUGraphGetNodeConnections)(AUGraph arg0, int32_t arg1, AudioUnitNodeConnection * arg2, UnsignedFixedPtr arg3)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphGetNodeConnections(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphGetNumberOfInteractions"
#pragma push_macro(FUNC_ID)
#undef AUGraphGetNumberOfInteractions
// extra usings

INTERPOSE(AUGraphGetNumberOfInteractions)(AUGraph arg0, UnsignedFixedPtr arg1)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphGetNumberOfInteractions(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicPlayerIsPlaying"
#pragma push_macro(FUNC_ID)
#undef MusicPlayerIsPlaying
// extra usings

INTERPOSE(MusicPlayerIsPlaying)(MusicPlayer arg0, BytePtr arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicPlayerIsPlaying(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioComponentFindNext"
#pragma push_macro(FUNC_ID)
#undef AudioComponentFindNext
// extra usings

INTERPOSE(AudioComponentFindNext)(AudioComponent arg0, const AudioComponentDescription * arg1)
{
    #define RUN_FUNC  AudioComponent ret = real::AudioComponentFindNext(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicTrackMerge"
#pragma push_macro(FUNC_ID)
#undef MusicTrackMerge
// extra usings

INTERPOSE(MusicTrackMerge)(MusicTrack arg0, Float64 arg1, Float64 arg2, MusicTrack arg3, Float64 arg4)
{
    #define RUN_FUNC  int32_t ret = real::MusicTrackMerge(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentOpenWithCallbacks"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentOpenWithCallbacks
// extra usings

INTERPOSE(AudioFileComponentOpenWithCallbacks)(AudioComponentInstance arg0, void * arg1, AudioFile_ReadProc arg2, AudioFile_WriteProc arg3, AudioFile_GetSizeProc arg4, AudioFile_SetSizeProc arg5)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentOpenWithCallbacks(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentInitialize"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentInitialize
// extra usings
using AudioFileComponentInitialize_T_arg2 = const AudioStreamBasicDescription *;
using AudioFileComponentInitialize_T_arg2 = const AudioStreamBasicDescription *;
INTERPOSE(AudioFileComponentInitialize)(AudioComponentInstance arg0, const FSRef * arg1, AudioFileComponentInitialize_T_arg2 arg2, uint32_t arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentInitialize(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentSetProperty"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentSetProperty
// extra usings

INTERPOSE(AudioFileComponentSetProperty)(AudioComponentInstance arg0, uint32_t arg1, uint32_t arg2, const void * arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentSetProperty(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueAllocateBuffer"
#pragma push_macro(FUNC_ID)
#undef AudioQueueAllocateBuffer
// extra usings
using AudioQueueAllocateBuffer_T_arg2 = AudioQueueBuffer **;
using AudioQueueAllocateBuffer_T_arg2 = AudioQueueBuffer **;
INTERPOSE(AudioQueueAllocateBuffer)(AudioQueueRef arg0, uint32_t arg1, AudioQueueAllocateBuffer_T_arg2 arg2)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueAllocateBuffer(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileStreamSetProperty"
#pragma push_macro(FUNC_ID)
#undef AudioFileStreamSetProperty
// extra usings

INTERPOSE(AudioFileStreamSetProperty)(AudioFileStreamID arg0, uint32_t arg1, uint32_t arg2, const void * arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileStreamSetProperty(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphIsOpen"
#pragma push_macro(FUNC_ID)
#undef AUGraphIsOpen
// extra usings

INTERPOSE(AUGraphIsOpen)(AUGraph arg0, BytePtr arg1)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphIsOpen(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueNewInput"
#pragma push_macro(FUNC_ID)
#undef AudioQueueNewInput
// extra usings
using AudioQueueNewInput_T_arg0 = const AudioStreamBasicDescription *;
using AudioQueueNewInput_T_arg6 = OpaqueAudioQueue **;
using AudioQueueNewInput_T_arg0 = const AudioStreamBasicDescription *;
using AudioQueueNewInput_T_arg6 = OpaqueAudioQueue **;
INTERPOSE(AudioQueueNewInput)(AudioQueueNewInput_T_arg0 arg0, AudioQueueInputCallback arg1, void * arg2, CFRunLoopRef arg3, CFStringRef arg4, uint32_t arg5, AudioQueueNewInput_T_arg6 arg6)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueNewInput(arg0, arg1, arg2, arg3, arg4, arg5, arg6)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg6);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg6);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphRemoveRenderNotify"
#pragma push_macro(FUNC_ID)
#undef AUGraphRemoveRenderNotify
// extra usings

INTERPOSE(AUGraphRemoveRenderNotify)(AUGraph arg0, AURenderCallback arg1, void * arg2)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphRemoveRenderNotify(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioServicesGetPropertyInfo"
#pragma push_macro(FUNC_ID)
#undef AudioServicesGetPropertyInfo
// extra usings

INTERPOSE(AudioServicesGetPropertyInfo)(uint32_t arg0, uint32_t arg1, const void * arg2, UnsignedFixedPtr arg3, BytePtr arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioServicesGetPropertyInfo(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicPlayerGetTime"
#pragma push_macro(FUNC_ID)
#undef MusicPlayerGetTime
// extra usings
using MusicPlayerGetTime_T_arg1 = double *;
using MusicPlayerGetTime_T_arg1 = double *;
INTERPOSE(MusicPlayerGetTime)(MusicPlayer arg0, MusicPlayerGetTime_T_arg1 arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicPlayerGetTime(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockGetProperty"
#pragma push_macro(FUNC_ID)
#undef CAClockGetProperty
// extra usings

INTERPOSE(CAClockGetProperty)(CAClockRef arg0, uint32_t arg1, UnsignedFixedPtr arg2, void * arg3)
{
    #define RUN_FUNC  int32_t ret = real::CAClockGetProperty(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioUnitReset"
#pragma push_macro(FUNC_ID)
#undef AudioUnitReset
// extra usings

INTERPOSE(AudioUnitReset)(AudioComponentInstance arg0, uint32_t arg1, uint32_t arg2)
{
    #define RUN_FUNC  int32_t ret = real::AudioUnitReset(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUEventListenerCreateWithDispatchQueue"
#pragma push_macro(FUNC_ID)
#undef AUEventListenerCreateWithDispatchQueue
// extra usings
using AUEventListenerCreateWithDispatchQueue_T_arg0 = AUListenerBase **;
using AUEventListenerCreateWithDispatchQueue_T_arg0 = AUListenerBase **;
INTERPOSE(AUEventListenerCreateWithDispatchQueue)(AUEventListenerCreateWithDispatchQueue_T_arg0 arg0, Float32 arg1, Float32 arg2, dispatch_queue_t arg3, AUEventListenerBlock arg4)
{
    #define RUN_FUNC  int32_t ret = real::AUEventListenerCreateWithDispatchQueue(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUListenerAddParameter"
#pragma push_macro(FUNC_ID)
#undef AUListenerAddParameter
// extra usings

INTERPOSE(AUListenerAddParameter)(AUParameterListenerRef arg0, void * arg1, const AudioUnitParameter * arg2)
{
    #define RUN_FUNC  int32_t ret = real::AUListenerAddParameter(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueNewOutput"
#pragma push_macro(FUNC_ID)
#undef AudioQueueNewOutput
// extra usings
using AudioQueueNewOutput_T_arg0 = const AudioStreamBasicDescription *;
using AudioQueueNewOutput_T_arg6 = OpaqueAudioQueue **;
using AudioQueueNewOutput_T_arg0 = const AudioStreamBasicDescription *;
using AudioQueueNewOutput_T_arg6 = OpaqueAudioQueue **;
INTERPOSE(AudioQueueNewOutput)(AudioQueueNewOutput_T_arg0 arg0, AudioQueueOutputCallback arg1, void * arg2, CFRunLoopRef arg3, CFStringRef arg4, uint32_t arg5, AudioQueueNewOutput_T_arg6 arg6)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueNewOutput(arg0, arg1, arg2, arg3, arg4, arg5, arg6)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg6);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg6);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "ExtAudioFileGetPropertyInfo"
#pragma push_macro(FUNC_ID)
#undef ExtAudioFileGetPropertyInfo
// extra usings

INTERPOSE(ExtAudioFileGetPropertyInfo)(ExtAudioFileRef arg0, uint32_t arg1, UnsignedFixedPtr arg2, BytePtr arg3)
{
    #define RUN_FUNC  int32_t ret = real::ExtAudioFileGetPropertyInfo(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueCreateTimeline"
#pragma push_macro(FUNC_ID)
#undef AudioQueueCreateTimeline
// extra usings
using AudioQueueCreateTimeline_T_arg1 = OpaqueAudioQueueTimeline **;
using AudioQueueCreateTimeline_T_arg1 = OpaqueAudioQueueTimeline **;
INTERPOSE(AudioQueueCreateTimeline)(AudioQueueRef arg0, AudioQueueCreateTimeline_T_arg1 arg1)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueCreateTimeline(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioComponentValidate"
#pragma push_macro(FUNC_ID)
#undef AudioComponentValidate
// extra usings

INTERPOSE(AudioComponentValidate)(AudioComponent arg0, CFDictionaryRef arg1, UnsignedFixedPtr arg2)
{
    #define RUN_FUNC  int32_t ret = real::AudioComponentValidate(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioServicesSetProperty"
#pragma push_macro(FUNC_ID)
#undef AudioServicesSetProperty
// extra usings

INTERPOSE(AudioServicesSetProperty)(uint32_t arg0, uint32_t arg1, const void * arg2, uint32_t arg3, const void * arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioServicesSetProperty(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueSetProperty"
#pragma push_macro(FUNC_ID)
#undef AudioQueueSetProperty
// extra usings

INTERPOSE(AudioQueueSetProperty)(AudioQueueRef arg0, uint32_t arg1, const void * arg2, uint32_t arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueSetProperty(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueSetParameter"
#pragma push_macro(FUNC_ID)
#undef AudioQueueSetParameter
// extra usings

INTERPOSE(AudioQueueSetParameter)(AudioQueueRef arg0, uint32_t arg1, Float32 arg2)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueSetParameter(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "DisposeAUGraph"
#pragma push_macro(FUNC_ID)
#undef DisposeAUGraph
// extra usings

INTERPOSE(DisposeAUGraph)(AUGraph arg0)
{
    #define RUN_FUNC  int32_t ret = real::DisposeAUGraph(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentOpenURL"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentOpenURL
// extra usings

INTERPOSE(AudioFileComponentOpenURL)(AudioComponentInstance arg0, CFURLRef arg1, int8_t arg2, int32_t arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentOpenURL(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "ExtAudioFileTell"
#pragma push_macro(FUNC_ID)
#undef ExtAudioFileTell
// extra usings

INTERPOSE(ExtAudioFileTell)(ExtAudioFileRef arg0, qaddr_t arg1)
{
    #define RUN_FUNC  int32_t ret = real::ExtAudioFileTell(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileReadPackets"
#pragma push_macro(FUNC_ID)
#undef AudioFileReadPackets
// extra usings

INTERPOSE(AudioFileReadPackets)(struct OpaqueAudioFileID * arg0, uint8_t arg1, UnsignedFixedPtr arg2, AudioStreamPacketDescription * arg3, int64_t arg4, UnsignedFixedPtr arg5, void * arg6)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileReadPackets(arg0, arg1, arg2, arg3, arg4, arg5, arg6)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg6);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg6);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "ExtAudioFileRead"
#pragma push_macro(FUNC_ID)
#undef ExtAudioFileRead
// extra usings

INTERPOSE(ExtAudioFileRead)(ExtAudioFileRef arg0, UnsignedFixedPtr arg1, AudioBufferList * arg2)
{
    #define RUN_FUNC  int32_t ret = real::ExtAudioFileRead(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockNew"
#pragma push_macro(FUNC_ID)
#undef CAClockNew
// extra usings
using CAClockNew_T_arg1 = OpaqueCAClock **;
using CAClockNew_T_arg1 = OpaqueCAClock **;
INTERPOSE(CAClockNew)(uint32_t arg0, CAClockNew_T_arg1 arg1)
{
    #define RUN_FUNC  int32_t ret = real::CAClockNew(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphConnectNodeInput"
#pragma push_macro(FUNC_ID)
#undef AUGraphConnectNodeInput
// extra usings

INTERPOSE(AUGraphConnectNodeInput)(AUGraph arg0, int32_t arg1, uint32_t arg2, int32_t arg3, uint32_t arg4)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphConnectNodeInput(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "ExtAudioFileCreateWithURL"
#pragma push_macro(FUNC_ID)
#undef ExtAudioFileCreateWithURL
// extra usings
using ExtAudioFileCreateWithURL_T_arg2 = const AudioStreamBasicDescription *;
using ExtAudioFileCreateWithURL_T_arg5 = OpaqueExtAudioFile **;
using ExtAudioFileCreateWithURL_T_arg2 = const AudioStreamBasicDescription *;
using ExtAudioFileCreateWithURL_T_arg5 = OpaqueExtAudioFile **;
INTERPOSE(ExtAudioFileCreateWithURL)(CFURLRef arg0, uint32_t arg1, ExtAudioFileCreateWithURL_T_arg2 arg2, const AudioChannelLayout * arg3, uint32_t arg4, ExtAudioFileCreateWithURL_T_arg5 arg5)
{
    #define RUN_FUNC  int32_t ret = real::ExtAudioFileCreateWithURL(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFormatGetPropertyInfo"
#pragma push_macro(FUNC_ID)
#undef AudioFormatGetPropertyInfo
// extra usings

INTERPOSE(AudioFormatGetPropertyInfo)(uint32_t arg0, uint32_t arg1, const void * arg2, UnsignedFixedPtr arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioFormatGetPropertyInfo(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceSetSequenceType"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceSetSequenceType
// extra usings

INTERPOSE(MusicSequenceSetSequenceType)(MusicSequence arg0, uint32_t arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceSetSequenceType(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileClose"
#pragma push_macro(FUNC_ID)
#undef AudioFileClose
// extra usings

INTERPOSE(AudioFileClose)(struct OpaqueAudioFileID * arg0)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileClose(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioOutputUnitStart"
#pragma push_macro(FUNC_ID)
#undef AudioOutputUnitStart
// extra usings

INTERPOSE(AudioOutputUnitStart)(AudioComponentInstance arg0)
{
    #define RUN_FUNC  int32_t ret = real::AudioOutputUnitStart(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUEventListenerRemoveEventType"
#pragma push_macro(FUNC_ID)
#undef AUEventListenerRemoveEventType
// extra usings

INTERPOSE(AUEventListenerRemoveEventType)(AUParameterListenerRef arg0, void * arg1, const AudioUnitEvent * arg2)
{
    #define RUN_FUNC  int32_t ret = real::AUEventListenerRemoveEventType(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueProcessingTapGetQueueTime"
#pragma push_macro(FUNC_ID)
#undef AudioQueueProcessingTapGetQueueTime
// extra usings
using AudioQueueProcessingTapGetQueueTime_T_arg1 = double *;
using AudioQueueProcessingTapGetQueueTime_T_arg1 = double *;
INTERPOSE(AudioQueueProcessingTapGetQueueTime)(AudioQueueProcessingTapRef arg0, AudioQueueProcessingTapGetQueueTime_T_arg1 arg1, UnsignedFixedPtr arg2)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueProcessingTapGetQueueTime(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceSetUserCallback"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceSetUserCallback
// extra usings

INTERPOSE(MusicSequenceSetUserCallback)(MusicSequence arg0, MusicSequenceUserCallback arg1, void * arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceSetUserCallback(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUEventListenerAddEventType"
#pragma push_macro(FUNC_ID)
#undef AUEventListenerAddEventType
// extra usings

INTERPOSE(AUEventListenerAddEventType)(AUParameterListenerRef arg0, void * arg1, const AudioUnitEvent * arg2)
{
    #define RUN_FUNC  int32_t ret = real::AUEventListenerAddEventType(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileStreamGetPropertyInfo"
#pragma push_macro(FUNC_ID)
#undef AudioFileStreamGetPropertyInfo
// extra usings

INTERPOSE(AudioFileStreamGetPropertyInfo)(AudioFileStreamID arg0, uint32_t arg1, UnsignedFixedPtr arg2, BytePtr arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileStreamGetPropertyInfo(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "NewMusicPlayer"
#pragma push_macro(FUNC_ID)
#undef NewMusicPlayer
// extra usings
using NewMusicPlayer_T_arg0 = OpaqueMusicPlayer **;
using NewMusicPlayer_T_arg0 = OpaqueMusicPlayer **;
INTERPOSE(NewMusicPlayer)(NewMusicPlayer_T_arg0 arg0)
{
    #define RUN_FUNC  int32_t ret = real::NewMusicPlayer(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileSetProperty"
#pragma push_macro(FUNC_ID)
#undef AudioFileSetProperty
// extra usings

INTERPOSE(AudioFileSetProperty)(struct OpaqueAudioFileID * arg0, uint32_t arg1, uint32_t arg2, const void * arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileSetProperty(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentGetGlobalInfo"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentGetGlobalInfo
// extra usings

INTERPOSE(AudioFileComponentGetGlobalInfo)(AudioComponentInstance arg0, uint32_t arg1, uint32_t arg2, const void * arg3, UnsignedFixedPtr arg4, void * arg5)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentGetGlobalInfo(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphRemoveNode"
#pragma push_macro(FUNC_ID)
#undef AUGraphRemoveNode
// extra usings

INTERPOSE(AUGraphRemoveNode)(AUGraph arg0, int32_t arg1)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphRemoveNode(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentCountUserData"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentCountUserData
// extra usings

INTERPOSE(AudioFileComponentCountUserData)(AudioComponentInstance arg0, uint32_t arg1, UnsignedFixedPtr arg2)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentCountUserData(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicEventIteratorSetEventInfo"
#pragma push_macro(FUNC_ID)
#undef MusicEventIteratorSetEventInfo
// extra usings

INTERPOSE(MusicEventIteratorSetEventInfo)(MusicEventIterator arg0, uint32_t arg1, const void * arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicEventIteratorSetEventInfo(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "ExtAudioFileGetProperty"
#pragma push_macro(FUNC_ID)
#undef ExtAudioFileGetProperty
// extra usings

INTERPOSE(ExtAudioFileGetProperty)(ExtAudioFileRef arg0, uint32_t arg1, UnsignedFixedPtr arg2, void * arg3)
{
    #define RUN_FUNC  int32_t ret = real::ExtAudioFileGetProperty(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentOptimize"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentOptimize
// extra usings

INTERPOSE(AudioFileComponentOptimize)(AudioComponentInstance arg0)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentOptimize(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicTrackSetDestNode"
#pragma push_macro(FUNC_ID)
#undef MusicTrackSetDestNode
// extra usings

INTERPOSE(MusicTrackSetDestNode)(MusicTrack arg0, int32_t arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicTrackSetDestNode(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockAddListener"
#pragma push_macro(FUNC_ID)
#undef CAClockAddListener
// extra usings

INTERPOSE(CAClockAddListener)(CAClockRef arg0, CAClockListenerProc arg1, void * arg2)
{
    #define RUN_FUNC  int32_t ret = real::CAClockAddListener(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioConverterSetProperty"
#pragma push_macro(FUNC_ID)
#undef AudioConverterSetProperty
// extra usings

INTERPOSE(AudioConverterSetProperty)(AudioConverterRef arg0, uint32_t arg1, uint32_t arg2, const void * arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioConverterSetProperty(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioConverterGetPropertyInfo"
#pragma push_macro(FUNC_ID)
#undef AudioConverterGetPropertyInfo
// extra usings

INTERPOSE(AudioConverterGetPropertyInfo)(AudioConverterRef arg0, uint32_t arg1, UnsignedFixedPtr arg2, BytePtr arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioConverterGetPropertyInfo(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphOpen"
#pragma push_macro(FUNC_ID)
#undef AUGraphOpen
// extra usings

INTERPOSE(AUGraphOpen)(AUGraph arg0)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphOpen(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceSetAUGraph"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceSetAUGraph
// extra usings

INTERPOSE(MusicSequenceSetAUGraph)(MusicSequence arg0, AUGraph arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceSetAUGraph(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioUnitUninitialize"
#pragma push_macro(FUNC_ID)
#undef AudioUnitUninitialize
// extra usings

INTERPOSE(AudioUnitUninitialize)(AudioComponentInstance arg0)
{
    #define RUN_FUNC  int32_t ret = real::AudioUnitUninitialize(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueSetOfflineRenderFormat"
#pragma push_macro(FUNC_ID)
#undef AudioQueueSetOfflineRenderFormat
// extra usings
using AudioQueueSetOfflineRenderFormat_T_arg1 = const AudioStreamBasicDescription *;
using AudioQueueSetOfflineRenderFormat_T_arg1 = const AudioStreamBasicDescription *;
INTERPOSE(AudioQueueSetOfflineRenderFormat)(AudioQueueRef arg0, AudioQueueSetOfflineRenderFormat_T_arg1 arg1, const AudioChannelLayout * arg2)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueSetOfflineRenderFormat(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceFileLoadData"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceFileLoadData
// extra usings

INTERPOSE(MusicSequenceFileLoadData)(MusicSequence arg0, CFDataRef arg1, uint32_t arg2, uint32_t arg3)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceFileLoadData(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockGetStartTime"
#pragma push_macro(FUNC_ID)
#undef CAClockGetStartTime
// extra usings

INTERPOSE(CAClockGetStartTime)(CAClockRef arg0, uint32_t arg1, CAClockTime * arg2)
{
    #define RUN_FUNC  int32_t ret = real::CAClockGetStartTime(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicEventIteratorGetEventInfo"
#pragma push_macro(FUNC_ID)
#undef MusicEventIteratorGetEventInfo
// extra usings
using MusicEventIteratorGetEventInfo_T_arg1 = double *;
using MusicEventIteratorGetEventInfo_T_arg1 = double *;
INTERPOSE(MusicEventIteratorGetEventInfo)(MusicEventIterator arg0, MusicEventIteratorGetEventInfo_T_arg1 arg1, UnsignedFixedPtr arg2, const void ** arg3, UnsignedFixedPtr arg4)
{
    #define RUN_FUNC  int32_t ret = real::MusicEventIteratorGetEventInfo(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicPlayerSetPlayRateScalar"
#pragma push_macro(FUNC_ID)
#undef MusicPlayerSetPlayRateScalar
// extra usings

INTERPOSE(MusicPlayerSetPlayRateScalar)(MusicPlayer arg0, Float64 arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicPlayerSetPlayRateScalar(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicEventIteratorDeleteEvent"
#pragma push_macro(FUNC_ID)
#undef MusicEventIteratorDeleteEvent
// extra usings

INTERPOSE(MusicEventIteratorDeleteEvent)(MusicEventIterator arg0)
{
    #define RUN_FUNC  int32_t ret = real::MusicEventIteratorDeleteEvent(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockStop"
#pragma push_macro(FUNC_ID)
#undef CAClockStop
// extra usings

INTERPOSE(CAClockStop)(CAClockRef arg0)
{
    #define RUN_FUNC  int32_t ret = real::CAClockStop(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioHardwareServiceHasProperty"
#pragma push_macro(FUNC_ID)
#undef AudioHardwareServiceHasProperty
// extra usings

INTERPOSE(AudioHardwareServiceHasProperty)(uint32_t arg0, const AudioObjectPropertyAddress * arg1)
{
    #define RUN_FUNC  uint8_t ret = real::AudioHardwareServiceHasProperty(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphNewNodeSubGraph"
#pragma push_macro(FUNC_ID)
#undef AUGraphNewNodeSubGraph
// extra usings

INTERPOSE(AUGraphNewNodeSubGraph)(AUGraph arg0, FixedPtr arg1)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphNewNodeSubGraph(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioCodecGetPropertyInfo"
#pragma push_macro(FUNC_ID)
#undef AudioCodecGetPropertyInfo
// extra usings

INTERPOSE(AudioCodecGetPropertyInfo)(AudioComponentInstance arg0, uint32_t arg1, UnsignedFixedPtr arg2, BytePtr arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioCodecGetPropertyInfo(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicPlayerSetSequence"
#pragma push_macro(FUNC_ID)
#undef MusicPlayerSetSequence
// extra usings

INTERPOSE(MusicPlayerSetSequence)(MusicPlayer arg0, MusicSequence arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicPlayerSetSequence(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioComponentInstanceDispose"
#pragma push_macro(FUNC_ID)
#undef AudioComponentInstanceDispose
// extra usings

INTERPOSE(AudioComponentInstanceDispose)(AudioComponentInstance arg0)
{
    #define RUN_FUNC  int32_t ret = real::AudioComponentInstanceDispose(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUParameterListenerNotify"
#pragma push_macro(FUNC_ID)
#undef AUParameterListenerNotify
// extra usings

INTERPOSE(AUParameterListenerNotify)(AUParameterListenerRef arg0, void * arg1, const AudioUnitParameter * arg2)
{
    #define RUN_FUNC  int32_t ret = real::AUParameterListenerNotify(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioComponentGetDescription"
#pragma push_macro(FUNC_ID)
#undef AudioComponentGetDescription
// extra usings

INTERPOSE(AudioComponentGetDescription)(AudioComponent arg0, AudioComponentDescription * arg1)
{
    #define RUN_FUNC  int32_t ret = real::AudioComponentGetDescription(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioUnitSetParameter"
#pragma push_macro(FUNC_ID)
#undef AudioUnitSetParameter
// extra usings

INTERPOSE(AudioUnitSetParameter)(AudioComponentInstance arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, Float32 arg4, uint32_t arg5)
{
    #define RUN_FUNC  int32_t ret = real::AudioUnitSetParameter(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioCodecUninitialize"
#pragma push_macro(FUNC_ID)
#undef AudioCodecUninitialize
// extra usings

INTERPOSE(AudioCodecUninitialize)(AudioComponentInstance arg0)
{
    #define RUN_FUNC  int32_t ret = real::AudioCodecUninitialize(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioCodecInitialize"
#pragma push_macro(FUNC_ID)
#undef AudioCodecInitialize
// extra usings
using AudioCodecInitialize_T_arg1 = const AudioStreamBasicDescription *;
using AudioCodecInitialize_T_arg2 = const AudioStreamBasicDescription *;
using AudioCodecInitialize_T_arg1 = const AudioStreamBasicDescription *;
using AudioCodecInitialize_T_arg2 = const AudioStreamBasicDescription *;
INTERPOSE(AudioCodecInitialize)(AudioComponentInstance arg0, AudioCodecInitialize_T_arg1 arg1, AudioCodecInitialize_T_arg2 arg2, const void * arg3, uint32_t arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioCodecInitialize(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentGetProperty"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentGetProperty
// extra usings

INTERPOSE(AudioFileComponentGetProperty)(AudioComponentInstance arg0, uint32_t arg1, UnsignedFixedPtr arg2, void * arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentGetProperty(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioConverterFillComplexBuffer"
#pragma push_macro(FUNC_ID)
#undef AudioConverterFillComplexBuffer
// extra usings

INTERPOSE(AudioConverterFillComplexBuffer)(AudioConverterRef arg0, AudioConverterComplexInputDataProc arg1, void * arg2, UnsignedFixedPtr arg3, AudioBufferList * arg4, AudioStreamPacketDescription * arg5)
{
    #define RUN_FUNC  int32_t ret = real::AudioConverterFillComplexBuffer(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "NewMusicEventIterator"
#pragma push_macro(FUNC_ID)
#undef NewMusicEventIterator
// extra usings
using NewMusicEventIterator_T_arg1 = OpaqueMusicEventIterator **;
using NewMusicEventIterator_T_arg1 = OpaqueMusicEventIterator **;
INTERPOSE(NewMusicEventIterator)(MusicTrack arg0, NewMusicEventIterator_T_arg1 arg1)
{
    #define RUN_FUNC  int32_t ret = real::NewMusicEventIterator(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphStart"
#pragma push_macro(FUNC_ID)
#undef AUGraphStart
// extra usings

INTERPOSE(AUGraphStart)(AUGraph arg0)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphStart(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioServicesGetProperty"
#pragma push_macro(FUNC_ID)
#undef AudioServicesGetProperty
// extra usings

INTERPOSE(AudioServicesGetProperty)(uint32_t arg0, uint32_t arg1, const void * arg2, UnsignedFixedPtr arg3, void * arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioServicesGetProperty(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockRemoveListener"
#pragma push_macro(FUNC_ID)
#undef CAClockRemoveListener
// extra usings

INTERPOSE(CAClockRemoveListener)(CAClockRef arg0, CAClockListenerProc arg1, void * arg2)
{
    #define RUN_FUNC  int32_t ret = real::CAClockRemoveListener(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioComponentInstanceNew"
#pragma push_macro(FUNC_ID)
#undef AudioComponentInstanceNew
// extra usings
using AudioComponentInstanceNew_T_arg1 = ComponentInstanceRecord **;
using AudioComponentInstanceNew_T_arg1 = ComponentInstanceRecord **;
INTERPOSE(AudioComponentInstanceNew)(AudioComponent arg0, AudioComponentInstanceNew_T_arg1 arg1)
{
    #define RUN_FUNC  int32_t ret = real::AudioComponentInstanceNew(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioConverterDispose"
#pragma push_macro(FUNC_ID)
#undef AudioConverterDispose
// extra usings

INTERPOSE(AudioConverterDispose)(AudioConverterRef arg0)
{
    #define RUN_FUNC  int32_t ret = real::AudioConverterDispose(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileGetUserDataSize"
#pragma push_macro(FUNC_ID)
#undef AudioFileGetUserDataSize
// extra usings

INTERPOSE(AudioFileGetUserDataSize)(struct OpaqueAudioFileID * arg0, uint32_t arg1, uint32_t arg2, UnsignedFixedPtr arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileGetUserDataSize(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicTrackNewAUPresetEvent"
#pragma push_macro(FUNC_ID)
#undef MusicTrackNewAUPresetEvent
// extra usings

INTERPOSE(MusicTrackNewAUPresetEvent)(MusicTrack arg0, Float64 arg1, const AUPresetEvent * arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicTrackNewAUPresetEvent(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicEventIteratorSetEventTime"
#pragma push_macro(FUNC_ID)
#undef MusicEventIteratorSetEventTime
// extra usings

INTERPOSE(MusicEventIteratorSetEventTime)(MusicEventIterator arg0, Float64 arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicEventIteratorSetEventTime(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueProcessingTapNew"
#pragma push_macro(FUNC_ID)
#undef AudioQueueProcessingTapNew
// extra usings
using AudioQueueProcessingTapNew_T_arg6 = OpaqueAudioQueueProcessingTap **;
using AudioQueueProcessingTapNew_T_arg6 = OpaqueAudioQueueProcessingTap **;
INTERPOSE(AudioQueueProcessingTapNew)(AudioQueueRef arg0, AudioQueueProcessingTapCallback arg1, void * arg2, uint32_t arg3, UnsignedFixedPtr arg4, AudioStreamBasicDescription * arg5, AudioQueueProcessingTapNew_T_arg6 arg6)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueProcessingTapNew(arg0, arg1, arg2, arg3, arg4, arg5, arg6)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg6);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg6);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentWritePackets"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentWritePackets
// extra usings

INTERPOSE(AudioFileComponentWritePackets)(AudioComponentInstance arg0, uint8_t arg1, uint32_t arg2, const AudioStreamPacketDescription * arg3, int64_t arg4, UnsignedFixedPtr arg5, const void * arg6)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentWritePackets(arg0, arg1, arg2, arg3, arg4, arg5, arg6)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg6);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg6);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphGetCPULoad"
#pragma push_macro(FUNC_ID)
#undef AUGraphGetCPULoad
// extra usings
using AUGraphGetCPULoad_T_arg1 = float *;
using AUGraphGetCPULoad_T_arg1 = float *;
INTERPOSE(AUGraphGetCPULoad)(AUGraph arg0, AUGraphGetCPULoad_T_arg1 arg1)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphGetCPULoad(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicTrackSetDestMIDIEndpoint"
#pragma push_macro(FUNC_ID)
#undef MusicTrackSetDestMIDIEndpoint
// extra usings

INTERPOSE(MusicTrackSetDestMIDIEndpoint)(MusicTrack arg0, uint32_t arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicTrackSetDestMIDIEndpoint(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileGetUserData"
#pragma push_macro(FUNC_ID)
#undef AudioFileGetUserData
// extra usings

INTERPOSE(AudioFileGetUserData)(struct OpaqueAudioFileID * arg0, uint32_t arg1, uint32_t arg2, UnsignedFixedPtr arg3, void * arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileGetUserData(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentGetPropertyInfo"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentGetPropertyInfo
// extra usings

INTERPOSE(AudioFileComponentGetPropertyInfo)(AudioComponentInstance arg0, uint32_t arg1, UnsignedFixedPtr arg2, UnsignedFixedPtr arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentGetPropertyInfo(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceNewTrack"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceNewTrack
// extra usings
using MusicSequenceNewTrack_T_arg1 = OpaqueMusicTrack **;
using MusicSequenceNewTrack_T_arg1 = OpaqueMusicTrack **;
INTERPOSE(MusicSequenceNewTrack)(MusicSequence arg0, MusicSequenceNewTrack_T_arg1 arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceNewTrack(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockSetCurrentTime"
#pragma push_macro(FUNC_ID)
#undef CAClockSetCurrentTime
// extra usings

INTERPOSE(CAClockSetCurrentTime)(CAClockRef arg0, const CAClockTime * arg1)
{
    #define RUN_FUNC  int32_t ret = real::CAClockSetCurrentTime(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentReadPacketData"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentReadPacketData
// extra usings

INTERPOSE(AudioFileComponentReadPacketData)(AudioComponentInstance arg0, uint8_t arg1, UnsignedFixedPtr arg2, AudioStreamPacketDescription * arg3, int64_t arg4, UnsignedFixedPtr arg5, void * arg6)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentReadPacketData(arg0, arg1, arg2, arg3, arg4, arg5, arg6)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg6);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg6);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentDataIsThisFormat"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentDataIsThisFormat
// extra usings

INTERPOSE(AudioFileComponentDataIsThisFormat)(AudioComponentInstance arg0, void * arg1, AudioFile_ReadProc arg2, AudioFile_WriteProc arg3, AudioFile_GetSizeProc arg4, AudioFile_SetSizeProc arg5, UnsignedFixedPtr arg6)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentDataIsThisFormat(arg0, arg1, arg2, arg3, arg4, arg5, arg6)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg6);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg6);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphAddRenderNotify"
#pragma push_macro(FUNC_ID)
#undef AUGraphAddRenderNotify
// extra usings

INTERPOSE(AUGraphAddRenderNotify)(AUGraph arg0, AURenderCallback arg1, void * arg2)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphAddRenderNotify(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioCodecGetProperty"
#pragma push_macro(FUNC_ID)
#undef AudioCodecGetProperty
// extra usings

INTERPOSE(AudioCodecGetProperty)(AudioComponentInstance arg0, uint32_t arg1, UnsignedFixedPtr arg2, void * arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioCodecGetProperty(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUEventListenerNotify"
#pragma push_macro(FUNC_ID)
#undef AUEventListenerNotify
// extra usings

INTERPOSE(AUEventListenerNotify)(AUParameterListenerRef arg0, void * arg1, const AudioUnitEvent * arg2)
{
    #define RUN_FUNC  int32_t ret = real::AUEventListenerNotify(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentReadBytes"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentReadBytes
// extra usings

INTERPOSE(AudioFileComponentReadBytes)(AudioComponentInstance arg0, uint8_t arg1, int64_t arg2, UnsignedFixedPtr arg3, void * arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentReadBytes(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileReadBytes"
#pragma push_macro(FUNC_ID)
#undef AudioFileReadBytes
// extra usings

INTERPOSE(AudioFileReadBytes)(struct OpaqueAudioFileID * arg0, uint8_t arg1, int64_t arg2, UnsignedFixedPtr arg3, void * arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileReadBytes(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileCountUserData"
#pragma push_macro(FUNC_ID)
#undef AudioFileCountUserData
// extra usings

INTERPOSE(AudioFileCountUserData)(struct OpaqueAudioFileID * arg0, uint32_t arg1, UnsignedFixedPtr arg2)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileCountUserData(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceBeatsToBarBeatTime"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceBeatsToBarBeatTime
// extra usings

INTERPOSE(MusicSequenceBeatsToBarBeatTime)(MusicSequence arg0, Float64 arg1, uint32_t arg2, CABarBeatTime * arg3)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceBeatsToBarBeatTime(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphGetMaxCPULoad"
#pragma push_macro(FUNC_ID)
#undef AUGraphGetMaxCPULoad
// extra usings
using AUGraphGetMaxCPULoad_T_arg1 = float *;
using AUGraphGetMaxCPULoad_T_arg1 = float *;
INTERPOSE(AUGraphGetMaxCPULoad)(AUGraph arg0, AUGraphGetMaxCPULoad_T_arg1 arg1)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphGetMaxCPULoad(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "ExtAudioFileOpenURL"
#pragma push_macro(FUNC_ID)
#undef ExtAudioFileOpenURL
// extra usings
using ExtAudioFileOpenURL_T_arg1 = OpaqueExtAudioFile **;
using ExtAudioFileOpenURL_T_arg1 = OpaqueExtAudioFile **;
INTERPOSE(ExtAudioFileOpenURL)(CFURLRef arg0, ExtAudioFileOpenURL_T_arg1 arg1)
{
    #define RUN_FUNC  int32_t ret = real::ExtAudioFileOpenURL(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioCodecSetProperty"
#pragma push_macro(FUNC_ID)
#undef AudioCodecSetProperty
// extra usings

INTERPOSE(AudioCodecSetProperty)(AudioComponentInstance arg0, uint32_t arg1, uint32_t arg2, const void * arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioCodecSetProperty(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphGetNodeInfo"
#pragma push_macro(FUNC_ID)
#undef AUGraphGetNodeInfo
// extra usings
using AUGraphGetNodeInfo_T_arg5 = ComponentInstanceRecord **;
using AUGraphGetNodeInfo_T_arg5 = ComponentInstanceRecord **;
INTERPOSE(AUGraphGetNodeInfo)(AUGraph arg0, int32_t arg1, ComponentDescription * arg2, UnsignedFixedPtr arg3, void ** arg4, AUGraphGetNodeInfo_T_arg5 arg5)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphGetNodeInfo(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockSMPTETimeToSeconds"
#pragma push_macro(FUNC_ID)
#undef CAClockSMPTETimeToSeconds
// extra usings
using CAClockSMPTETimeToSeconds_T_arg2 = double *;
using CAClockSMPTETimeToSeconds_T_arg2 = double *;
INTERPOSE(CAClockSMPTETimeToSeconds)(CAClockRef arg0, const SMPTETime * arg1, CAClockSMPTETimeToSeconds_T_arg2 arg2)
{
    #define RUN_FUNC  int32_t ret = real::CAClockSMPTETimeToSeconds(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentCreateURL"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentCreateURL
// extra usings
using AudioFileComponentCreateURL_T_arg2 = const AudioStreamBasicDescription *;
using AudioFileComponentCreateURL_T_arg2 = const AudioStreamBasicDescription *;
INTERPOSE(AudioFileComponentCreateURL)(AudioComponentInstance arg0, CFURLRef arg1, AudioFileComponentCreateURL_T_arg2 arg2, uint32_t arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentCreateURL(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioCodecReset"
#pragma push_macro(FUNC_ID)
#undef AudioCodecReset
// extra usings

INTERPOSE(AudioCodecReset)(AudioComponentInstance arg0)
{
    #define RUN_FUNC  int32_t ret = real::AudioCodecReset(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioHardwareServiceGetPropertyData"
#pragma push_macro(FUNC_ID)
#undef AudioHardwareServiceGetPropertyData
// extra usings

INTERPOSE(AudioHardwareServiceGetPropertyData)(uint32_t arg0, const AudioObjectPropertyAddress * arg1, uint32_t arg2, const void * arg3, UnsignedFixedPtr arg4, void * arg5)
{
    #define RUN_FUNC  int32_t ret = real::AudioHardwareServiceGetPropertyData(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicTrackMoveEvents"
#pragma push_macro(FUNC_ID)
#undef MusicTrackMoveEvents
// extra usings

INTERPOSE(MusicTrackMoveEvents)(MusicTrack arg0, Float64 arg1, Float64 arg2, Float64 arg3)
{
    #define RUN_FUNC  int32_t ret = real::MusicTrackMoveEvents(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphIsInitialized"
#pragma push_macro(FUNC_ID)
#undef AUGraphIsInitialized
// extra usings

INTERPOSE(AUGraphIsInitialized)(AUGraph arg0, BytePtr arg1)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphIsInitialized(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphClose"
#pragma push_macro(FUNC_ID)
#undef AUGraphClose
// extra usings

INTERPOSE(AUGraphClose)(AUGraph arg0)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphClose(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileCreate"
#pragma push_macro(FUNC_ID)
#undef AudioFileCreate
// extra usings
using AudioFileCreate_T_arg3 = const AudioStreamBasicDescription *;
using AudioFileCreate_T_arg3 = const AudioStreamBasicDescription *;
INTERPOSE(AudioFileCreate)(const FSRef * arg0, CFStringRef arg1, uint32_t arg2, AudioFileCreate_T_arg3 arg3, uint32_t arg4, FSRef * arg5, OpaqueAudioFileID ** arg6)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileCreate(arg0, arg1, arg2, arg3, arg4, arg5, arg6)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg6);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg6);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockGetCurrentTime"
#pragma push_macro(FUNC_ID)
#undef CAClockGetCurrentTime
// extra usings

INTERPOSE(CAClockGetCurrentTime)(CAClockRef arg0, uint32_t arg1, CAClockTime * arg2)
{
    #define RUN_FUNC  int32_t ret = real::CAClockGetCurrentTime(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceGetTempoTrack"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceGetTempoTrack
// extra usings
using MusicSequenceGetTempoTrack_T_arg1 = OpaqueMusicTrack **;
using MusicSequenceGetTempoTrack_T_arg1 = OpaqueMusicTrack **;
INTERPOSE(MusicSequenceGetTempoTrack)(MusicSequence arg0, MusicSequenceGetTempoTrack_T_arg1 arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceGetTempoTrack(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicEventIteratorPreviousEvent"
#pragma push_macro(FUNC_ID)
#undef MusicEventIteratorPreviousEvent
// extra usings

INTERPOSE(MusicEventIteratorPreviousEvent)(MusicEventIterator arg0)
{
    #define RUN_FUNC  int32_t ret = real::MusicEventIteratorPreviousEvent(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicTrackNewMetaEvent"
#pragma push_macro(FUNC_ID)
#undef MusicTrackNewMetaEvent
// extra usings

INTERPOSE(MusicTrackNewMetaEvent)(MusicTrack arg0, Float64 arg1, const MIDIMetaEvent * arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicTrackNewMetaEvent(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileGetGlobalInfo"
#pragma push_macro(FUNC_ID)
#undef AudioFileGetGlobalInfo
// extra usings

INTERPOSE(AudioFileGetGlobalInfo)(uint32_t arg0, uint32_t arg1, void * arg2, UnsignedFixedPtr arg3, void * arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileGetGlobalInfo(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueRemovePropertyListener"
#pragma push_macro(FUNC_ID)
#undef AudioQueueRemovePropertyListener
// extra usings

INTERPOSE(AudioQueueRemovePropertyListener)(AudioQueueRef arg0, uint32_t arg1, AudioQueuePropertyListenerProc arg2, void * arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueRemovePropertyListener(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceGetSecondsForBeats"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceGetSecondsForBeats
// extra usings
using MusicSequenceGetSecondsForBeats_T_arg2 = double *;
using MusicSequenceGetSecondsForBeats_T_arg2 = double *;
INTERPOSE(MusicSequenceGetSecondsForBeats)(MusicSequence arg0, Float64 arg1, MusicSequenceGetSecondsForBeats_T_arg2 arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceGetSecondsForBeats(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicEventIteratorHasCurrentEvent"
#pragma push_macro(FUNC_ID)
#undef MusicEventIteratorHasCurrentEvent
// extra usings

INTERPOSE(MusicEventIteratorHasCurrentEvent)(MusicEventIterator arg0, BytePtr arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicEventIteratorHasCurrentEvent(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "NewAUGraph"
#pragma push_macro(FUNC_ID)
#undef NewAUGraph
// extra usings
using NewAUGraph_T_arg0 = OpaqueAUGraph **;
using NewAUGraph_T_arg0 = OpaqueAUGraph **;
INTERPOSE(NewAUGraph)(NewAUGraph_T_arg0 arg0)
{
    #define RUN_FUNC  int32_t ret = real::NewAUGraph(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioHardwareServiceIsPropertySettable"
#pragma push_macro(FUNC_ID)
#undef AudioHardwareServiceIsPropertySettable
// extra usings

INTERPOSE(AudioHardwareServiceIsPropertySettable)(uint32_t arg0, const AudioObjectPropertyAddress * arg1, BytePtr arg2)
{
    #define RUN_FUNC  int32_t ret = real::AudioHardwareServiceIsPropertySettable(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileOpenWithCallbacks"
#pragma push_macro(FUNC_ID)
#undef AudioFileOpenWithCallbacks
// extra usings

INTERPOSE(AudioFileOpenWithCallbacks)(void * arg0, AudioFile_ReadProc arg1, AudioFile_WriteProc arg2, AudioFile_GetSizeProc arg3, AudioFile_SetSizeProc arg4, uint32_t arg5, OpaqueAudioFileID ** arg6)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileOpenWithCallbacks(arg0, arg1, arg2, arg3, arg4, arg5, arg6)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg6);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg6);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceSaveMIDIFile"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceSaveMIDIFile
// extra usings

INTERPOSE(MusicSequenceSaveMIDIFile)(MusicSequence arg0, const FSRef * arg1, CFStringRef arg2, uint16_t arg3, uint32_t arg4)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceSaveMIDIFile(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioUnitExtensionSetComponentList"
#pragma push_macro(FUNC_ID)
#undef AudioUnitExtensionSetComponentList
// extra usings

INTERPOSE(AudioUnitExtensionSetComponentList)(CFStringRef arg0, CFArrayRef arg1)
{
    #define RUN_FUNC  int32_t ret = real::AudioUnitExtensionSetComponentList(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileCreateWithURL"
#pragma push_macro(FUNC_ID)
#undef AudioFileCreateWithURL
// extra usings
using AudioFileCreateWithURL_T_arg2 = const AudioStreamBasicDescription *;
using AudioFileCreateWithURL_T_arg2 = const AudioStreamBasicDescription *;
INTERPOSE(AudioFileCreateWithURL)(CFURLRef arg0, uint32_t arg1, AudioFileCreateWithURL_T_arg2 arg2, uint32_t arg3, OpaqueAudioFileID ** arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileCreateWithURL(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicDevicePrepareInstrument"
#pragma push_macro(FUNC_ID)
#undef MusicDevicePrepareInstrument
// extra usings

INTERPOSE(MusicDevicePrepareInstrument)(AudioComponentInstance arg0, uint32_t arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicDevicePrepareInstrument(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockBeatsToBarBeatTime"
#pragma push_macro(FUNC_ID)
#undef CAClockBeatsToBarBeatTime
// extra usings

INTERPOSE(CAClockBeatsToBarBeatTime)(CAClockRef arg0, Float64 arg1, uint16_t arg2, CABarBeatTime * arg3)
{
    #define RUN_FUNC  int32_t ret = real::CAClockBeatsToBarBeatTime(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueFreeBuffer"
#pragma push_macro(FUNC_ID)
#undef AudioQueueFreeBuffer
// extra usings

INTERPOSE(AudioQueueFreeBuffer)(AudioQueueRef arg0, AudioQueueBufferRef arg1)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueFreeBuffer(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentSetUserData"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentSetUserData
// extra usings

INTERPOSE(AudioFileComponentSetUserData)(AudioComponentInstance arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, const void * arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentSetUserData(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicTrackGetSequence"
#pragma push_macro(FUNC_ID)
#undef MusicTrackGetSequence
// extra usings
using MusicTrackGetSequence_T_arg1 = OpaqueMusicSequence **;
using MusicTrackGetSequence_T_arg1 = OpaqueMusicSequence **;
INTERPOSE(MusicTrackGetSequence)(MusicTrack arg0, MusicTrackGetSequence_T_arg1 arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicTrackGetSequence(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioComponentGetIcon"
#pragma push_macro(FUNC_ID)
#undef AudioComponentGetIcon
// extra usings

INTERPOSE(AudioComponentGetIcon)(AudioComponent arg0)
{
    #define RUN_FUNC  NSImage * ret = real::AudioComponentGetIcon(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFormatGetProperty"
#pragma push_macro(FUNC_ID)
#undef AudioFormatGetProperty
// extra usings

INTERPOSE(AudioFormatGetProperty)(uint32_t arg0, uint32_t arg1, const void * arg2, UnsignedFixedPtr arg3, void * arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioFormatGetProperty(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioHardwareServiceRemovePropertyListener"
#pragma push_macro(FUNC_ID)
#undef AudioHardwareServiceRemovePropertyListener
// extra usings

INTERPOSE(AudioHardwareServiceRemovePropertyListener)(uint32_t arg0, const AudioObjectPropertyAddress * arg1, AudioObjectPropertyListenerProc arg2, void * arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioHardwareServiceRemovePropertyListener(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioConverterConvertBuffer"
#pragma push_macro(FUNC_ID)
#undef AudioConverterConvertBuffer
// extra usings

INTERPOSE(AudioConverterConvertBuffer)(AudioConverterRef arg0, uint32_t arg1, const void * arg2, UnsignedFixedPtr arg3, void * arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioConverterConvertBuffer(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceDisposeTrack"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceDisposeTrack
// extra usings

INTERPOSE(MusicSequenceDisposeTrack)(MusicSequence arg0, MusicTrack arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceDisposeTrack(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentGetUserDataSize"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentGetUserDataSize
// extra usings

INTERPOSE(AudioFileComponentGetUserDataSize)(AudioComponentInstance arg0, uint32_t arg1, uint32_t arg2, UnsignedFixedPtr arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentGetUserDataSize(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioHardwareServiceAddPropertyListener"
#pragma push_macro(FUNC_ID)
#undef AudioHardwareServiceAddPropertyListener
// extra usings

INTERPOSE(AudioHardwareServiceAddPropertyListener)(uint32_t arg0, const AudioObjectPropertyAddress * arg1, AudioObjectPropertyListenerProc arg2, void * arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioHardwareServiceAddPropertyListener(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioComponentCount"
#pragma push_macro(FUNC_ID)
#undef AudioComponentCount
// extra usings

INTERPOSE(AudioComponentCount)(const AudioComponentDescription * arg0)
{
    #define RUN_FUNC  uint32_t ret = real::AudioComponentCount(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioOutputUnitStop"
#pragma push_macro(FUNC_ID)
#undef AudioOutputUnitStop
// extra usings

INTERPOSE(AudioOutputUnitStop)(AudioComponentInstance arg0)
{
    #define RUN_FUNC  int32_t ret = real::AudioOutputUnitStop(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUParameterSet"
#pragma push_macro(FUNC_ID)
#undef AUParameterSet
// extra usings

INTERPOSE(AUParameterSet)(AUParameterListenerRef arg0, void * arg1, const AudioUnitParameter * arg2, Float32 arg3, uint32_t arg4)
{
    #define RUN_FUNC  int32_t ret = real::AUParameterSet(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioConverterNew"
#pragma push_macro(FUNC_ID)
#undef AudioConverterNew
// extra usings
using AudioConverterNew_T_arg0 = const AudioStreamBasicDescription *;
using AudioConverterNew_T_arg1 = const AudioStreamBasicDescription *;
using AudioConverterNew_T_arg2 = OpaqueAudioConverter **;
using AudioConverterNew_T_arg0 = const AudioStreamBasicDescription *;
using AudioConverterNew_T_arg1 = const AudioStreamBasicDescription *;
using AudioConverterNew_T_arg2 = OpaqueAudioConverter **;
INTERPOSE(AudioConverterNew)(AudioConverterNew_T_arg0 arg0, AudioConverterNew_T_arg1 arg1, AudioConverterNew_T_arg2 arg2)
{
    #define RUN_FUNC  int32_t ret = real::AudioConverterNew(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphInitialize"
#pragma push_macro(FUNC_ID)
#undef AUGraphInitialize
// extra usings

INTERPOSE(AUGraphInitialize)(AUGraph arg0)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphInitialize(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "DisposeMusicSequence"
#pragma push_macro(FUNC_ID)
#undef DisposeMusicSequence
// extra usings

INTERPOSE(DisposeMusicSequence)(MusicSequence arg0)
{
    #define RUN_FUNC  int32_t ret = real::DisposeMusicSequence(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockSecondsToSMPTETime"
#pragma push_macro(FUNC_ID)
#undef CAClockSecondsToSMPTETime
// extra usings

INTERPOSE(CAClockSecondsToSMPTETime)(CAClockRef arg0, Float64 arg1, uint16_t arg2, SMPTETime * arg3)
{
    #define RUN_FUNC  int32_t ret = real::CAClockSecondsToSMPTETime(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioUnitProcessMultiple"
#pragma push_macro(FUNC_ID)
#undef AudioUnitProcessMultiple
// extra usings

INTERPOSE(AudioUnitProcessMultiple)(AudioComponentInstance arg0, UnsignedFixedPtr arg1, const AudioTimeStamp * arg2, uint32_t arg3, uint32_t arg4, const AudioBufferList ** arg5, uint32_t arg6, AudioBufferList ** arg7)
{
    #define RUN_FUNC  int32_t ret = real::AudioUnitProcessMultiple(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg6);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg7);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg6);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg7);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioHardwareServiceSetPropertyData"
#pragma push_macro(FUNC_ID)
#undef AudioHardwareServiceSetPropertyData
// extra usings

INTERPOSE(AudioHardwareServiceSetPropertyData)(uint32_t arg0, const AudioObjectPropertyAddress * arg1, uint32_t arg2, const void * arg3, uint32_t arg4, const void * arg5)
{
    #define RUN_FUNC  int32_t ret = real::AudioHardwareServiceSetPropertyData(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioConverterFillBuffer"
#pragma push_macro(FUNC_ID)
#undef AudioConverterFillBuffer
// extra usings

INTERPOSE(AudioConverterFillBuffer)(AudioConverterRef arg0, AudioConverterInputDataProc arg1, void * arg2, UnsignedFixedPtr arg3, void * arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioConverterFillBuffer(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicTrackGetDestMIDIEndpoint"
#pragma push_macro(FUNC_ID)
#undef MusicTrackGetDestMIDIEndpoint
// extra usings

INTERPOSE(MusicTrackGetDestMIDIEndpoint)(MusicTrack arg0, UnsignedFixedPtr arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicTrackGetDestMIDIEndpoint(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioServicesPlayAlertSound"
#pragma push_macro(FUNC_ID)
#undef AudioServicesPlayAlertSound
// extra usings

INTERPOSE(AudioServicesPlayAlertSound)(uint32_t arg0)
{
    #define RUN_FUNC  real::AudioServicesPlayAlertSound(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicTrackNewParameterEvent"
#pragma push_macro(FUNC_ID)
#undef MusicTrackNewParameterEvent
// extra usings

INTERPOSE(MusicTrackNewParameterEvent)(MusicTrack arg0, Float64 arg1, const ParameterEvent * arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicTrackNewParameterEvent(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueuePrime"
#pragma push_macro(FUNC_ID)
#undef AudioQueuePrime
// extra usings

INTERPOSE(AudioQueuePrime)(AudioQueueRef arg0, uint32_t arg1, UnsignedFixedPtr arg2)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueuePrime(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentWriteBytes"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentWriteBytes
// extra usings

INTERPOSE(AudioFileComponentWriteBytes)(AudioComponentInstance arg0, uint8_t arg1, int64_t arg2, UnsignedFixedPtr arg3, const void * arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentWriteBytes(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceFileLoad"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceFileLoad
// extra usings

INTERPOSE(MusicSequenceFileLoad)(MusicSequence arg0, CFURLRef arg1, uint32_t arg2, uint32_t arg3)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceFileLoad(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueEnqueueBuffer"
#pragma push_macro(FUNC_ID)
#undef AudioQueueEnqueueBuffer
// extra usings

INTERPOSE(AudioQueueEnqueueBuffer)(AudioQueueRef arg0, AudioQueueBufferRef arg1, uint32_t arg2, const AudioStreamPacketDescription * arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueEnqueueBuffer(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentRemoveUserData"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentRemoveUserData
// extra usings

INTERPOSE(AudioFileComponentRemoveUserData)(AudioComponentInstance arg0, uint32_t arg1, uint32_t arg2)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentRemoveUserData(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphNewNode"
#pragma push_macro(FUNC_ID)
#undef AUGraphNewNode
// extra usings

INTERPOSE(AUGraphNewNode)(AUGraph arg0, const ComponentDescription * arg1, uint32_t arg2, const void * arg3, FixedPtr arg4)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphNewNode(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockDisarm"
#pragma push_macro(FUNC_ID)
#undef CAClockDisarm
// extra usings

INTERPOSE(CAClockDisarm)(CAClockRef arg0)
{
    #define RUN_FUNC  int32_t ret = real::CAClockDisarm(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "ExtAudioFileSeek"
#pragma push_macro(FUNC_ID)
#undef ExtAudioFileSeek
// extra usings

INTERPOSE(ExtAudioFileSeek)(ExtAudioFileRef arg0, int64_t arg1)
{
    #define RUN_FUNC  int32_t ret = real::ExtAudioFileSeek(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioComponentInstanceCanDo"
#pragma push_macro(FUNC_ID)
#undef AudioComponentInstanceCanDo
// extra usings

INTERPOSE(AudioComponentInstanceCanDo)(AudioComponentInstance arg0, int16_t arg1)
{
    #define RUN_FUNC  uint8_t ret = real::AudioComponentInstanceCanDo(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioUnitAddPropertyListener"
#pragma push_macro(FUNC_ID)
#undef AudioUnitAddPropertyListener
// extra usings

INTERPOSE(AudioUnitAddPropertyListener)(AudioComponentInstance arg0, uint32_t arg1, AudioUnitPropertyListenerProc arg2, void * arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioUnitAddPropertyListener(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "DisposeMusicEventIterator"
#pragma push_macro(FUNC_ID)
#undef DisposeMusicEventIterator
// extra usings

INTERPOSE(DisposeMusicEventIterator)(MusicEventIterator arg0)
{
    #define RUN_FUNC  int32_t ret = real::DisposeMusicEventIterator(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioUnitGetPropertyInfo"
#pragma push_macro(FUNC_ID)
#undef AudioUnitGetPropertyInfo
// extra usings

INTERPOSE(AudioUnitGetPropertyInfo)(AudioComponentInstance arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, UnsignedFixedPtr arg4, BytePtr arg5)
{
    #define RUN_FUNC  int32_t ret = real::AudioUnitGetPropertyInfo(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioCodecAppendInputBufferList"
#pragma push_macro(FUNC_ID)
#undef AudioCodecAppendInputBufferList
// extra usings

INTERPOSE(AudioCodecAppendInputBufferList)(AudioComponentInstance arg0, const AudioBufferList * arg1, UnsignedFixedPtr arg2, const AudioStreamPacketDescription * arg3, UnsignedFixedPtr arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioCodecAppendInputBufferList(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueStart"
#pragma push_macro(FUNC_ID)
#undef AudioQueueStart
// extra usings

INTERPOSE(AudioQueueStart)(AudioQueueRef arg0, const AudioTimeStamp * arg1)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueStart(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "ExtAudioFileSetProperty"
#pragma push_macro(FUNC_ID)
#undef ExtAudioFileSetProperty
// extra usings

INTERPOSE(ExtAudioFileSetProperty)(ExtAudioFileRef arg0, uint32_t arg1, uint32_t arg2, const void * arg3)
{
    #define RUN_FUNC  int32_t ret = real::ExtAudioFileSetProperty(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphClearConnections"
#pragma push_macro(FUNC_ID)
#undef AUGraphClearConnections
// extra usings

INTERPOSE(AUGraphClearConnections)(AUGraph arg0)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphClearConnections(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "ExtAudioFileWrite"
#pragma push_macro(FUNC_ID)
#undef ExtAudioFileWrite
// extra usings

INTERPOSE(ExtAudioFileWrite)(ExtAudioFileRef arg0, uint32_t arg1, const AudioBufferList * arg2)
{
    #define RUN_FUNC  int32_t ret = real::ExtAudioFileWrite(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioUnitAddRenderNotify"
#pragma push_macro(FUNC_ID)
#undef AudioUnitAddRenderNotify
// extra usings

INTERPOSE(AudioUnitAddRenderNotify)(AudioComponentInstance arg0, AURenderCallback arg1, void * arg2)
{
    #define RUN_FUNC  int32_t ret = real::AudioUnitAddRenderNotify(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileGetPropertyInfo"
#pragma push_macro(FUNC_ID)
#undef AudioFileGetPropertyInfo
// extra usings

INTERPOSE(AudioFileGetPropertyInfo)(struct OpaqueAudioFileID * arg0, uint32_t arg1, UnsignedFixedPtr arg2, UnsignedFixedPtr arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileGetPropertyInfo(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioUnitRemoveRenderNotify"
#pragma push_macro(FUNC_ID)
#undef AudioUnitRemoveRenderNotify
// extra usings

INTERPOSE(AudioUnitRemoveRenderNotify)(AudioComponentInstance arg0, AURenderCallback arg1, void * arg2)
{
    #define RUN_FUNC  int32_t ret = real::AudioUnitRemoveRenderNotify(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileGetProperty"
#pragma push_macro(FUNC_ID)
#undef AudioFileGetProperty
// extra usings

INTERPOSE(AudioFileGetProperty)(struct OpaqueAudioFileID * arg0, uint32_t arg1, UnsignedFixedPtr arg2, void * arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileGetProperty(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphGetNodeCount"
#pragma push_macro(FUNC_ID)
#undef AUGraphGetNodeCount
// extra usings

INTERPOSE(AUGraphGetNodeCount)(AUGraph arg0, UnsignedFixedPtr arg1)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphGetNodeCount(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioServicesDisposeSystemSoundID"
#pragma push_macro(FUNC_ID)
#undef AudioServicesDisposeSystemSoundID
// extra usings

INTERPOSE(AudioServicesDisposeSystemSoundID)(uint32_t arg0)
{
    #define RUN_FUNC  int32_t ret = real::AudioServicesDisposeSystemSoundID(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicDeviceStartNote"
#pragma push_macro(FUNC_ID)
#undef MusicDeviceStartNote
// extra usings

INTERPOSE(MusicDeviceStartNote)(AudioComponentInstance arg0, uint32_t arg1, uint32_t arg2, UnsignedFixedPtr arg3, uint32_t arg4, const MusicDeviceNoteParams * arg5)
{
    #define RUN_FUNC  int32_t ret = real::MusicDeviceStartNote(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueAddPropertyListener"
#pragma push_macro(FUNC_ID)
#undef AudioQueueAddPropertyListener
// extra usings

INTERPOSE(AudioQueueAddPropertyListener)(AudioQueueRef arg0, uint32_t arg1, AudioQueuePropertyListenerProc arg2, void * arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueAddPropertyListener(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockSetProperty"
#pragma push_macro(FUNC_ID)
#undef CAClockSetProperty
// extra usings

INTERPOSE(CAClockSetProperty)(CAClockRef arg0, uint32_t arg1, uint32_t arg2, const void * arg3)
{
    #define RUN_FUNC  int32_t ret = real::CAClockSetProperty(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUListenerRemoveParameter"
#pragma push_macro(FUNC_ID)
#undef AUListenerRemoveParameter
// extra usings

INTERPOSE(AUListenerRemoveParameter)(AUParameterListenerRef arg0, void * arg1, const AudioUnitParameter * arg2)
{
    #define RUN_FUNC  int32_t ret = real::AUListenerRemoveParameter(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioComponentCopyName"
#pragma push_macro(FUNC_ID)
#undef AudioComponentCopyName
// extra usings
using AudioComponentCopyName_T_arg1 = const __CFString **;
using AudioComponentCopyName_T_arg1 = const __CFString **;
INTERPOSE(AudioComponentCopyName)(AudioComponent arg0, AudioComponentCopyName_T_arg1 arg1)
{
    #define RUN_FUNC  int32_t ret = real::AudioComponentCopyName(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicTrackSetProperty"
#pragma push_macro(FUNC_ID)
#undef MusicTrackSetProperty
// extra usings

INTERPOSE(MusicTrackSetProperty)(MusicTrack arg0, uint32_t arg1, void * arg2, uint32_t arg3)
{
    #define RUN_FUNC  int32_t ret = real::MusicTrackSetProperty(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "NewMusicTrackFrom"
#pragma push_macro(FUNC_ID)
#undef NewMusicTrackFrom
// extra usings
using NewMusicTrackFrom_T_arg3 = OpaqueMusicTrack **;
using NewMusicTrackFrom_T_arg3 = OpaqueMusicTrack **;
INTERPOSE(NewMusicTrackFrom)(MusicTrack arg0, Float64 arg1, Float64 arg2, NewMusicTrackFrom_T_arg3 arg3)
{
    #define RUN_FUNC  int32_t ret = real::NewMusicTrackFrom(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicPlayerStart"
#pragma push_macro(FUNC_ID)
#undef MusicPlayerStart
// extra usings

INTERPOSE(MusicPlayerStart)(MusicPlayer arg0)
{
    #define RUN_FUNC  int32_t ret = real::MusicPlayerStart(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockGetPropertyInfo"
#pragma push_macro(FUNC_ID)
#undef CAClockGetPropertyInfo
// extra usings

INTERPOSE(CAClockGetPropertyInfo)(CAClockRef arg0, uint32_t arg1, UnsignedFixedPtr arg2, BytePtr arg3)
{
    #define RUN_FUNC  int32_t ret = real::CAClockGetPropertyInfo(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentCreate"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentCreate
// extra usings
using AudioFileComponentCreate_T_arg3 = const AudioStreamBasicDescription *;
using AudioFileComponentCreate_T_arg3 = const AudioStreamBasicDescription *;
INTERPOSE(AudioFileComponentCreate)(AudioComponentInstance arg0, const FSRef * arg1, CFStringRef arg2, AudioFileComponentCreate_T_arg3 arg3, uint32_t arg4, FSRef * arg5)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentCreate(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioUnitExtensionCopyComponentList"
#pragma push_macro(FUNC_ID)
#undef AudioUnitExtensionCopyComponentList
// extra usings

INTERPOSE(AudioUnitExtensionCopyComponentList)(CFStringRef arg0)
{
    #define RUN_FUNC  CFArrayRef ret = real::AudioUnitExtensionCopyComponentList(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioUnitGetParameter"
#pragma push_macro(FUNC_ID)
#undef AudioUnitGetParameter
// extra usings
using AudioUnitGetParameter_T_arg4 = float *;
using AudioUnitGetParameter_T_arg4 = float *;
INTERPOSE(AudioUnitGetParameter)(AudioComponentInstance arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, AudioUnitGetParameter_T_arg4 arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioUnitGetParameter(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicTrackNewUserEvent"
#pragma push_macro(FUNC_ID)
#undef MusicTrackNewUserEvent
// extra usings

INTERPOSE(MusicTrackNewUserEvent)(MusicTrack arg0, Float64 arg1, const MusicEventUserData * arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicTrackNewUserEvent(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockStart"
#pragma push_macro(FUNC_ID)
#undef CAClockStart
// extra usings

INTERPOSE(CAClockStart)(CAClockRef arg0)
{
    #define RUN_FUNC  int32_t ret = real::CAClockStart(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "ExtAudioFileOpen"
#pragma push_macro(FUNC_ID)
#undef ExtAudioFileOpen
// extra usings
using ExtAudioFileOpen_T_arg1 = OpaqueExtAudioFile **;
using ExtAudioFileOpen_T_arg1 = OpaqueExtAudioFile **;
INTERPOSE(ExtAudioFileOpen)(const FSRef * arg0, ExtAudioFileOpen_T_arg1 arg1)
{
    #define RUN_FUNC  int32_t ret = real::ExtAudioFileOpen(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueGetParameter"
#pragma push_macro(FUNC_ID)
#undef AudioQueueGetParameter
// extra usings
using AudioQueueGetParameter_T_arg2 = float *;
using AudioQueueGetParameter_T_arg2 = float *;
INTERPOSE(AudioQueueGetParameter)(AudioQueueRef arg0, uint32_t arg1, AudioQueueGetParameter_T_arg2 arg2)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueGetParameter(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "DisposeMusicPlayer"
#pragma push_macro(FUNC_ID)
#undef DisposeMusicPlayer
// extra usings

INTERPOSE(DisposeMusicPlayer)(MusicPlayer arg0)
{
    #define RUN_FUNC  int32_t ret = real::DisposeMusicPlayer(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioComponentGetVersion"
#pragma push_macro(FUNC_ID)
#undef AudioComponentGetVersion
// extra usings

INTERPOSE(AudioComponentGetVersion)(AudioComponent arg0, UnsignedFixedPtr arg1)
{
    #define RUN_FUNC  int32_t ret = real::AudioComponentGetVersion(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentGetUserData"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentGetUserData
// extra usings

INTERPOSE(AudioFileComponentGetUserData)(AudioComponentInstance arg0, uint32_t arg1, uint32_t arg2, UnsignedFixedPtr arg3, void * arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentGetUserData(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueNewOutputWithDispatchQueue"
#pragma push_macro(FUNC_ID)
#undef AudioQueueNewOutputWithDispatchQueue
// extra usings
using AudioQueueNewOutputWithDispatchQueue_T_arg0 = OpaqueAudioQueue **;
using AudioQueueNewOutputWithDispatchQueue_T_arg1 = const AudioStreamBasicDescription *;
using AudioQueueNewOutputWithDispatchQueue_T_arg0 = OpaqueAudioQueue **;
using AudioQueueNewOutputWithDispatchQueue_T_arg1 = const AudioStreamBasicDescription *;
INTERPOSE(AudioQueueNewOutputWithDispatchQueue)(AudioQueueNewOutputWithDispatchQueue_T_arg0 arg0, AudioQueueNewOutputWithDispatchQueue_T_arg1 arg1, uint32_t arg2, dispatch_queue_t arg3, AudioQueueOutputCallbackBlock arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueNewOutputWithDispatchQueue(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceGetIndTrack"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceGetIndTrack
// extra usings
using MusicSequenceGetIndTrack_T_arg2 = OpaqueMusicTrack **;
using MusicSequenceGetIndTrack_T_arg2 = OpaqueMusicTrack **;
INTERPOSE(MusicSequenceGetIndTrack)(MusicSequence arg0, uint32_t arg1, MusicSequenceGetIndTrack_T_arg2 arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceGetIndTrack(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceSaveSMFData"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceSaveSMFData
// extra usings
using MusicSequenceSaveSMFData_T_arg1 = const __CFData **;
using MusicSequenceSaveSMFData_T_arg1 = const __CFData **;
INTERPOSE(MusicSequenceSaveSMFData)(MusicSequence arg0, MusicSequenceSaveSMFData_T_arg1 arg1, uint16_t arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceSaveSMFData(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioUnitGetProperty"
#pragma push_macro(FUNC_ID)
#undef AudioUnitGetProperty
// extra usings

INTERPOSE(AudioUnitGetProperty)(AudioComponentInstance arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, void * arg4, UnsignedFixedPtr arg5)
{
    #define RUN_FUNC  int32_t ret = real::AudioUnitGetProperty(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockGetPlayRate"
#pragma push_macro(FUNC_ID)
#undef CAClockGetPlayRate
// extra usings
using CAClockGetPlayRate_T_arg1 = double *;
using CAClockGetPlayRate_T_arg1 = double *;
INTERPOSE(CAClockGetPlayRate)(CAClockRef arg0, CAClockGetPlayRate_T_arg1 arg1)
{
    #define RUN_FUNC  int32_t ret = real::CAClockGetPlayRate(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "ExtAudioFileWriteAsync"
#pragma push_macro(FUNC_ID)
#undef ExtAudioFileWriteAsync
// extra usings

INTERPOSE(ExtAudioFileWriteAsync)(ExtAudioFileRef arg0, uint32_t arg1, const AudioBufferList * arg2)
{
    #define RUN_FUNC  int32_t ret = real::ExtAudioFileWriteAsync(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicTrackClear"
#pragma push_macro(FUNC_ID)
#undef MusicTrackClear
// extra usings

INTERPOSE(MusicTrackClear)(MusicTrack arg0, Float64 arg1, Float64 arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicTrackClear(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileStreamGetProperty"
#pragma push_macro(FUNC_ID)
#undef AudioFileStreamGetProperty
// extra usings

INTERPOSE(AudioFileStreamGetProperty)(AudioFileStreamID arg0, uint32_t arg1, UnsignedFixedPtr arg2, void * arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileStreamGetProperty(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioUnitProcess"
#pragma push_macro(FUNC_ID)
#undef AudioUnitProcess
// extra usings

INTERPOSE(AudioUnitProcess)(AudioComponentInstance arg0, UnsignedFixedPtr arg1, const AudioTimeStamp * arg2, uint32_t arg3, AudioBufferList * arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioUnitProcess(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CopyNameFromSoundBank"
#pragma push_macro(FUNC_ID)
#undef CopyNameFromSoundBank
// extra usings
using CopyNameFromSoundBank_T_arg1 = const __CFString **;
using CopyNameFromSoundBank_T_arg1 = const __CFString **;
INTERPOSE(CopyNameFromSoundBank)(CFURLRef arg0, CopyNameFromSoundBank_T_arg1 arg1)
{
    #define RUN_FUNC  int32_t ret = real::CopyNameFromSoundBank(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioServicesCreateSystemSoundID"
#pragma push_macro(FUNC_ID)
#undef AudioServicesCreateSystemSoundID
// extra usings

INTERPOSE(AudioServicesCreateSystemSoundID)(CFURLRef arg0, UnsignedFixedPtr arg1)
{
    #define RUN_FUNC  int32_t ret = real::AudioServicesCreateSystemSoundID(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicDeviceMIDIEvent"
#pragma push_macro(FUNC_ID)
#undef MusicDeviceMIDIEvent
// extra usings

INTERPOSE(MusicDeviceMIDIEvent)(AudioComponentInstance arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4)
{
    #define RUN_FUNC  int32_t ret = real::MusicDeviceMIDIEvent(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphUninitialize"
#pragma push_macro(FUNC_ID)
#undef AUGraphUninitialize
// extra usings

INTERPOSE(AUGraphUninitialize)(AUGraph arg0)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphUninitialize(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueReset"
#pragma push_macro(FUNC_ID)
#undef AudioQueueReset
// extra usings

INTERPOSE(AudioQueueReset)(AudioQueueRef arg0)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueReset(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceLoadSMFWithFlags"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceLoadSMFWithFlags
// extra usings

INTERPOSE(MusicSequenceLoadSMFWithFlags)(MusicSequence arg0, const FSRef * arg1, uint32_t arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceLoadSMFWithFlags(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioServicesAddSystemSoundCompletion"
#pragma push_macro(FUNC_ID)
#undef AudioServicesAddSystemSoundCompletion
// extra usings

INTERPOSE(AudioServicesAddSystemSoundCompletion)(uint32_t arg0, CFRunLoopRef arg1, CFStringRef arg2, AudioServicesSystemSoundCompletionProc arg3, void * arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioServicesAddSystemSoundCompletion(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueDisposeTimeline"
#pragma push_macro(FUNC_ID)
#undef AudioQueueDisposeTimeline
// extra usings

INTERPOSE(AudioQueueDisposeTimeline)(AudioQueueRef arg0, AudioQueueTimelineRef arg1)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueDisposeTimeline(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentFileIsThisFormat"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentFileIsThisFormat
// extra usings

INTERPOSE(AudioFileComponentFileIsThisFormat)(AudioComponentInstance arg0, int16_t arg1, UnsignedFixedPtr arg2)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentFileIsThisFormat(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileOptimize"
#pragma push_macro(FUNC_ID)
#undef AudioFileOptimize
// extra usings

INTERPOSE(AudioFileOptimize)(struct OpaqueAudioFileID * arg0)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileOptimize(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceGetTrackCount"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceGetTrackCount
// extra usings

INTERPOSE(MusicSequenceGetTrackCount)(MusicSequence arg0, UnsignedFixedPtr arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceGetTrackCount(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicEventIteratorHasNextEvent"
#pragma push_macro(FUNC_ID)
#undef MusicEventIteratorHasNextEvent
// extra usings

INTERPOSE(MusicEventIteratorHasNextEvent)(MusicEventIterator arg0, BytePtr arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicEventIteratorHasNextEvent(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioUnitSetProperty"
#pragma push_macro(FUNC_ID)
#undef AudioUnitSetProperty
// extra usings

INTERPOSE(AudioUnitSetProperty)(AudioComponentInstance arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, const void * arg4, uint32_t arg5)
{
    #define RUN_FUNC  int32_t ret = real::AudioUnitSetProperty(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicDeviceStopNote"
#pragma push_macro(FUNC_ID)
#undef MusicDeviceStopNote
// extra usings

INTERPOSE(MusicDeviceStopNote)(AudioComponentInstance arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3)
{
    #define RUN_FUNC  int32_t ret = real::MusicDeviceStopNote(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockArm"
#pragma push_macro(FUNC_ID)
#undef CAClockArm
// extra usings

INTERPOSE(CAClockArm)(CAClockRef arg0)
{
    #define RUN_FUNC  int32_t ret = real::CAClockArm(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceGetAUGraph"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceGetAUGraph
// extra usings
using MusicSequenceGetAUGraph_T_arg1 = OpaqueAUGraph **;
using MusicSequenceGetAUGraph_T_arg1 = OpaqueAUGraph **;
INTERPOSE(MusicSequenceGetAUGraph)(MusicSequence arg0, MusicSequenceGetAUGraph_T_arg1 arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceGetAUGraph(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileReadPacketData"
#pragma push_macro(FUNC_ID)
#undef AudioFileReadPacketData
// extra usings

INTERPOSE(AudioFileReadPacketData)(struct OpaqueAudioFileID * arg0, uint8_t arg1, UnsignedFixedPtr arg2, AudioStreamPacketDescription * arg3, int64_t arg4, UnsignedFixedPtr arg5, void * arg6)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileReadPacketData(arg0, arg1, arg2, arg3, arg4, arg5, arg6)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg6);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg6);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicTrackGetProperty"
#pragma push_macro(FUNC_ID)
#undef MusicTrackGetProperty
// extra usings

INTERPOSE(MusicTrackGetProperty)(MusicTrack arg0, uint32_t arg1, void * arg2, UnsignedFixedPtr arg3)
{
    #define RUN_FUNC  int32_t ret = real::MusicTrackGetProperty(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioCodecAppendInputData"
#pragma push_macro(FUNC_ID)
#undef AudioCodecAppendInputData
// extra usings

INTERPOSE(AudioCodecAppendInputData)(AudioComponentInstance arg0, const void * arg1, UnsignedFixedPtr arg2, UnsignedFixedPtr arg3, const AudioStreamPacketDescription * arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioCodecAppendInputData(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicEventIteratorSeek"
#pragma push_macro(FUNC_ID)
#undef MusicEventIteratorSeek
// extra usings

INTERPOSE(MusicEventIteratorSeek)(MusicEventIterator arg0, Float64 arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicEventIteratorSeek(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioUnitInitialize"
#pragma push_macro(FUNC_ID)
#undef AudioUnitInitialize
// extra usings

INTERPOSE(AudioUnitInitialize)(AudioComponentInstance arg0)
{
    #define RUN_FUNC  int32_t ret = real::AudioUnitInitialize(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileOpenURL"
#pragma push_macro(FUNC_ID)
#undef AudioFileOpenURL
// extra usings

INTERPOSE(AudioFileOpenURL)(CFURLRef arg0, int8_t arg1, uint32_t arg2, OpaqueAudioFileID ** arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileOpenURL(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUListenerCreate"
#pragma push_macro(FUNC_ID)
#undef AUListenerCreate
// extra usings
using AUListenerCreate_T_arg5 = AUListenerBase **;
using AUListenerCreate_T_arg5 = AUListenerBase **;
INTERPOSE(AUListenerCreate)(AUParameterListenerProc arg0, void * arg1, CFRunLoopRef arg2, CFStringRef arg3, Float32 arg4, AUListenerCreate_T_arg5 arg5)
{
    #define RUN_FUNC  int32_t ret = real::AUListenerCreate(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicTrackNewExtendedTempoEvent"
#pragma push_macro(FUNC_ID)
#undef MusicTrackNewExtendedTempoEvent
// extra usings

INTERPOSE(MusicTrackNewExtendedTempoEvent)(MusicTrack arg0, Float64 arg1, Float64 arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicTrackNewExtendedTempoEvent(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUListenerDispose"
#pragma push_macro(FUNC_ID)
#undef AUListenerDispose
// extra usings

INTERPOSE(AUListenerDispose)(AUParameterListenerRef arg0)
{
    #define RUN_FUNC  int32_t ret = real::AUListenerDispose(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphGetNodeInteractions"
#pragma push_macro(FUNC_ID)
#undef AUGraphGetNodeInteractions
// extra usings

INTERPOSE(AUGraphGetNodeInteractions)(AUGraph arg0, int32_t arg1, UnsignedFixedPtr arg2, AUNodeInteraction * arg3)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphGetNodeInteractions(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphCountNodeConnections"
#pragma push_macro(FUNC_ID)
#undef AUGraphCountNodeConnections
// extra usings

INTERPOSE(AUGraphCountNodeConnections)(AUGraph arg0, int32_t arg1, UnsignedFixedPtr arg2)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphCountNodeConnections(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphGetNodeInfoSubGraph"
#pragma push_macro(FUNC_ID)
#undef AUGraphGetNodeInfoSubGraph
// extra usings
using AUGraphGetNodeInfoSubGraph_T_arg2 = OpaqueAUGraph **;
using AUGraphGetNodeInfoSubGraph_T_arg2 = OpaqueAUGraph **;
INTERPOSE(AUGraphGetNodeInfoSubGraph)(AUGraph arg0, int32_t arg1, AUGraphGetNodeInfoSubGraph_T_arg2 arg2)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphGetNodeInfoSubGraph(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicTrackNewExtendedNoteEvent"
#pragma push_macro(FUNC_ID)
#undef MusicTrackNewExtendedNoteEvent
// extra usings

INTERPOSE(MusicTrackNewExtendedNoteEvent)(MusicTrack arg0, Float64 arg1, const ExtendedNoteOnEvent * arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicTrackNewExtendedNoteEvent(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUParameterValueFromLinear"
#pragma push_macro(FUNC_ID)
#undef AUParameterValueFromLinear
// extra usings

INTERPOSE(AUParameterValueFromLinear)(Float32 arg0, const AudioUnitParameter * arg1)
{
    #define RUN_FUNC  Float32 ret = real::AUParameterValueFromLinear(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileOpen"
#pragma push_macro(FUNC_ID)
#undef AudioFileOpen
// extra usings

INTERPOSE(AudioFileOpen)(const FSRef * arg0, int8_t arg1, uint32_t arg2, OpaqueAudioFileID ** arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileOpen(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphGetNumberOfConnections"
#pragma push_macro(FUNC_ID)
#undef AUGraphGetNumberOfConnections
// extra usings

INTERPOSE(AUGraphGetNumberOfConnections)(AUGraph arg0, UnsignedFixedPtr arg1)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphGetNumberOfConnections(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicTrackNewMIDIRawDataEvent"
#pragma push_macro(FUNC_ID)
#undef MusicTrackNewMIDIRawDataEvent
// extra usings

INTERPOSE(MusicTrackNewMIDIRawDataEvent)(MusicTrack arg0, Float64 arg1, const MIDIRawData * arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicTrackNewMIDIRawDataEvent(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicPlayerGetBeatsForHostTime"
#pragma push_macro(FUNC_ID)
#undef MusicPlayerGetBeatsForHostTime
// extra usings
using MusicPlayerGetBeatsForHostTime_T_arg2 = double *;
using MusicPlayerGetBeatsForHostTime_T_arg2 = double *;
INTERPOSE(MusicPlayerGetBeatsForHostTime)(MusicPlayer arg0, uint64_t arg1, MusicPlayerGetBeatsForHostTime_T_arg2 arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicPlayerGetBeatsForHostTime(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueDeviceTranslateTime"
#pragma push_macro(FUNC_ID)
#undef AudioQueueDeviceTranslateTime
// extra usings

INTERPOSE(AudioQueueDeviceTranslateTime)(AudioQueueRef arg0, const AudioTimeStamp * arg1, AudioTimeStamp * arg2)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueDeviceTranslateTime(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockSetPlayRate"
#pragma push_macro(FUNC_ID)
#undef CAClockSetPlayRate
// extra usings

INTERPOSE(CAClockSetPlayRate)(CAClockRef arg0, Float64 arg1)
{
    #define RUN_FUNC  int32_t ret = real::CAClockSetPlayRate(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioCodecProduceOutputPackets"
#pragma push_macro(FUNC_ID)
#undef AudioCodecProduceOutputPackets
// extra usings

INTERPOSE(AudioCodecProduceOutputPackets)(AudioComponentInstance arg0, void * arg1, UnsignedFixedPtr arg2, UnsignedFixedPtr arg3, AudioStreamPacketDescription * arg4, UnsignedFixedPtr arg5)
{
    #define RUN_FUNC  int32_t ret = real::AudioCodecProduceOutputPackets(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioUnitRemovePropertyListenerWithUserData"
#pragma push_macro(FUNC_ID)
#undef AudioUnitRemovePropertyListenerWithUserData
// extra usings

INTERPOSE(AudioUnitRemovePropertyListenerWithUserData)(AudioComponentInstance arg0, uint32_t arg1, AudioUnitPropertyListenerProc arg2, void * arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioUnitRemovePropertyListenerWithUserData(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUEventListenerCreate"
#pragma push_macro(FUNC_ID)
#undef AUEventListenerCreate
// extra usings
using AUEventListenerCreate_T_arg6 = AUListenerBase **;
using AUEventListenerCreate_T_arg6 = AUListenerBase **;
INTERPOSE(AUEventListenerCreate)(AUEventListenerProc arg0, void * arg1, CFRunLoopRef arg2, CFStringRef arg3, Float32 arg4, Float32 arg5, AUEventListenerCreate_T_arg6 arg6)
{
    #define RUN_FUNC  int32_t ret = real::AUEventListenerCreate(arg0, arg1, arg2, arg3, arg4, arg5, arg6)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg6);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg6);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentInitializeWithCallbacks"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentInitializeWithCallbacks
// extra usings
using AudioFileComponentInitializeWithCallbacks_T_arg7 = const AudioStreamBasicDescription *;
using AudioFileComponentInitializeWithCallbacks_T_arg7 = const AudioStreamBasicDescription *;
INTERPOSE(AudioFileComponentInitializeWithCallbacks)(AudioComponentInstance arg0, void * arg1, AudioFile_ReadProc arg2, AudioFile_WriteProc arg3, AudioFile_GetSizeProc arg4, AudioFile_SetSizeProc arg5, uint32_t arg6, AudioFileComponentInitializeWithCallbacks_T_arg7 arg7, uint32_t arg8)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentInitializeWithCallbacks(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg6);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg7);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg8);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg6);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg7);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg8);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileGetGlobalInfoSize"
#pragma push_macro(FUNC_ID)
#undef AudioFileGetGlobalInfoSize
// extra usings

INTERPOSE(AudioFileGetGlobalInfoSize)(uint32_t arg0, uint32_t arg1, void * arg2, UnsignedFixedPtr arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileGetGlobalInfoSize(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "ExtAudioFileWrapAudioFileID"
#pragma push_macro(FUNC_ID)
#undef ExtAudioFileWrapAudioFileID
// extra usings
using ExtAudioFileWrapAudioFileID_T_arg2 = OpaqueExtAudioFile **;
using ExtAudioFileWrapAudioFileID_T_arg2 = OpaqueExtAudioFile **;
INTERPOSE(ExtAudioFileWrapAudioFileID)(struct OpaqueAudioFileID * arg0, uint8_t arg1, ExtAudioFileWrapAudioFileID_T_arg2 arg2)
{
    #define RUN_FUNC  int32_t ret = real::ExtAudioFileWrapAudioFileID(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileStreamParseBytes"
#pragma push_macro(FUNC_ID)
#undef AudioFileStreamParseBytes
// extra usings

INTERPOSE(AudioFileStreamParseBytes)(AudioFileStreamID arg0, uint32_t arg1, const void * arg2, uint32_t arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileStreamParseBytes(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileStreamOpen"
#pragma push_macro(FUNC_ID)
#undef AudioFileStreamOpen
// extra usings
using AudioFileStreamOpen_T_arg4 = OpaqueAudioFileStreamID **;
using AudioFileStreamOpen_T_arg4 = OpaqueAudioFileStreamID **;
INTERPOSE(AudioFileStreamOpen)(void * arg0, AudioFileStream_PropertyListenerProc arg1, AudioFileStream_PacketsProc arg2, uint32_t arg3, AudioFileStreamOpen_T_arg4 arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileStreamOpen(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicPlayerStop"
#pragma push_macro(FUNC_ID)
#undef MusicPlayerStop
// extra usings

INTERPOSE(MusicPlayerStop)(MusicPlayer arg0)
{
    #define RUN_FUNC  int32_t ret = real::MusicPlayerStop(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioComponentRegister"
#pragma push_macro(FUNC_ID)
#undef AudioComponentRegister
// extra usings

INTERPOSE(AudioComponentRegister)(const AudioComponentDescription * arg0, CFStringRef arg1, uint32_t arg2, AudioComponentFactoryFunction arg3)
{
    #define RUN_FUNC  AudioComponent ret = real::AudioComponentRegister(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CopyInstrumentInfoFromSoundBank"
#pragma push_macro(FUNC_ID)
#undef CopyInstrumentInfoFromSoundBank
// extra usings
using CopyInstrumentInfoFromSoundBank_T_arg1 = const __CFArray **;
using CopyInstrumentInfoFromSoundBank_T_arg1 = const __CFArray **;
INTERPOSE(CopyInstrumentInfoFromSoundBank)(CFURLRef arg0, CopyInstrumentInfoFromSoundBank_T_arg1 arg1)
{
    #define RUN_FUNC  int32_t ret = real::CopyInstrumentInfoFromSoundBank(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockDispose"
#pragma push_macro(FUNC_ID)
#undef CAClockDispose
// extra usings

INTERPOSE(CAClockDispose)(CAClockRef arg0)
{
    #define RUN_FUNC  int32_t ret = real::CAClockDispose(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockGetCurrentTempo"
#pragma push_macro(FUNC_ID)
#undef CAClockGetCurrentTempo
// extra usings
using CAClockGetCurrentTempo_T_arg1 = double *;
using CAClockGetCurrentTempo_T_arg1 = double *;
INTERPOSE(CAClockGetCurrentTempo)(CAClockRef arg0, CAClockGetCurrentTempo_T_arg1 arg1, CAClockTime * arg2)
{
    #define RUN_FUNC  int32_t ret = real::CAClockGetCurrentTempo(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicTrackNewMIDIChannelEvent"
#pragma push_macro(FUNC_ID)
#undef MusicTrackNewMIDIChannelEvent
// extra usings

INTERPOSE(MusicTrackNewMIDIChannelEvent)(MusicTrack arg0, Float64 arg1, const MIDIChannelMessage * arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicTrackNewMIDIChannelEvent(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceReverse"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceReverse
// extra usings

INTERPOSE(MusicSequenceReverse)(MusicSequence arg0)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceReverse(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileInitialize"
#pragma push_macro(FUNC_ID)
#undef AudioFileInitialize
// extra usings
using AudioFileInitialize_T_arg2 = const AudioStreamBasicDescription *;
using AudioFileInitialize_T_arg2 = const AudioStreamBasicDescription *;
INTERPOSE(AudioFileInitialize)(const FSRef * arg0, uint32_t arg1, AudioFileInitialize_T_arg2 arg2, uint32_t arg3, OpaqueAudioFileID ** arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileInitialize(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueProcessingTapDispose"
#pragma push_macro(FUNC_ID)
#undef AudioQueueProcessingTapDispose
// extra usings

INTERPOSE(AudioQueueProcessingTapDispose)(AudioQueueProcessingTapRef arg0)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueProcessingTapDispose(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicEventIteratorHasPreviousEvent"
#pragma push_macro(FUNC_ID)
#undef MusicEventIteratorHasPreviousEvent
// extra usings

INTERPOSE(MusicEventIteratorHasPreviousEvent)(MusicEventIterator arg0, BytePtr arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicEventIteratorHasPreviousEvent(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphIsRunning"
#pragma push_macro(FUNC_ID)
#undef AUGraphIsRunning
// extra usings

INTERPOSE(AUGraphIsRunning)(AUGraph arg0, BytePtr arg1)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphIsRunning(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicDeviceSysEx"
#pragma push_macro(FUNC_ID)
#undef MusicDeviceSysEx
// extra usings

INTERPOSE(MusicDeviceSysEx)(AudioComponentInstance arg0, ConstStringPtr arg1, uint32_t arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicDeviceSysEx(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueGetProperty"
#pragma push_macro(FUNC_ID)
#undef AudioQueueGetProperty
// extra usings

INTERPOSE(AudioQueueGetProperty)(AudioQueueRef arg0, uint32_t arg1, void * arg2, UnsignedFixedPtr arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueGetProperty(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceFileCreateData"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceFileCreateData
// extra usings
using MusicSequenceFileCreateData_T_arg4 = const __CFData **;
using MusicSequenceFileCreateData_T_arg4 = const __CFData **;
INTERPOSE(MusicSequenceFileCreateData)(MusicSequence arg0, uint32_t arg1, uint32_t arg2, int16_t arg3, MusicSequenceFileCreateData_T_arg4 arg4)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceFileCreateData(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueDeviceGetNearestStartTime"
#pragma push_macro(FUNC_ID)
#undef AudioQueueDeviceGetNearestStartTime
// extra usings

INTERPOSE(AudioQueueDeviceGetNearestStartTime)(AudioQueueRef arg0, AudioTimeStamp * arg1, uint32_t arg2)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueDeviceGetNearestStartTime(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphGetConnectionInfo"
#pragma push_macro(FUNC_ID)
#undef AUGraphGetConnectionInfo
// extra usings

INTERPOSE(AUGraphGetConnectionInfo)(AUGraph arg0, uint32_t arg1, FixedPtr arg2, UnsignedFixedPtr arg3, FixedPtr arg4, UnsignedFixedPtr arg5)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphGetConnectionInfo(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueGetCurrentTime"
#pragma push_macro(FUNC_ID)
#undef AudioQueueGetCurrentTime
// extra usings

INTERPOSE(AudioQueueGetCurrentTime)(AudioQueueRef arg0, AudioQueueTimelineRef arg1, AudioTimeStamp * arg2, BytePtr arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueGetCurrentTime(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicPlayerGetSequence"
#pragma push_macro(FUNC_ID)
#undef MusicPlayerGetSequence
// extra usings
using MusicPlayerGetSequence_T_arg1 = OpaqueMusicSequence **;
using MusicPlayerGetSequence_T_arg1 = OpaqueMusicSequence **;
INTERPOSE(MusicPlayerGetSequence)(MusicPlayer arg0, MusicPlayerGetSequence_T_arg1 arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicPlayerGetSequence(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicPlayerGetHostTimeForBeats"
#pragma push_macro(FUNC_ID)
#undef MusicPlayerGetHostTimeForBeats
// extra usings
using MusicPlayerGetHostTimeForBeats_T_arg2 = unsigned long long *;
using MusicPlayerGetHostTimeForBeats_T_arg2 = unsigned long long *;
INTERPOSE(MusicPlayerGetHostTimeForBeats)(MusicPlayer arg0, Float64 arg1, MusicPlayerGetHostTimeForBeats_T_arg2 arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicPlayerGetHostTimeForBeats(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicTrackNewMIDINoteEvent"
#pragma push_macro(FUNC_ID)
#undef MusicTrackNewMIDINoteEvent
// extra usings

INTERPOSE(MusicTrackNewMIDINoteEvent)(MusicTrack arg0, Float64 arg1, const MIDINoteMessage * arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicTrackNewMIDINoteEvent(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockTranslateTime"
#pragma push_macro(FUNC_ID)
#undef CAClockTranslateTime
// extra usings

INTERPOSE(CAClockTranslateTime)(CAClockRef arg0, const CAClockTime * arg1, uint32_t arg2, CAClockTime * arg3)
{
    #define RUN_FUNC  int32_t ret = real::CAClockTranslateTime(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileSetUserData"
#pragma push_macro(FUNC_ID)
#undef AudioFileSetUserData
// extra usings

INTERPOSE(AudioFileSetUserData)(struct OpaqueAudioFileID * arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, const void * arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileSetUserData(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentFileDataIsThisFormat"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentFileDataIsThisFormat
// extra usings

INTERPOSE(AudioFileComponentFileDataIsThisFormat)(AudioComponentInstance arg0, uint32_t arg1, const void * arg2, UnsignedFixedPtr arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentFileDataIsThisFormat(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioComponentCopyConfigurationInfo"
#pragma push_macro(FUNC_ID)
#undef AudioComponentCopyConfigurationInfo
// extra usings
using AudioComponentCopyConfigurationInfo_T_arg1 = const __CFDictionary **;
using AudioComponentCopyConfigurationInfo_T_arg1 = const __CFDictionary **;
INTERPOSE(AudioComponentCopyConfigurationInfo)(AudioComponent arg0, AudioComponentCopyConfigurationInfo_T_arg1 arg1)
{
    #define RUN_FUNC  int32_t ret = real::AudioComponentCopyConfigurationInfo(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "GetNameFromSoundBank"
#pragma push_macro(FUNC_ID)
#undef GetNameFromSoundBank
// extra usings
using GetNameFromSoundBank_T_arg1 = const __CFString **;
using GetNameFromSoundBank_T_arg1 = const __CFString **;
INTERPOSE(GetNameFromSoundBank)(const FSRef * arg0, GetNameFromSoundBank_T_arg1 arg1)
{
    #define RUN_FUNC  int32_t ret = real::GetNameFromSoundBank(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentReadPackets"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentReadPackets
// extra usings

INTERPOSE(AudioFileComponentReadPackets)(AudioComponentInstance arg0, uint8_t arg1, UnsignedFixedPtr arg2, AudioStreamPacketDescription * arg3, int64_t arg4, UnsignedFixedPtr arg5, void * arg6)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentReadPackets(arg0, arg1, arg2, arg3, arg4, arg5, arg6)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg6);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg6);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicTrackCut"
#pragma push_macro(FUNC_ID)
#undef MusicTrackCut
// extra usings

INTERPOSE(MusicTrackCut)(MusicTrack arg0, Float64 arg1, Float64 arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicTrackCut(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUParameterValueToLinear"
#pragma push_macro(FUNC_ID)
#undef AUParameterValueToLinear
// extra usings

INTERPOSE(AUParameterValueToLinear)(Float32 arg0, const AudioUnitParameter * arg1)
{
    #define RUN_FUNC  Float32 ret = real::AUParameterValueToLinear(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicPlayerGetPlayRateScalar"
#pragma push_macro(FUNC_ID)
#undef MusicPlayerGetPlayRateScalar
// extra usings
using MusicPlayerGetPlayRateScalar_T_arg1 = double *;
using MusicPlayerGetPlayRateScalar_T_arg1 = double *;
INTERPOSE(MusicPlayerGetPlayRateScalar)(MusicPlayer arg0, MusicPlayerGetPlayRateScalar_T_arg1 arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicPlayerGetPlayRateScalar(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "NewMusicSequence"
#pragma push_macro(FUNC_ID)
#undef NewMusicSequence
// extra usings
using NewMusicSequence_T_arg0 = OpaqueMusicSequence **;
using NewMusicSequence_T_arg0 = OpaqueMusicSequence **;
INTERPOSE(NewMusicSequence)(NewMusicSequence_T_arg0 arg0)
{
    #define RUN_FUNC  int32_t ret = real::NewMusicSequence(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphSetNodeInputCallback"
#pragma push_macro(FUNC_ID)
#undef AUGraphSetNodeInputCallback
// extra usings

INTERPOSE(AUGraphSetNodeInputCallback)(AUGraph arg0, int32_t arg1, uint32_t arg2, const AURenderCallbackStruct * arg3)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphSetNodeInputCallback(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceFileCreate"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceFileCreate
// extra usings

INTERPOSE(MusicSequenceFileCreate)(MusicSequence arg0, CFURLRef arg1, uint32_t arg2, uint32_t arg3, int16_t arg4)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceFileCreate(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioUnitScheduleParameters"
#pragma push_macro(FUNC_ID)
#undef AudioUnitScheduleParameters
// extra usings

INTERPOSE(AudioUnitScheduleParameters)(AudioComponentInstance arg0, const AudioUnitParameterEvent * arg1, uint32_t arg2)
{
    #define RUN_FUNC  int32_t ret = real::AudioUnitScheduleParameters(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicTrackGetDestNode"
#pragma push_macro(FUNC_ID)
#undef MusicTrackGetDestNode
// extra usings

INTERPOSE(MusicTrackGetDestNode)(MusicTrack arg0, FixedPtr arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicTrackGetDestNode(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueEnqueueBufferWithParameters"
#pragma push_macro(FUNC_ID)
#undef AudioQueueEnqueueBufferWithParameters
// extra usings

INTERPOSE(AudioQueueEnqueueBufferWithParameters)(AudioQueueRef arg0, AudioQueueBufferRef arg1, uint32_t arg2, const AudioStreamPacketDescription * arg3, uint32_t arg4, uint32_t arg5, uint32_t arg6, const AudioQueueParameterEvent * arg7, const AudioTimeStamp * arg8, AudioTimeStamp * arg9)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueEnqueueBufferWithParameters(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg6);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg7);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg8);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg9);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg6);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg7);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg8);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg9);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceLoadSMFDataWithFlags"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceLoadSMFDataWithFlags
// extra usings

INTERPOSE(MusicSequenceLoadSMFDataWithFlags)(MusicSequence arg0, CFDataRef arg1, uint32_t arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceLoadSMFDataWithFlags(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentExtensionIsThisFormat"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentExtensionIsThisFormat
// extra usings

INTERPOSE(AudioFileComponentExtensionIsThisFormat)(AudioComponentInstance arg0, CFStringRef arg1, UnsignedFixedPtr arg2)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentExtensionIsThisFormat(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceGetTrackIndex"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceGetTrackIndex
// extra usings

INTERPOSE(MusicSequenceGetTrackIndex)(MusicSequence arg0, MusicTrack arg1, UnsignedFixedPtr arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceGetTrackIndex(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphNodeInfo"
#pragma push_macro(FUNC_ID)
#undef AUGraphNodeInfo
// extra usings
using AUGraphNodeInfo_T_arg3 = ComponentInstanceRecord **;
using AUGraphNodeInfo_T_arg3 = ComponentInstanceRecord **;
INTERPOSE(AUGraphNodeInfo)(AUGraph arg0, int32_t arg1, AudioComponentDescription * arg2, AUGraphNodeInfo_T_arg3 arg3)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphNodeInfo(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueOfflineRender"
#pragma push_macro(FUNC_ID)
#undef AudioQueueOfflineRender
// extra usings

INTERPOSE(AudioQueueOfflineRender)(AudioQueueRef arg0, const AudioTimeStamp * arg1, AudioQueueBufferRef arg2, uint32_t arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueOfflineRender(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphGetIndNode"
#pragma push_macro(FUNC_ID)
#undef AUGraphGetIndNode
// extra usings

INTERPOSE(AUGraphGetIndNode)(AUGraph arg0, uint32_t arg1, FixedPtr arg2)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphGetIndNode(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceGetSequenceType"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceGetSequenceType
// extra usings

INTERPOSE(MusicSequenceGetSequenceType)(MusicSequence arg0, UnsignedFixedPtr arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceGetSequenceType(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueDeviceGetCurrentTime"
#pragma push_macro(FUNC_ID)
#undef AudioQueueDeviceGetCurrentTime
// extra usings

INTERPOSE(AudioQueueDeviceGetCurrentTime)(AudioQueueRef arg0, AudioTimeStamp * arg1)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueDeviceGetCurrentTime(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "ExtAudioFileCreateNew"
#pragma push_macro(FUNC_ID)
#undef ExtAudioFileCreateNew
// extra usings
using ExtAudioFileCreateNew_T_arg3 = const AudioStreamBasicDescription *;
using ExtAudioFileCreateNew_T_arg5 = OpaqueExtAudioFile **;
using ExtAudioFileCreateNew_T_arg3 = const AudioStreamBasicDescription *;
using ExtAudioFileCreateNew_T_arg5 = OpaqueExtAudioFile **;
INTERPOSE(ExtAudioFileCreateNew)(const FSRef * arg0, CFStringRef arg1, uint32_t arg2, ExtAudioFileCreateNew_T_arg3 arg3, const AudioChannelLayout * arg4, ExtAudioFileCreateNew_T_arg5 arg5)
{
    #define RUN_FUNC  int32_t ret = real::ExtAudioFileCreateNew(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAShow"
#pragma push_macro(FUNC_ID)
#undef CAShow
// extra usings

INTERPOSE(CAShow)(void * arg0)
{
    #define RUN_FUNC  real::CAShow(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueNewInputWithDispatchQueue"
#pragma push_macro(FUNC_ID)
#undef AudioQueueNewInputWithDispatchQueue
// extra usings
using AudioQueueNewInputWithDispatchQueue_T_arg0 = OpaqueAudioQueue **;
using AudioQueueNewInputWithDispatchQueue_T_arg1 = const AudioStreamBasicDescription *;
using AudioQueueNewInputWithDispatchQueue_T_arg0 = OpaqueAudioQueue **;
using AudioQueueNewInputWithDispatchQueue_T_arg1 = const AudioStreamBasicDescription *;
INTERPOSE(AudioQueueNewInputWithDispatchQueue)(AudioQueueNewInputWithDispatchQueue_T_arg0 arg0, AudioQueueNewInputWithDispatchQueue_T_arg1 arg1, uint32_t arg2, dispatch_queue_t arg3, AudioQueueInputCallbackBlock arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueNewInputWithDispatchQueue(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphStop"
#pragma push_macro(FUNC_ID)
#undef AUGraphStop
// extra usings

INTERPOSE(AUGraphStop)(AUGraph arg0)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphStop(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueProcessingTapGetSourceAudio"
#pragma push_macro(FUNC_ID)
#undef AudioQueueProcessingTapGetSourceAudio
// extra usings

INTERPOSE(AudioQueueProcessingTapGetSourceAudio)(AudioQueueProcessingTapRef arg0, uint32_t arg1, AudioTimeStamp * arg2, UnsignedFixedPtr arg3, UnsignedFixedPtr arg4, AudioBufferList * arg5)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueProcessingTapGetSourceAudio(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioCodecProduceOutputBufferList"
#pragma push_macro(FUNC_ID)
#undef AudioCodecProduceOutputBufferList
// extra usings

INTERPOSE(AudioCodecProduceOutputBufferList)(AudioComponentInstance arg0, AudioBufferList * arg1, UnsignedFixedPtr arg2, AudioStreamPacketDescription * arg3, UnsignedFixedPtr arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioCodecProduceOutputBufferList(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileWritePackets"
#pragma push_macro(FUNC_ID)
#undef AudioFileWritePackets
// extra usings

INTERPOSE(AudioFileWritePackets)(struct OpaqueAudioFileID * arg0, uint8_t arg1, uint32_t arg2, const AudioStreamPacketDescription * arg3, int64_t arg4, UnsignedFixedPtr arg5, const void * arg6)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileWritePackets(arg0, arg1, arg2, arg3, arg4, arg5, arg6)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg6);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg6);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentCloseFile"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentCloseFile
// extra usings

INTERPOSE(AudioFileComponentCloseFile)(AudioComponentInstance arg0)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentCloseFile(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileStreamSeek"
#pragma push_macro(FUNC_ID)
#undef AudioFileStreamSeek
// extra usings

INTERPOSE(AudioFileStreamSeek)(AudioFileStreamID arg0, int64_t arg1, qaddr_t arg2, UnsignedFixedPtr arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileStreamSeek(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceGetInfoDictionary"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceGetInfoDictionary
// extra usings

INTERPOSE(MusicSequenceGetInfoDictionary)(MusicSequence arg0)
{
    #define RUN_FUNC  CFDictionaryRef ret = real::MusicSequenceGetInfoDictionary(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioConverterConvertComplexBuffer"
#pragma push_macro(FUNC_ID)
#undef AudioConverterConvertComplexBuffer
// extra usings

INTERPOSE(AudioConverterConvertComplexBuffer)(AudioConverterRef arg0, uint32_t arg1, const AudioBufferList * arg2, AudioBufferList * arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioConverterConvertComplexBuffer(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceGetBeatsForSeconds"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceGetBeatsForSeconds
// extra usings
using MusicSequenceGetBeatsForSeconds_T_arg2 = double *;
using MusicSequenceGetBeatsForSeconds_T_arg2 = double *;
INTERPOSE(MusicSequenceGetBeatsForSeconds)(MusicSequence arg0, Float64 arg1, MusicSequenceGetBeatsForSeconds_T_arg2 arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceGetBeatsForSeconds(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockParseMIDI"
#pragma push_macro(FUNC_ID)
#undef CAClockParseMIDI
// extra usings

INTERPOSE(CAClockParseMIDI)(CAClockRef arg0, const MIDIPacketList * arg1)
{
    #define RUN_FUNC  int32_t ret = real::CAClockParseMIDI(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueStop"
#pragma push_macro(FUNC_ID)
#undef AudioQueueStop
// extra usings

INTERPOSE(AudioQueueStop)(AudioQueueRef arg0, uint8_t arg1)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueStop(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicPlayerSetTime"
#pragma push_macro(FUNC_ID)
#undef MusicPlayerSetTime
// extra usings

INTERPOSE(MusicPlayerSetTime)(MusicPlayer arg0, Float64 arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicPlayerSetTime(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUListenerCreateWithDispatchQueue"
#pragma push_macro(FUNC_ID)
#undef AUListenerCreateWithDispatchQueue
// extra usings
using AUListenerCreateWithDispatchQueue_T_arg0 = AUListenerBase **;
using AUListenerCreateWithDispatchQueue_T_arg0 = AUListenerBase **;
INTERPOSE(AUListenerCreateWithDispatchQueue)(AUListenerCreateWithDispatchQueue_T_arg0 arg0, Float32 arg1, dispatch_queue_t arg2, AUParameterListenerBlock arg3)
{
    #define RUN_FUNC  int32_t ret = real::AUListenerCreateWithDispatchQueue(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioConverterNewSpecific"
#pragma push_macro(FUNC_ID)
#undef AudioConverterNewSpecific
// extra usings
using AudioConverterNewSpecific_T_arg0 = const AudioStreamBasicDescription *;
using AudioConverterNewSpecific_T_arg1 = const AudioStreamBasicDescription *;
using AudioConverterNewSpecific_T_arg4 = OpaqueAudioConverter **;
using AudioConverterNewSpecific_T_arg0 = const AudioStreamBasicDescription *;
using AudioConverterNewSpecific_T_arg1 = const AudioStreamBasicDescription *;
using AudioConverterNewSpecific_T_arg4 = OpaqueAudioConverter **;
INTERPOSE(AudioConverterNewSpecific)(AudioConverterNewSpecific_T_arg0 arg0, AudioConverterNewSpecific_T_arg1 arg1, uint32_t arg2, const AudioClassDescription * arg3, AudioConverterNewSpecific_T_arg4 arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioConverterNewSpecific(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicTrackCopyInsert"
#pragma push_macro(FUNC_ID)
#undef MusicTrackCopyInsert
// extra usings

INTERPOSE(MusicTrackCopyInsert)(MusicTrack arg0, Float64 arg1, Float64 arg2, MusicTrack arg3, Float64 arg4)
{
    #define RUN_FUNC  int32_t ret = real::MusicTrackCopyInsert(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAShowFile"
#pragma push_macro(FUNC_ID)
#undef CAShowFile
// extra usings

INTERPOSE(CAShowFile)(void * arg0, FILE * arg1)
{
    #define RUN_FUNC  real::CAShowFile(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicPlayerPreroll"
#pragma push_macro(FUNC_ID)
#undef MusicPlayerPreroll
// extra usings

INTERPOSE(MusicPlayerPreroll)(MusicPlayer arg0)
{
    #define RUN_FUNC  int32_t ret = real::MusicPlayerPreroll(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioConverterGetProperty"
#pragma push_macro(FUNC_ID)
#undef AudioConverterGetProperty
// extra usings

INTERPOSE(AudioConverterGetProperty)(AudioConverterRef arg0, uint32_t arg1, UnsignedFixedPtr arg2, void * arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioConverterGetProperty(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileWriteBytes"
#pragma push_macro(FUNC_ID)
#undef AudioFileWriteBytes
// extra usings

INTERPOSE(AudioFileWriteBytes)(struct OpaqueAudioFileID * arg0, uint8_t arg1, int64_t arg2, UnsignedFixedPtr arg3, const void * arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileWriteBytes(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueuePause"
#pragma push_macro(FUNC_ID)
#undef AudioQueuePause
// extra usings

INTERPOSE(AudioQueuePause)(AudioQueueRef arg0)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueuePause(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileComponentGetGlobalInfoSize"
#pragma push_macro(FUNC_ID)
#undef AudioFileComponentGetGlobalInfoSize
// extra usings

INTERPOSE(AudioFileComponentGetGlobalInfoSize)(AudioComponentInstance arg0, uint32_t arg1, uint32_t arg2, const void * arg3, UnsignedFixedPtr arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileComponentGetGlobalInfoSize(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioComponentInstanceGetComponent"
#pragma push_macro(FUNC_ID)
#undef AudioComponentInstanceGetComponent
// extra usings

INTERPOSE(AudioComponentInstanceGetComponent)(AudioComponentInstance arg0)
{
    #define RUN_FUNC  AudioComponent ret = real::AudioComponentInstanceGetComponent(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueDispose"
#pragma push_macro(FUNC_ID)
#undef AudioQueueDispose
// extra usings

INTERPOSE(AudioQueueDispose)(AudioQueueRef arg0, uint8_t arg1)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueDispose(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileStreamClose"
#pragma push_macro(FUNC_ID)
#undef AudioFileStreamClose
// extra usings

INTERPOSE(AudioFileStreamClose)(AudioFileStreamID arg0)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileStreamClose(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceSetMIDIEndpoint"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceSetMIDIEndpoint
// extra usings

INTERPOSE(MusicSequenceSetMIDIEndpoint)(MusicSequence arg0, uint32_t arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceSetMIDIEndpoint(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockSetCurrentTempo"
#pragma push_macro(FUNC_ID)
#undef CAClockSetCurrentTempo
// extra usings

INTERPOSE(CAClockSetCurrentTempo)(CAClockRef arg0, Float64 arg1, const CAClockTime * arg2)
{
    #define RUN_FUNC  int32_t ret = real::CAClockSetCurrentTempo(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphCountNodeInteractions"
#pragma push_macro(FUNC_ID)
#undef AUGraphCountNodeInteractions
// extra usings

INTERPOSE(AUGraphCountNodeInteractions)(AUGraph arg0, int32_t arg1, UnsignedFixedPtr arg2)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphCountNodeInteractions(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicTrackNewExtendedControlEvent"
#pragma push_macro(FUNC_ID)
#undef MusicTrackNewExtendedControlEvent
// extra usings

INTERPOSE(MusicTrackNewExtendedControlEvent)(MusicTrack arg0, Float64 arg1, const ExtendedControlEvent * arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicTrackNewExtendedControlEvent(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueFlush"
#pragma push_macro(FUNC_ID)
#undef AudioQueueFlush
// extra usings

INTERPOSE(AudioQueueFlush)(AudioQueueRef arg0)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueFlush(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioServicesPlaySystemSound"
#pragma push_macro(FUNC_ID)
#undef AudioServicesPlaySystemSound
// extra usings

INTERPOSE(AudioServicesPlaySystemSound)(uint32_t arg0)
{
    #define RUN_FUNC  real::AudioServicesPlaySystemSound(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphUpdate"
#pragma push_macro(FUNC_ID)
#undef AUGraphUpdate
// extra usings

INTERPOSE(AUGraphUpdate)(AUGraph arg0, BytePtr arg1)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphUpdate(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CAClockBarBeatTimeToBeats"
#pragma push_macro(FUNC_ID)
#undef CAClockBarBeatTimeToBeats
// extra usings
using CAClockBarBeatTimeToBeats_T_arg2 = double *;
using CAClockBarBeatTimeToBeats_T_arg2 = double *;
INTERPOSE(CAClockBarBeatTimeToBeats)(CAClockRef arg0, const CABarBeatTime * arg1, CAClockBarBeatTimeToBeats_T_arg2 arg2)
{
    #define RUN_FUNC  int32_t ret = real::CAClockBarBeatTimeToBeats(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileInitializeWithCallbacks"
#pragma push_macro(FUNC_ID)
#undef AudioFileInitializeWithCallbacks
// extra usings
using AudioFileInitializeWithCallbacks_T_arg6 = const AudioStreamBasicDescription *;
using AudioFileInitializeWithCallbacks_T_arg6 = const AudioStreamBasicDescription *;
INTERPOSE(AudioFileInitializeWithCallbacks)(void * arg0, AudioFile_ReadProc arg1, AudioFile_WriteProc arg2, AudioFile_GetSizeProc arg3, AudioFile_SetSizeProc arg4, uint32_t arg5, AudioFileInitializeWithCallbacks_T_arg6 arg6, uint32_t arg7, OpaqueAudioFileID ** arg8)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileInitializeWithCallbacks(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg6);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg7);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg8);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg6);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg7);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg8);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioFileRemoveUserData"
#pragma push_macro(FUNC_ID)
#undef AudioFileRemoveUserData
// extra usings

INTERPOSE(AudioFileRemoveUserData)(struct OpaqueAudioFileID * arg0, uint32_t arg1, uint32_t arg2)
{
    #define RUN_FUNC  int32_t ret = real::AudioFileRemoveUserData(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueAllocateBufferWithPacketDescriptions"
#pragma push_macro(FUNC_ID)
#undef AudioQueueAllocateBufferWithPacketDescriptions
// extra usings
using AudioQueueAllocateBufferWithPacketDescriptions_T_arg3 = AudioQueueBuffer **;
using AudioQueueAllocateBufferWithPacketDescriptions_T_arg3 = AudioQueueBuffer **;
INTERPOSE(AudioQueueAllocateBufferWithPacketDescriptions)(AudioQueueRef arg0, uint32_t arg1, uint32_t arg2, AudioQueueAllocateBufferWithPacketDescriptions_T_arg3 arg3)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueAllocateBufferWithPacketDescriptions(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioConverterReset"
#pragma push_macro(FUNC_ID)
#undef AudioConverterReset
// extra usings

INTERPOSE(AudioConverterReset)(AudioConverterRef arg0)
{
    #define RUN_FUNC  int32_t ret = real::AudioConverterReset(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioQueueGetPropertySize"
#pragma push_macro(FUNC_ID)
#undef AudioQueueGetPropertySize
// extra usings

INTERPOSE(AudioQueueGetPropertySize)(AudioQueueRef arg0, uint32_t arg1, UnsignedFixedPtr arg2)
{
    #define RUN_FUNC  int32_t ret = real::AudioQueueGetPropertySize(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUParameterFormatValue"
#pragma push_macro(FUNC_ID)
#undef AUParameterFormatValue
// extra usings

INTERPOSE(AUParameterFormatValue)(Float64 arg0, const AudioUnitParameter * arg1, caddr_t arg2, uint32_t arg3)
{
    #define RUN_FUNC  caddr_t ret = real::AUParameterFormatValue(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicSequenceBarBeatTimeToBeats"
#pragma push_macro(FUNC_ID)
#undef MusicSequenceBarBeatTimeToBeats
// extra usings
using MusicSequenceBarBeatTimeToBeats_T_arg2 = double *;
using MusicSequenceBarBeatTimeToBeats_T_arg2 = double *;
INTERPOSE(MusicSequenceBarBeatTimeToBeats)(MusicSequence arg0, const CABarBeatTime * arg1, MusicSequenceBarBeatTimeToBeats_T_arg2 arg2)
{
    #define RUN_FUNC  int32_t ret = real::MusicSequenceBarBeatTimeToBeats(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioHardwareServiceGetPropertyDataSize"
#pragma push_macro(FUNC_ID)
#undef AudioHardwareServiceGetPropertyDataSize
// extra usings

INTERPOSE(AudioHardwareServiceGetPropertyDataSize)(uint32_t arg0, const AudioObjectPropertyAddress * arg1, uint32_t arg2, const void * arg3, UnsignedFixedPtr arg4)
{
    #define RUN_FUNC  int32_t ret = real::AudioHardwareServiceGetPropertyDataSize(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphDisconnectNodeInput"
#pragma push_macro(FUNC_ID)
#undef AUGraphDisconnectNodeInput
// extra usings

INTERPOSE(AUGraphDisconnectNodeInput)(AUGraph arg0, int32_t arg1, uint32_t arg2)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphDisconnectNodeInput(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicEventIteratorNextEvent"
#pragma push_macro(FUNC_ID)
#undef MusicEventIteratorNextEvent
// extra usings

INTERPOSE(MusicEventIteratorNextEvent)(MusicEventIterator arg0)
{
    #define RUN_FUNC  int32_t ret = real::MusicEventIteratorNextEvent(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "ExtAudioFileDispose"
#pragma push_macro(FUNC_ID)
#undef ExtAudioFileDispose
// extra usings

INTERPOSE(ExtAudioFileDispose)(ExtAudioFileRef arg0)
{
    #define RUN_FUNC  int32_t ret = real::ExtAudioFileDispose(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioServicesRemoveSystemSoundCompletion"
#pragma push_macro(FUNC_ID)
#undef AudioServicesRemoveSystemSoundCompletion
// extra usings

INTERPOSE(AudioServicesRemoveSystemSoundCompletion)(uint32_t arg0)
{
    #define RUN_FUNC  real::AudioServicesRemoveSystemSoundCompletion(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphAddNode"
#pragma push_macro(FUNC_ID)
#undef AUGraphAddNode
// extra usings

INTERPOSE(AUGraphAddNode)(AUGraph arg0, const AudioComponentDescription * arg1, FixedPtr arg2)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphAddNode(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AUGraphIsNodeSubGraph"
#pragma push_macro(FUNC_ID)
#undef AUGraphIsNodeSubGraph
// extra usings

INTERPOSE(AUGraphIsNodeSubGraph)(AUGraph arg0, int32_t arg1, BytePtr arg2)
{
    #define RUN_FUNC  int32_t ret = real::AUGraphIsNodeSubGraph(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "AudioUnitRender"
#pragma push_macro(FUNC_ID)
#undef AudioUnitRender
// extra usings

INTERPOSE(AudioUnitRender)(AudioComponentInstance arg0, UnsignedFixedPtr arg1, const AudioTimeStamp * arg2, uint32_t arg3, uint32_t arg4, AudioBufferList * arg5)
{
    #define RUN_FUNC  int32_t ret = real::AudioUnitRender(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg5);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg3);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg4);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg5);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "MusicDeviceReleaseInstrument"
#pragma push_macro(FUNC_ID)
#undef MusicDeviceReleaseInstrument
// extra usings

INTERPOSE(MusicDeviceReleaseInstrument)(AudioComponentInstance arg0, uint32_t arg1)
{
    #define RUN_FUNC  int32_t ret = real::MusicDeviceReleaseInstrument(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg1);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

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

#define FUNC_ID "CGPDFDocumentGetVersion"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentGetVersion
// extra usings

INTERPOSE(CGPDFDocumentGetVersion)(CGPDFDocumentRef arg0, FixedPtr arg1, FixedPtr arg2)
{
    #define RUN_FUNC  real::CGPDFDocumentGetVersion(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGContextAddArcToPoint"
#pragma push_macro(FUNC_ID)
#undef CGContextAddArcToPoint
// extra usings

INTERPOSE(CGContextAddArcToPoint)(CGContextRef arg0, CGFloat arg1, CGFloat arg2, CGFloat arg3, CGFloat arg4, CGFloat arg5)
{
    #define RUN_FUNC  real::CGContextAddArcToPoint(arg0, arg1, arg2, arg3, arg4, arg5)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGDataConsumerRetain"
#pragma push_macro(FUNC_ID)
#undef CGDataConsumerRetain
// extra usings

INTERPOSE(CGDataConsumerRetain)(CGDataConsumerRef arg0)
{
    #define RUN_FUNC  CGDataConsumerRef ret = real::CGDataConsumerRetain(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGColorSpaceCreateDeviceCMYK"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceCreateDeviceCMYK
// extra usings

INTERPOSE(CGColorSpaceCreateDeviceCMYK)()
{
    #define RUN_FUNC  CGColorSpaceRef ret = real::CGColorSpaceCreateDeviceCMYK()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGGradientGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CGGradientGetTypeID
// extra usings

INTERPOSE(CGGradientGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGGradientGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGColorConversionInfoCreate"
#pragma push_macro(FUNC_ID)
#undef CGColorConversionInfoCreate
// extra usings

INTERPOSE(CGColorConversionInfoCreate)(CGColorSpaceRef arg0, CGColorSpaceRef arg1)
{
    #define RUN_FUNC  CGColorConversionInfoRef ret = real::CGColorConversionInfoCreate(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFPageGetDrawingTransform"
#pragma push_macro(FUNC_ID)
#undef CGPDFPageGetDrawingTransform
// extra usings

INTERPOSE(CGPDFPageGetDrawingTransform)(CGPDFPageRef arg0, __int32_t arg1, CGRect arg2, __int32_t arg3, bool arg4)
{
    #define RUN_FUNC  CGAffineTransform ret = real::CGPDFPageGetDrawingTransform(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGFontCanCreatePostScriptSubset"
#pragma push_macro(FUNC_ID)
#undef CGFontCanCreatePostScriptSubset
// extra usings

INTERPOSE(CGFontCanCreatePostScriptSubset)(CGFontRef arg0, __int32_t arg1)
{
    #define RUN_FUNC  bool ret = real::CGFontCanCreatePostScriptSubset(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextSetStrokeColorSpace"
#pragma push_macro(FUNC_ID)
#undef CGContextSetStrokeColorSpace
// extra usings

INTERPOSE(CGContextSetStrokeColorSpace)(CGContextRef arg0, CGColorSpaceRef arg1)
{
    #define RUN_FUNC  real::CGContextSetStrokeColorSpace(arg0, arg1)

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

#define FUNC_ID "CGContextPathContainsPoint"
#pragma push_macro(FUNC_ID)
#undef CGContextPathContainsPoint
// extra usings

INTERPOSE(CGContextPathContainsPoint)(CGContextRef arg0, CGPoint arg1, __int32_t arg2)
{
    #define RUN_FUNC  bool ret = real::CGContextPathContainsPoint(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGAffineTransformRotate"
#pragma push_macro(FUNC_ID)
#undef CGAffineTransformRotate
// extra usings

INTERPOSE(CGAffineTransformRotate)(CGAffineTransform arg0, CGFloat arg1)
{
    #define RUN_FUNC  CGAffineTransform ret = real::CGAffineTransformRotate(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextRelease"
#pragma push_macro(FUNC_ID)
#undef CGContextRelease
// extra usings

INTERPOSE(CGContextRelease)(CGContextRef arg0)
{
    #define RUN_FUNC  real::CGContextRelease(arg0)

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

#define FUNC_ID "CGPDFArrayGetStream"
#pragma push_macro(FUNC_ID)
#undef CGPDFArrayGetStream
// extra usings
using CGPDFArrayGetStream_T_arg2 = CGPDFStream **;
using CGPDFArrayGetStream_T_arg2 = CGPDFStream **;
INTERPOSE(CGPDFArrayGetStream)(CGPDFArrayRef arg0, __darwin_size_t arg1, CGPDFArrayGetStream_T_arg2 arg2)
{
    #define RUN_FUNC  bool ret = real::CGPDFArrayGetStream(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFDictionaryGetStream"
#pragma push_macro(FUNC_ID)
#undef CGPDFDictionaryGetStream
// extra usings
using CGPDFDictionaryGetStream_T_arg2 = CGPDFStream **;
using CGPDFDictionaryGetStream_T_arg2 = CGPDFStream **;
INTERPOSE(CGPDFDictionaryGetStream)(CGPDFDictionaryRef arg0, const char * arg1, CGPDFDictionaryGetStream_T_arg2 arg2)
{
    #define RUN_FUNC  bool ret = real::CGPDFDictionaryGetStream(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGDisplayModeGetRefreshRate"
#pragma push_macro(FUNC_ID)
#undef CGDisplayModeGetRefreshRate
// extra usings

INTERPOSE(CGDisplayModeGetRefreshRate)(CGDisplayModeRef arg0)
{
    #define RUN_FUNC  CGFloat ret = real::CGDisplayModeGetRefreshRate(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGAffineTransformMake"
#pragma push_macro(FUNC_ID)
#undef CGAffineTransformMake
// extra usings

INTERPOSE(CGAffineTransformMake)(CGFloat arg0, CGFloat arg1, CGFloat arg2, CGFloat arg3, CGFloat arg4, CGFloat arg5)
{
    #define RUN_FUNC  CGAffineTransform ret = real::CGAffineTransformMake(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextAddLines"
#pragma push_macro(FUNC_ID)
#undef CGContextAddLines
// extra usings
using CGContextAddLines_T_arg1 = const CGPoint *;
using CGContextAddLines_T_arg1 = const CGPoint *;
INTERPOSE(CGContextAddLines)(CGContextRef arg0, CGContextAddLines_T_arg1 arg1, __darwin_size_t arg2)
{
    #define RUN_FUNC  real::CGContextAddLines(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGContextSetTextPosition"
#pragma push_macro(FUNC_ID)
#undef CGContextSetTextPosition
// extra usings

INTERPOSE(CGContextSetTextPosition)(CGContextRef arg0, CGFloat arg1, CGFloat arg2)
{
    #define RUN_FUNC  real::CGContextSetTextPosition(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGColorCreateSRGB"
#pragma push_macro(FUNC_ID)
#undef CGColorCreateSRGB
// extra usings

INTERPOSE(CGColorCreateSRGB)(CGFloat arg0, CGFloat arg1, CGFloat arg2, CGFloat arg3)
{
    #define RUN_FUNC  CGColorRef ret = real::CGColorCreateSRGB(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextGetTextPosition"
#pragma push_macro(FUNC_ID)
#undef CGContextGetTextPosition
// extra usings

INTERPOSE(CGContextGetTextPosition)(CGContextRef arg0)
{
    #define RUN_FUNC  CGPoint ret = real::CGContextGetTextPosition(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFPageGetRotationAngle"
#pragma push_macro(FUNC_ID)
#undef CGPDFPageGetRotationAngle
// extra usings

INTERPOSE(CGPDFPageGetRotationAngle)(CGPDFPageRef arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGPDFPageGetRotationAngle(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextGetPathBoundingBox"
#pragma push_macro(FUNC_ID)
#undef CGContextGetPathBoundingBox
// extra usings

INTERPOSE(CGContextGetPathBoundingBox)(CGContextRef arg0)
{
    #define RUN_FUNC  CGRect ret = real::CGContextGetPathBoundingBox(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGRectContainsPoint"
#pragma push_macro(FUNC_ID)
#undef CGRectContainsPoint
// extra usings

INTERPOSE(CGRectContainsPoint)(CGRect arg0, CGPoint arg1)
{
    #define RUN_FUNC  bool ret = real::CGRectContainsPoint(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFDictionaryGetCount"
#pragma push_macro(FUNC_ID)
#undef CGPDFDictionaryGetCount
// extra usings

INTERPOSE(CGPDFDictionaryGetCount)(CGPDFDictionaryRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGPDFDictionaryGetCount(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGRectMake"
#pragma push_macro(FUNC_ID)
#undef CGRectMake
// extra usings

INTERPOSE(CGRectMake)(CGFloat arg0, CGFloat arg1, CGFloat arg2, CGFloat arg3)
{
    #define RUN_FUNC  CGRect ret = real::CGRectMake(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGColorSpaceRetain"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceRetain
// extra usings

INTERPOSE(CGColorSpaceRetain)(CGColorSpaceRef arg0)
{
    #define RUN_FUNC  CGColorSpaceRef ret = real::CGColorSpaceRetain(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPathCreateCopyByStrokingPath"
#pragma push_macro(FUNC_ID)
#undef CGPathCreateCopyByStrokingPath
// extra usings
using CGPathCreateCopyByStrokingPath_T_arg1 = const CGAffineTransform *;
using CGPathCreateCopyByStrokingPath_T_arg1 = const CGAffineTransform *;
INTERPOSE(CGPathCreateCopyByStrokingPath)(CGPathRef arg0, CGPathCreateCopyByStrokingPath_T_arg1 arg1, CGFloat arg2, __int32_t arg3, __int32_t arg4, CGFloat arg5)
{
    #define RUN_FUNC  CGPathRef ret = real::CGPathCreateCopyByStrokingPath(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextAddEllipseInRect"
#pragma push_macro(FUNC_ID)
#undef CGContextAddEllipseInRect
// extra usings

INTERPOSE(CGContextAddEllipseInRect)(CGContextRef arg0, CGRect arg1)
{
    #define RUN_FUNC  real::CGContextAddEllipseInRect(arg0, arg1)

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

#define FUNC_ID "CGContextEndTransparencyLayer"
#pragma push_macro(FUNC_ID)
#undef CGContextEndTransparencyLayer
// extra usings

INTERPOSE(CGContextEndTransparencyLayer)(CGContextRef arg0)
{
    #define RUN_FUNC  real::CGContextEndTransparencyLayer(arg0)

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

#define FUNC_ID "CGContextSelectFont"
#pragma push_macro(FUNC_ID)
#undef CGContextSelectFont
// extra usings

INTERPOSE(CGContextSelectFont)(CGContextRef arg0, const char * arg1, CGFloat arg2, __int32_t arg3)
{
    #define RUN_FUNC  real::CGContextSelectFont(arg0, arg1, arg2, arg3)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGLayerGetSize"
#pragma push_macro(FUNC_ID)
#undef CGLayerGetSize
// extra usings

INTERPOSE(CGLayerGetSize)(CGLayerRef arg0)
{
    #define RUN_FUNC  CGSize ret = real::CGLayerGetSize(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGSizeEqualToSize"
#pragma push_macro(FUNC_ID)
#undef CGSizeEqualToSize
// extra usings

INTERPOSE(CGSizeEqualToSize)(CGSize arg0, CGSize arg1)
{
    #define RUN_FUNC  bool ret = real::CGSizeEqualToSize(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFStringCopyTextString"
#pragma push_macro(FUNC_ID)
#undef CGPDFStringCopyTextString
// extra usings

INTERPOSE(CGPDFStringCopyTextString)(CGPDFStringRef arg0)
{
    #define RUN_FUNC  CFStringRef ret = real::CGPDFStringCopyTextString(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGColorSpaceGetBaseColorSpace"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceGetBaseColorSpace
// extra usings

INTERPOSE(CGColorSpaceGetBaseColorSpace)(CGColorSpaceRef arg0)
{
    #define RUN_FUNC  CGColorSpaceRef ret = real::CGColorSpaceGetBaseColorSpace(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPathCreateMutable"
#pragma push_macro(FUNC_ID)
#undef CGPathCreateMutable
// extra usings

INTERPOSE(CGPathCreateMutable)()
{
    #define RUN_FUNC  CGMutablePathRef ret = real::CGPathCreateMutable()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGBitmapContextGetHeight"
#pragma push_macro(FUNC_ID)
#undef CGBitmapContextGetHeight
// extra usings

INTERPOSE(CGBitmapContextGetHeight)(CGContextRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGBitmapContextGetHeight(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFPageGetBoxRect"
#pragma push_macro(FUNC_ID)
#undef CGPDFPageGetBoxRect
// extra usings

INTERPOSE(CGPDFPageGetBoxRect)(CGPDFPageRef arg0, __int32_t arg1)
{
    #define RUN_FUNC  CGRect ret = real::CGPDFPageGetBoxRect(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFStringCopyDate"
#pragma push_macro(FUNC_ID)
#undef CGPDFStringCopyDate
// extra usings

INTERPOSE(CGPDFStringCopyDate)(CGPDFStringRef arg0)
{
    #define RUN_FUNC  CFDateRef ret = real::CGPDFStringCopyDate(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayStreamUpdateGetDropCount"
#pragma push_macro(FUNC_ID)
#undef CGDisplayStreamUpdateGetDropCount
// extra usings

INTERPOSE(CGDisplayStreamUpdateGetDropCount)(CGDisplayStreamUpdateRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGDisplayStreamUpdateGetDropCount(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayBestModeForParametersAndRefreshRate"
#pragma push_macro(FUNC_ID)
#undef CGDisplayBestModeForParametersAndRefreshRate
// extra usings

INTERPOSE(CGDisplayBestModeForParametersAndRefreshRate)(__uint32_t arg0, __darwin_size_t arg1, __darwin_size_t arg2, __darwin_size_t arg3, CGFloat arg4, UnsignedFixedPtr arg5)
{
    #define RUN_FUNC  CFDictionaryRef ret = real::CGDisplayBestModeForParametersAndRefreshRate(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFScannerPopString"
#pragma push_macro(FUNC_ID)
#undef CGPDFScannerPopString
// extra usings
using CGPDFScannerPopString_T_arg1 = CGPDFString **;
using CGPDFScannerPopString_T_arg1 = CGPDFString **;
INTERPOSE(CGPDFScannerPopString)(CGPDFScannerRef arg0, CGPDFScannerPopString_T_arg1 arg1)
{
    #define RUN_FUNC  bool ret = real::CGPDFScannerPopString(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFPageGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CGPDFPageGetTypeID
// extra usings

INTERPOSE(CGPDFPageGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGPDFPageGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGContextAddRect"
#pragma push_macro(FUNC_ID)
#undef CGContextAddRect
// extra usings

INTERPOSE(CGContextAddRect)(CGContextRef arg0, CGRect arg1)
{
    #define RUN_FUNC  real::CGContextAddRect(arg0, arg1)

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

#define FUNC_ID "CGDataProviderCreateWithURL"
#pragma push_macro(FUNC_ID)
#undef CGDataProviderCreateWithURL
// extra usings

INTERPOSE(CGDataProviderCreateWithURL)(CFURLRef arg0)
{
    #define RUN_FUNC  CGDataProviderRef ret = real::CGDataProviderCreateWithURL(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFScannerCreate"
#pragma push_macro(FUNC_ID)
#undef CGPDFScannerCreate
// extra usings

INTERPOSE(CGPDFScannerCreate)(CGPDFContentStreamRef arg0, CGPDFOperatorTableRef arg1, void * arg2)
{
    #define RUN_FUNC  CGPDFScannerRef ret = real::CGPDFScannerCreate(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGConfigureDisplayFadeEffect"
#pragma push_macro(FUNC_ID)
#undef CGConfigureDisplayFadeEffect
// extra usings

INTERPOSE(CGConfigureDisplayFadeEffect)(CGDisplayConfigRef arg0, Float32 arg1, Float32 arg2, Float32 arg3, Float32 arg4, Float32 arg5)
{
    #define RUN_FUNC  __int32_t ret = real::CGConfigureDisplayFadeEffect(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGDisplayFade"
#pragma push_macro(FUNC_ID)
#undef CGDisplayFade
// extra usings

INTERPOSE(CGDisplayFade)(__uint32_t arg0, Float32 arg1, Float32 arg2, Float32 arg3, Float32 arg4, Float32 arg5, Float32 arg6, __uint32_t arg7)
{
    #define RUN_FUNC  __int32_t ret = real::CGDisplayFade(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFArrayGetObject"
#pragma push_macro(FUNC_ID)
#undef CGPDFArrayGetObject
// extra usings
using CGPDFArrayGetObject_T_arg2 = CGPDFObject **;
using CGPDFArrayGetObject_T_arg2 = CGPDFObject **;
INTERPOSE(CGPDFArrayGetObject)(CGPDFArrayRef arg0, __darwin_size_t arg1, CGPDFArrayGetObject_T_arg2 arg2)
{
    #define RUN_FUNC  bool ret = real::CGPDFArrayGetObject(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGLayerGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CGLayerGetTypeID
// extra usings

INTERPOSE(CGLayerGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGLayerGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGDataProviderCreateWithFilename"
#pragma push_macro(FUNC_ID)
#undef CGDataProviderCreateWithFilename
// extra usings

INTERPOSE(CGDataProviderCreateWithFilename)(const char * arg0)
{
    #define RUN_FUNC  CGDataProviderRef ret = real::CGDataProviderCreateWithFilename(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGColorGetComponents"
#pragma push_macro(FUNC_ID)
#undef CGColorGetComponents
// extra usings

INTERPOSE(CGColorGetComponents)(CGColorRef arg0)
{
    #define RUN_FUNC  const double * ret = real::CGColorGetComponents(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGAffineTransformMakeTranslation"
#pragma push_macro(FUNC_ID)
#undef CGAffineTransformMakeTranslation
// extra usings

INTERPOSE(CGAffineTransformMakeTranslation)(CGFloat arg0, CGFloat arg1)
{
    #define RUN_FUNC  CGAffineTransform ret = real::CGAffineTransformMakeTranslation(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGSizeMake"
#pragma push_macro(FUNC_ID)
#undef CGSizeMake
// extra usings

INTERPOSE(CGSizeMake)(CGFloat arg0, CGFloat arg1)
{
    #define RUN_FUNC  CGSize ret = real::CGSizeMake(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGDisplayVendorNumber"
#pragma push_macro(FUNC_ID)
#undef CGDisplayVendorNumber
// extra usings

INTERPOSE(CGDisplayVendorNumber)(__uint32_t arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGDisplayVendorNumber(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFContextBeginTag"
#pragma push_macro(FUNC_ID)
#undef CGPDFContextBeginTag
// extra usings

INTERPOSE(CGPDFContextBeginTag)(CGContextRef arg0, __int32_t arg1, CFDictionaryRef arg2)
{
    #define RUN_FUNC  real::CGPDFContextBeginTag(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPDFDocumentGetID"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentGetID
// extra usings

INTERPOSE(CGPDFDocumentGetID)(CGPDFDocumentRef arg0)
{
    #define RUN_FUNC  CGPDFArrayRef ret = real::CGPDFDocumentGetID(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDataProviderCreateWithData"
#pragma push_macro(FUNC_ID)
#undef CGDataProviderCreateWithData
// extra usings

INTERPOSE(CGDataProviderCreateWithData)(void * arg0, const void * arg1, __darwin_size_t arg2, CGDataProviderReleaseDataCallback arg3)
{
    #define RUN_FUNC  CGDataProviderRef ret = real::CGDataProviderCreateWithData(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGColorSpaceCreatePattern"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceCreatePattern
// extra usings

INTERPOSE(CGColorSpaceCreatePattern)(CGColorSpaceRef arg0)
{
    #define RUN_FUNC  CGColorSpaceRef ret = real::CGColorSpaceCreatePattern(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextSynchronize"
#pragma push_macro(FUNC_ID)
#undef CGContextSynchronize
// extra usings

INTERPOSE(CGContextSynchronize)(CGContextRef arg0)
{
    #define RUN_FUNC  real::CGContextSynchronize(arg0)

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

#define FUNC_ID "CGDisplayModeGetIODisplayModeID"
#pragma push_macro(FUNC_ID)
#undef CGDisplayModeGetIODisplayModeID
// extra usings

INTERPOSE(CGDisplayModeGetIODisplayModeID)(CGDisplayModeRef arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGDisplayModeGetIODisplayModeID(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGFontGetGlyphBBoxes"
#pragma push_macro(FUNC_ID)
#undef CGFontGetGlyphBBoxes
// extra usings

INTERPOSE(CGFontGetGlyphBBoxes)(CGFontRef arg0, const unsigned short * arg1, __darwin_size_t arg2, CGRect * arg3)
{
    #define RUN_FUNC  bool ret = real::CGFontGetGlyphBBoxes(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFContentStreamGetResource"
#pragma push_macro(FUNC_ID)
#undef CGPDFContentStreamGetResource
// extra usings

INTERPOSE(CGPDFContentStreamGetResource)(CGPDFContentStreamRef arg0, const char * arg1, const char * arg2)
{
    #define RUN_FUNC  CGPDFObjectRef ret = real::CGPDFContentStreamGetResource(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGAffineTransformMakeRotation"
#pragma push_macro(FUNC_ID)
#undef CGAffineTransformMakeRotation
// extra usings

INTERPOSE(CGAffineTransformMakeRotation)(CGFloat arg0)
{
    #define RUN_FUNC  CGAffineTransform ret = real::CGAffineTransformMakeRotation(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGGradientRetain"
#pragma push_macro(FUNC_ID)
#undef CGGradientRetain
// extra usings

INTERPOSE(CGGradientRetain)(CGGradientRef arg0)
{
    #define RUN_FUNC  CGGradientRef ret = real::CGGradientRetain(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayCreateImageForRect"
#pragma push_macro(FUNC_ID)
#undef CGDisplayCreateImageForRect
// extra usings

INTERPOSE(CGDisplayCreateImageForRect)(__uint32_t arg0, CGRect arg1)
{
    #define RUN_FUNC  CGImageRef ret = real::CGDisplayCreateImageForRect(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGImageGetWidth"
#pragma push_macro(FUNC_ID)
#undef CGImageGetWidth
// extra usings

INTERPOSE(CGImageGetWidth)(CGImageRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGImageGetWidth(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFDocumentIsUnlocked"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentIsUnlocked
// extra usings

INTERPOSE(CGPDFDocumentIsUnlocked)(CGPDFDocumentRef arg0)
{
    #define RUN_FUNC  bool ret = real::CGPDFDocumentIsUnlocked(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPathCreateWithRect"
#pragma push_macro(FUNC_ID)
#undef CGPathCreateWithRect
// extra usings
using CGPathCreateWithRect_T_arg1 = const CGAffineTransform *;
using CGPathCreateWithRect_T_arg1 = const CGAffineTransform *;
INTERPOSE(CGPathCreateWithRect)(CGRect arg0, CGPathCreateWithRect_T_arg1 arg1)
{
    #define RUN_FUNC  CGPathRef ret = real::CGPathCreateWithRect(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGImageGetBitmapInfo"
#pragma push_macro(FUNC_ID)
#undef CGImageGetBitmapInfo
// extra usings

INTERPOSE(CGImageGetBitmapInfo)(CGImageRef arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGImageGetBitmapInfo(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayRegisterReconfigurationCallback"
#pragma push_macro(FUNC_ID)
#undef CGDisplayRegisterReconfigurationCallback
// extra usings

INTERPOSE(CGDisplayRegisterReconfigurationCallback)(CGDisplayReconfigurationCallBack arg0, void * arg1)
{
    #define RUN_FUNC  __int32_t ret = real::CGDisplayRegisterReconfigurationCallback(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGFontGetItalicAngle"
#pragma push_macro(FUNC_ID)
#undef CGFontGetItalicAngle
// extra usings

INTERPOSE(CGFontGetItalicAngle)(CGFontRef arg0)
{
    #define RUN_FUNC  CGFloat ret = real::CGFontGetItalicAngle(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDataProviderGetInfo"
#pragma push_macro(FUNC_ID)
#undef CGDataProviderGetInfo
// extra usings

INTERPOSE(CGDataProviderGetInfo)(CGDataProviderRef arg0)
{
    #define RUN_FUNC  void * ret = real::CGDataProviderGetInfo(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextSetAllowsFontSmoothing"
#pragma push_macro(FUNC_ID)
#undef CGContextSetAllowsFontSmoothing
// extra usings

INTERPOSE(CGContextSetAllowsFontSmoothing)(CGContextRef arg0, bool arg1)
{
    #define RUN_FUNC  real::CGContextSetAllowsFontSmoothing(arg0, arg1)

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

#define FUNC_ID "CGDisplayUsesOpenGLAcceleration"
#pragma push_macro(FUNC_ID)
#undef CGDisplayUsesOpenGLAcceleration
// extra usings

INTERPOSE(CGDisplayUsesOpenGLAcceleration)(__uint32_t arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGDisplayUsesOpenGLAcceleration(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPointMakeWithDictionaryRepresentation"
#pragma push_macro(FUNC_ID)
#undef CGPointMakeWithDictionaryRepresentation
// extra usings

INTERPOSE(CGPointMakeWithDictionaryRepresentation)(CFDictionaryRef arg0, CGPoint * arg1)
{
    #define RUN_FUNC  bool ret = real::CGPointMakeWithDictionaryRepresentation(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextResetClip"
#pragma push_macro(FUNC_ID)
#undef CGContextResetClip
// extra usings

INTERPOSE(CGContextResetClip)(CGContextRef arg0)
{
    #define RUN_FUNC  real::CGContextResetClip(arg0)

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

#define FUNC_ID "CGPDFDictionaryApplyFunction"
#pragma push_macro(FUNC_ID)
#undef CGPDFDictionaryApplyFunction
// extra usings

INTERPOSE(CGPDFDictionaryApplyFunction)(CGPDFDictionaryRef arg0, CGPDFDictionaryApplierFunction arg1, void * arg2)
{
    #define RUN_FUNC  real::CGPDFDictionaryApplyFunction(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGWindowServerCreateServerPort"
#pragma push_macro(FUNC_ID)
#undef CGWindowServerCreateServerPort
// extra usings

INTERPOSE(CGWindowServerCreateServerPort)()
{
    #define RUN_FUNC  CFMachPortRef ret = real::CGWindowServerCreateServerPort()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPathAddEllipseInRect"
#pragma push_macro(FUNC_ID)
#undef CGPathAddEllipseInRect
// extra usings
using CGPathAddEllipseInRect_T_arg1 = const CGAffineTransform *;
using CGPathAddEllipseInRect_T_arg1 = const CGAffineTransform *;
INTERPOSE(CGPathAddEllipseInRect)(CGMutablePathRef arg0, CGPathAddEllipseInRect_T_arg1 arg1, CGRect arg2)
{
    #define RUN_FUNC  real::CGPathAddEllipseInRect(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGColorSpaceGetColorTableCount"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceGetColorTableCount
// extra usings

INTERPOSE(CGColorSpaceGetColorTableCount)(CGColorSpaceRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGColorSpaceGetColorTableCount(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextClearRect"
#pragma push_macro(FUNC_ID)
#undef CGContextClearRect
// extra usings

INTERPOSE(CGContextClearRect)(CGContextRef arg0, CGRect arg1)
{
    #define RUN_FUNC  real::CGContextClearRect(arg0, arg1)

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

#define FUNC_ID "CGPDFDocumentGetAccessPermissions"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentGetAccessPermissions
// extra usings

INTERPOSE(CGPDFDocumentGetAccessPermissions)(CGPDFDocumentRef arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGPDFDocumentGetAccessPermissions(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGBitmapContextGetBitmapInfo"
#pragma push_macro(FUNC_ID)
#undef CGBitmapContextGetBitmapInfo
// extra usings

INTERPOSE(CGBitmapContextGetBitmapInfo)(CGContextRef arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGBitmapContextGetBitmapInfo(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPathAddQuadCurveToPoint"
#pragma push_macro(FUNC_ID)
#undef CGPathAddQuadCurveToPoint
// extra usings
using CGPathAddQuadCurveToPoint_T_arg1 = const CGAffineTransform *;
using CGPathAddQuadCurveToPoint_T_arg1 = const CGAffineTransform *;
INTERPOSE(CGPathAddQuadCurveToPoint)(CGMutablePathRef arg0, CGPathAddQuadCurveToPoint_T_arg1 arg1, CGFloat arg2, CGFloat arg3, CGFloat arg4, CGFloat arg5)
{
    #define RUN_FUNC  real::CGPathAddQuadCurveToPoint(arg0, arg1, arg2, arg3, arg4, arg5)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGColorSpaceCreateDeviceGray"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceCreateDeviceGray
// extra usings

INTERPOSE(CGColorSpaceCreateDeviceGray)()
{
    #define RUN_FUNC  CGColorSpaceRef ret = real::CGColorSpaceCreateDeviceGray()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPDFPageGetDocument"
#pragma push_macro(FUNC_ID)
#undef CGPDFPageGetDocument
// extra usings

INTERPOSE(CGPDFPageGetDocument)(CGPDFPageRef arg0)
{
    #define RUN_FUNC  CGPDFDocumentRef ret = real::CGPDFPageGetDocument(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGRestorePermanentDisplayConfiguration"
#pragma push_macro(FUNC_ID)
#undef CGRestorePermanentDisplayConfiguration
// extra usings

INTERPOSE(CGRestorePermanentDisplayConfiguration)()
{
    #define RUN_FUNC  real::CGRestorePermanentDisplayConfiguration()

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
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGImageGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CGImageGetTypeID
// extra usings

INTERPOSE(CGImageGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGImageGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGFontCreatePostScriptEncoding"
#pragma push_macro(FUNC_ID)
#undef CGFontCreatePostScriptEncoding
// extra usings

INTERPOSE(CGFontCreatePostScriptEncoding)(CGFontRef arg0, const unsigned short * arg1)
{
    #define RUN_FUNC  CFDataRef ret = real::CGFontCreatePostScriptEncoding(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGFontGetStemV"
#pragma push_macro(FUNC_ID)
#undef CGFontGetStemV
// extra usings

INTERPOSE(CGFontGetStemV)(CGFontRef arg0)
{
    #define RUN_FUNC  CGFloat ret = real::CGFontGetStemV(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPointApplyAffineTransform"
#pragma push_macro(FUNC_ID)
#undef CGPointApplyAffineTransform
// extra usings

INTERPOSE(CGPointApplyAffineTransform)(CGPoint arg0, CGAffineTransform arg1)
{
    #define RUN_FUNC  CGPoint ret = real::CGPointApplyAffineTransform(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGRectStandardize"
#pragma push_macro(FUNC_ID)
#undef CGRectStandardize
// extra usings

INTERPOSE(CGRectStandardize)(CGRect arg0)
{
    #define RUN_FUNC  CGRect ret = real::CGRectStandardize(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPathAddLineToPoint"
#pragma push_macro(FUNC_ID)
#undef CGPathAddLineToPoint
// extra usings
using CGPathAddLineToPoint_T_arg1 = const CGAffineTransform *;
using CGPathAddLineToPoint_T_arg1 = const CGAffineTransform *;
INTERPOSE(CGPathAddLineToPoint)(CGMutablePathRef arg0, CGPathAddLineToPoint_T_arg1 arg1, CGFloat arg2, CGFloat arg3)
{
    #define RUN_FUNC  real::CGPathAddLineToPoint(arg0, arg1, arg2, arg3)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGDataProviderCopyData"
#pragma push_macro(FUNC_ID)
#undef CGDataProviderCopyData
// extra usings

INTERPOSE(CGDataProviderCopyData)(CGDataProviderRef arg0)
{
    #define RUN_FUNC  CFDataRef ret = real::CGDataProviderCopyData(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGColorCreateGenericGray"
#pragma push_macro(FUNC_ID)
#undef CGColorCreateGenericGray
// extra usings

INTERPOSE(CGColorCreateGenericGray)(CGFloat arg0, CGFloat arg1)
{
    #define RUN_FUNC  CGColorRef ret = real::CGColorCreateGenericGray(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGColorSpaceIsWideGamutRGB"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceIsWideGamutRGB
// extra usings

INTERPOSE(CGColorSpaceIsWideGamutRGB)(CGColorSpaceRef arg0)
{
    #define RUN_FUNC  bool ret = real::CGColorSpaceIsWideGamutRGB(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPSConverterGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CGPSConverterGetTypeID
// extra usings

INTERPOSE(CGPSConverterGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGPSConverterGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGColorRetain"
#pragma push_macro(FUNC_ID)
#undef CGColorRetain
// extra usings

INTERPOSE(CGColorRetain)(CGColorRef arg0)
{
    #define RUN_FUNC  CGColorRef ret = real::CGColorRetain(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGColorCreateGenericCMYK"
#pragma push_macro(FUNC_ID)
#undef CGColorCreateGenericCMYK
// extra usings

INTERPOSE(CGColorCreateGenericCMYK)(CGFloat arg0, CGFloat arg1, CGFloat arg2, CGFloat arg3, CGFloat arg4)
{
    #define RUN_FUNC  CGColorRef ret = real::CGColorCreateGenericCMYK(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGBeginDisplayConfiguration"
#pragma push_macro(FUNC_ID)
#undef CGBeginDisplayConfiguration
// extra usings
using CGBeginDisplayConfiguration_T_arg0 = _CGDisplayConfigRef **;
using CGBeginDisplayConfiguration_T_arg0 = _CGDisplayConfigRef **;
INTERPOSE(CGBeginDisplayConfiguration)(CGBeginDisplayConfiguration_T_arg0 arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGBeginDisplayConfiguration(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayStreamGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CGDisplayStreamGetTypeID
// extra usings

INTERPOSE(CGDisplayStreamGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGDisplayStreamGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGBitmapContextGetBitsPerPixel"
#pragma push_macro(FUNC_ID)
#undef CGBitmapContextGetBitsPerPixel
// extra usings

INTERPOSE(CGBitmapContextGetBitsPerPixel)(CGContextRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGBitmapContextGetBitsPerPixel(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFDictionaryGetArray"
#pragma push_macro(FUNC_ID)
#undef CGPDFDictionaryGetArray
// extra usings
using CGPDFDictionaryGetArray_T_arg2 = CGPDFArray **;
using CGPDFDictionaryGetArray_T_arg2 = CGPDFArray **;
INTERPOSE(CGPDFDictionaryGetArray)(CGPDFDictionaryRef arg0, const char * arg1, CGPDFDictionaryGetArray_T_arg2 arg2)
{
    #define RUN_FUNC  bool ret = real::CGPDFDictionaryGetArray(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGColorSpaceCreateWithPlatformColorSpace"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceCreateWithPlatformColorSpace
// extra usings

INTERPOSE(CGColorSpaceCreateWithPlatformColorSpace)(const void * arg0)
{
    #define RUN_FUNC  CGColorSpaceRef ret = real::CGColorSpaceCreateWithPlatformColorSpace(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextSetCMYKStrokeColor"
#pragma push_macro(FUNC_ID)
#undef CGContextSetCMYKStrokeColor
// extra usings

INTERPOSE(CGContextSetCMYKStrokeColor)(CGContextRef arg0, CGFloat arg1, CGFloat arg2, CGFloat arg3, CGFloat arg4, CGFloat arg5)
{
    #define RUN_FUNC  real::CGContextSetCMYKStrokeColor(arg0, arg1, arg2, arg3, arg4, arg5)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGDisplayStreamGetRunLoopSource"
#pragma push_macro(FUNC_ID)
#undef CGDisplayStreamGetRunLoopSource
// extra usings

INTERPOSE(CGDisplayStreamGetRunLoopSource)(CGDisplayStreamRef arg0)
{
    #define RUN_FUNC  CFRunLoopSourceRef ret = real::CGDisplayStreamGetRunLoopSource(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextEndPage"
#pragma push_macro(FUNC_ID)
#undef CGContextEndPage
// extra usings

INTERPOSE(CGContextEndPage)(CGContextRef arg0)
{
    #define RUN_FUNC  real::CGContextEndPage(arg0)

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

#define FUNC_ID "CGUnregisterScreenRefreshCallback"
#pragma push_macro(FUNC_ID)
#undef CGUnregisterScreenRefreshCallback
// extra usings

INTERPOSE(CGUnregisterScreenRefreshCallback)(CGScreenRefreshCallback arg0, void * arg1)
{
    #define RUN_FUNC  real::CGUnregisterScreenRefreshCallback(arg0, arg1)

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

#define FUNC_ID "CGPDFContentStreamRelease"
#pragma push_macro(FUNC_ID)
#undef CGPDFContentStreamRelease
// extra usings

INTERPOSE(CGPDFContentStreamRelease)(CGPDFContentStreamRef arg0)
{
    #define RUN_FUNC  real::CGPDFContentStreamRelease(arg0)

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

#define FUNC_ID "CGContextGetCTM"
#pragma push_macro(FUNC_ID)
#undef CGContextGetCTM
// extra usings

INTERPOSE(CGContextGetCTM)(CGContextRef arg0)
{
    #define RUN_FUNC  CGAffineTransform ret = real::CGContextGetCTM(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayStreamUpdateGetRects"
#pragma push_macro(FUNC_ID)
#undef CGDisplayStreamUpdateGetRects
// extra usings
using CGDisplayStreamUpdateGetRects_T_ret = const CGRect *;
using CGDisplayStreamUpdateGetRects_T_ret = const CGRect *;
INTERPOSE(CGDisplayStreamUpdateGetRects)(CGDisplayStreamUpdateRef arg0, __int32_t arg1, UniCharCountPtr arg2)
{
    #define RUN_FUNC  CGDisplayStreamUpdateGetRects_T_ret ret = real::CGDisplayStreamUpdateGetRects(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFArrayGetName"
#pragma push_macro(FUNC_ID)
#undef CGPDFArrayGetName
// extra usings

INTERPOSE(CGPDFArrayGetName)(CGPDFArrayRef arg0, __darwin_size_t arg1, const char ** arg2)
{
    #define RUN_FUNC  bool ret = real::CGPDFArrayGetName(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGDisplayStreamUpdateGetMovedRectsDelta"
#pragma push_macro(FUNC_ID)
#undef CGDisplayStreamUpdateGetMovedRectsDelta
// extra usings
using CGDisplayStreamUpdateGetMovedRectsDelta_T_arg1 = double *;
using CGDisplayStreamUpdateGetMovedRectsDelta_T_arg2 = double *;
using CGDisplayStreamUpdateGetMovedRectsDelta_T_arg1 = double *;
using CGDisplayStreamUpdateGetMovedRectsDelta_T_arg2 = double *;
INTERPOSE(CGDisplayStreamUpdateGetMovedRectsDelta)(CGDisplayStreamUpdateRef arg0, CGDisplayStreamUpdateGetMovedRectsDelta_T_arg1 arg1, CGDisplayStreamUpdateGetMovedRectsDelta_T_arg2 arg2)
{
    #define RUN_FUNC  real::CGDisplayStreamUpdateGetMovedRectsDelta(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGFontGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CGFontGetTypeID
// extra usings

INTERPOSE(CGFontGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGFontGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPDFContextSetOutline"
#pragma push_macro(FUNC_ID)
#undef CGPDFContextSetOutline
// extra usings

INTERPOSE(CGPDFContextSetOutline)(CGContextRef arg0, CFDictionaryRef arg1)
{
    #define RUN_FUNC  real::CGPDFContextSetOutline(arg0, arg1)

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

#define FUNC_ID "CGDataProviderCreateWithCFData"
#pragma push_macro(FUNC_ID)
#undef CGDataProviderCreateWithCFData
// extra usings

INTERPOSE(CGDataProviderCreateWithCFData)(CFDataRef arg0)
{
    #define RUN_FUNC  CGDataProviderRef ret = real::CGDataProviderCreateWithCFData(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGShieldingWindowLevel"
#pragma push_macro(FUNC_ID)
#undef CGShieldingWindowLevel
// extra usings

INTERPOSE(CGShieldingWindowLevel)()
{
    #define RUN_FUNC  __int32_t ret = real::CGShieldingWindowLevel()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGDisplayIsOnline"
#pragma push_macro(FUNC_ID)
#undef CGDisplayIsOnline
// extra usings

INTERPOSE(CGDisplayIsOnline)(__uint32_t arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGDisplayIsOnline(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayStreamCreate"
#pragma push_macro(FUNC_ID)
#undef CGDisplayStreamCreate
// extra usings

INTERPOSE(CGDisplayStreamCreate)(__uint32_t arg0, __darwin_size_t arg1, __darwin_size_t arg2, __int32_t arg3, CFDictionaryRef arg4, CGDisplayStreamFrameAvailableHandler arg5)
{
    #define RUN_FUNC  CGDisplayStreamRef ret = real::CGDisplayStreamCreate(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGFontGetCapHeight"
#pragma push_macro(FUNC_ID)
#undef CGFontGetCapHeight
// extra usings

INTERPOSE(CGFontGetCapHeight)(CGFontRef arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGFontGetCapHeight(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextShowGlyphsWithAdvances"
#pragma push_macro(FUNC_ID)
#undef CGContextShowGlyphsWithAdvances
// extra usings
using CGContextShowGlyphsWithAdvances_T_arg2 = const CGSize *;
using CGContextShowGlyphsWithAdvances_T_arg2 = const CGSize *;
INTERPOSE(CGContextShowGlyphsWithAdvances)(CGContextRef arg0, const unsigned short * arg1, CGContextShowGlyphsWithAdvances_T_arg2 arg2, __darwin_size_t arg3)
{
    #define RUN_FUNC  real::CGContextShowGlyphsWithAdvances(arg0, arg1, arg2, arg3)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGDataConsumerCreate"
#pragma push_macro(FUNC_ID)
#undef CGDataConsumerCreate
// extra usings

INTERPOSE(CGDataConsumerCreate)(void * arg0, const CGDataConsumerCallbacks * arg1)
{
    #define RUN_FUNC  CGDataConsumerRef ret = real::CGDataConsumerCreate(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFArrayGetInteger"
#pragma push_macro(FUNC_ID)
#undef CGPDFArrayGetInteger
// extra usings
using CGPDFArrayGetInteger_T_arg2 = long *;
using CGPDFArrayGetInteger_T_arg2 = long *;
INTERPOSE(CGPDFArrayGetInteger)(CGPDFArrayRef arg0, __darwin_size_t arg1, CGPDFArrayGetInteger_T_arg2 arg2)
{
    #define RUN_FUNC  bool ret = real::CGPDFArrayGetInteger(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGColorCreateCopy"
#pragma push_macro(FUNC_ID)
#undef CGColorCreateCopy
// extra usings

INTERPOSE(CGColorCreateCopy)(CGColorRef arg0)
{
    #define RUN_FUNC  CGColorRef ret = real::CGColorCreateCopy(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGBitmapContextCreate"
#pragma push_macro(FUNC_ID)
#undef CGBitmapContextCreate
// extra usings

INTERPOSE(CGBitmapContextCreate)(void * arg0, __darwin_size_t arg1, __darwin_size_t arg2, __darwin_size_t arg3, __darwin_size_t arg4, CGColorSpaceRef arg5, __uint32_t arg6)
{
    #define RUN_FUNC  CGContextRef ret = real::CGBitmapContextCreate(arg0, arg1, arg2, arg3, arg4, arg5, arg6)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFArrayApplyBlock"
#pragma push_macro(FUNC_ID)
#undef CGPDFArrayApplyBlock
// extra usings

INTERPOSE(CGPDFArrayApplyBlock)(CGPDFArrayRef arg0, CGPDFArrayApplierBlock arg1, void * arg2)
{
    #define RUN_FUNC  real::CGPDFArrayApplyBlock(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPathAddRelativeArc"
#pragma push_macro(FUNC_ID)
#undef CGPathAddRelativeArc
// extra usings
using CGPathAddRelativeArc_T_arg1 = const CGAffineTransform *;
using CGPathAddRelativeArc_T_arg1 = const CGAffineTransform *;
INTERPOSE(CGPathAddRelativeArc)(CGMutablePathRef arg0, CGPathAddRelativeArc_T_arg1 arg1, CGFloat arg2, CGFloat arg3, CGFloat arg4, CGFloat arg5, CGFloat arg6)
{
    #define RUN_FUNC  real::CGPathAddRelativeArc(arg0, arg1, arg2, arg3, arg4, arg5, arg6)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGDisplaySetStereoOperation"
#pragma push_macro(FUNC_ID)
#undef CGDisplaySetStereoOperation
// extra usings

INTERPOSE(CGDisplaySetStereoOperation)(__uint32_t arg0, __uint32_t arg1, __uint32_t arg2, __uint32_t arg3)
{
    #define RUN_FUNC  __int32_t ret = real::CGDisplaySetStereoOperation(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextSetShouldAntialias"
#pragma push_macro(FUNC_ID)
#undef CGContextSetShouldAntialias
// extra usings

INTERPOSE(CGContextSetShouldAntialias)(CGContextRef arg0, bool arg1)
{
    #define RUN_FUNC  real::CGContextSetShouldAntialias(arg0, arg1)

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

#define FUNC_ID "CGDisplayModeGetHeight"
#pragma push_macro(FUNC_ID)
#undef CGDisplayModeGetHeight
// extra usings

INTERPOSE(CGDisplayModeGetHeight)(CGDisplayModeRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGDisplayModeGetHeight(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextSetFillColor"
#pragma push_macro(FUNC_ID)
#undef CGContextSetFillColor
// extra usings

INTERPOSE(CGContextSetFillColor)(CGContextRef arg0, const double * arg1)
{
    #define RUN_FUNC  real::CGContextSetFillColor(arg0, arg1)

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

#define FUNC_ID "CGImageRelease"
#pragma push_macro(FUNC_ID)
#undef CGImageRelease
// extra usings

INTERPOSE(CGImageRelease)(CGImageRef arg0)
{
    #define RUN_FUNC  real::CGImageRelease(arg0)

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

#define FUNC_ID "CGRectDivide"
#pragma push_macro(FUNC_ID)
#undef CGRectDivide
// extra usings

INTERPOSE(CGRectDivide)(CGRect arg0, CGRect * arg1, CGRect * arg2, CGFloat arg3, __uint32_t arg4)
{
    #define RUN_FUNC  real::CGRectDivide(arg0, arg1, arg2, arg3, arg4)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGContextSetGrayFillColor"
#pragma push_macro(FUNC_ID)
#undef CGContextSetGrayFillColor
// extra usings

INTERPOSE(CGContextSetGrayFillColor)(CGContextRef arg0, CGFloat arg1, CGFloat arg2)
{
    #define RUN_FUNC  real::CGContextSetGrayFillColor(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGColorSpaceIsHDR"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceIsHDR
// extra usings

INTERPOSE(CGColorSpaceIsHDR)(CGColorSpaceRef arg0)
{
    #define RUN_FUNC  bool ret = real::CGColorSpaceIsHDR(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGImageGetUTType"
#pragma push_macro(FUNC_ID)
#undef CGImageGetUTType
// extra usings

INTERPOSE(CGImageGetUTType)(CGImageRef arg0)
{
    #define RUN_FUNC  CFStringRef ret = real::CGImageGetUTType(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPSConverterCreate"
#pragma push_macro(FUNC_ID)
#undef CGPSConverterCreate
// extra usings

INTERPOSE(CGPSConverterCreate)(void * arg0, const CGPSConverterCallbacks * arg1, CFDictionaryRef arg2)
{
    #define RUN_FUNC  CGPSConverterRef ret = real::CGPSConverterCreate(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGDirectDisplayCopyCurrentMetalDevice"
#pragma push_macro(FUNC_ID)
#undef CGDirectDisplayCopyCurrentMetalDevice
// extra usings

INTERPOSE(CGDirectDisplayCopyCurrentMetalDevice)(__uint32_t arg0)
{
    #define RUN_FUNC  id<MTLDevice> ret = real::CGDirectDisplayCopyCurrentMetalDevice(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextClipToMask"
#pragma push_macro(FUNC_ID)
#undef CGContextClipToMask
// extra usings

INTERPOSE(CGContextClipToMask)(CGContextRef arg0, CGRect arg1, CGImageRef arg2)
{
    #define RUN_FUNC  real::CGContextClipToMask(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGDisplayCopyColorSpace"
#pragma push_macro(FUNC_ID)
#undef CGDisplayCopyColorSpace
// extra usings

INTERPOSE(CGDisplayCopyColorSpace)(__uint32_t arg0)
{
    #define RUN_FUNC  CGColorSpaceRef ret = real::CGDisplayCopyColorSpace(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextAddLineToPoint"
#pragma push_macro(FUNC_ID)
#undef CGContextAddLineToPoint
// extra usings

INTERPOSE(CGContextAddLineToPoint)(CGContextRef arg0, CGFloat arg1, CGFloat arg2)
{
    #define RUN_FUNC  real::CGContextAddLineToPoint(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGColorSpaceGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceGetTypeID
// extra usings

INTERPOSE(CGColorSpaceGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGColorSpaceGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPathAddPath"
#pragma push_macro(FUNC_ID)
#undef CGPathAddPath
// extra usings
using CGPathAddPath_T_arg1 = const CGAffineTransform *;
using CGPathAddPath_T_arg1 = const CGAffineTransform *;
INTERPOSE(CGPathAddPath)(CGMutablePathRef arg0, CGPathAddPath_T_arg1 arg1, CGPathRef arg2)
{
    #define RUN_FUNC  real::CGPathAddPath(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGDataProviderRetain"
#pragma push_macro(FUNC_ID)
#undef CGDataProviderRetain
// extra usings

INTERPOSE(CGDataProviderRetain)(CGDataProviderRef arg0)
{
    #define RUN_FUNC  CGDataProviderRef ret = real::CGDataProviderRetain(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayPixelsHigh"
#pragma push_macro(FUNC_ID)
#undef CGDisplayPixelsHigh
// extra usings

INTERPOSE(CGDisplayPixelsHigh)(__uint32_t arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGDisplayPixelsHigh(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGConfigureDisplayStereoOperation"
#pragma push_macro(FUNC_ID)
#undef CGConfigureDisplayStereoOperation
// extra usings

INTERPOSE(CGConfigureDisplayStereoOperation)(CGDisplayConfigRef arg0, __uint32_t arg1, __uint32_t arg2, __uint32_t arg3)
{
    #define RUN_FUNC  __int32_t ret = real::CGConfigureDisplayStereoOperation(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGColorConversionInfoCreateWithOptions"
#pragma push_macro(FUNC_ID)
#undef CGColorConversionInfoCreateWithOptions
// extra usings

INTERPOSE(CGColorConversionInfoCreateWithOptions)(CGColorSpaceRef arg0, CGColorSpaceRef arg1, CFDictionaryRef arg2)
{
    #define RUN_FUNC  CGColorConversionInfoRef ret = real::CGColorConversionInfoCreateWithOptions(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFOperatorTableCreate"
#pragma push_macro(FUNC_ID)
#undef CGPDFOperatorTableCreate
// extra usings

INTERPOSE(CGPDFOperatorTableCreate)()
{
    #define RUN_FUNC  CGPDFOperatorTableRef ret = real::CGPDFOperatorTableCreate()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPDFContextAddDestinationAtPoint"
#pragma push_macro(FUNC_ID)
#undef CGPDFContextAddDestinationAtPoint
// extra usings

INTERPOSE(CGPDFContextAddDestinationAtPoint)(CGContextRef arg0, CFStringRef arg1, CGPoint arg2)
{
    #define RUN_FUNC  real::CGPDFContextAddDestinationAtPoint(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPDFScannerGetContentStream"
#pragma push_macro(FUNC_ID)
#undef CGPDFScannerGetContentStream
// extra usings

INTERPOSE(CGPDFScannerGetContentStream)(CGPDFScannerRef arg0)
{
    #define RUN_FUNC  CGPDFContentStreamRef ret = real::CGPDFScannerGetContentStream(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextSetShouldSubpixelQuantizeFonts"
#pragma push_macro(FUNC_ID)
#undef CGContextSetShouldSubpixelQuantizeFonts
// extra usings

INTERPOSE(CGContextSetShouldSubpixelQuantizeFonts)(CGContextRef arg0, bool arg1)
{
    #define RUN_FUNC  real::CGContextSetShouldSubpixelQuantizeFonts(arg0, arg1)

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

#define FUNC_ID "CGPathContainsPoint"
#pragma push_macro(FUNC_ID)
#undef CGPathContainsPoint
// extra usings
using CGPathContainsPoint_T_arg1 = const CGAffineTransform *;
using CGPathContainsPoint_T_arg1 = const CGAffineTransform *;
INTERPOSE(CGPathContainsPoint)(CGPathRef arg0, CGPathContainsPoint_T_arg1 arg1, CGPoint arg2, bool arg3)
{
    #define RUN_FUNC  bool ret = real::CGPathContainsPoint(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGSizeApplyAffineTransform"
#pragma push_macro(FUNC_ID)
#undef CGSizeApplyAffineTransform
// extra usings

INTERPOSE(CGSizeApplyAffineTransform)(CGSize arg0, CGAffineTransform arg1)
{
    #define RUN_FUNC  CGSize ret = real::CGSizeApplyAffineTransform(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGRectIntegral"
#pragma push_macro(FUNC_ID)
#undef CGRectIntegral
// extra usings

INTERPOSE(CGRectIntegral)(CGRect arg0)
{
    #define RUN_FUNC  CGRect ret = real::CGRectIntegral(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayPrimaryDisplay"
#pragma push_macro(FUNC_ID)
#undef CGDisplayPrimaryDisplay
// extra usings

INTERPOSE(CGDisplayPrimaryDisplay)(__uint32_t arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGDisplayPrimaryDisplay(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextConcatCTM"
#pragma push_macro(FUNC_ID)
#undef CGContextConcatCTM
// extra usings

INTERPOSE(CGContextConcatCTM)(CGContextRef arg0, CGAffineTransform arg1)
{
    #define RUN_FUNC  real::CGContextConcatCTM(arg0, arg1)

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

#define FUNC_ID "CGFunctionRelease"
#pragma push_macro(FUNC_ID)
#undef CGFunctionRelease
// extra usings

INTERPOSE(CGFunctionRelease)(CGFunctionRef arg0)
{
    #define RUN_FUNC  real::CGFunctionRelease(arg0)

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

#define FUNC_ID "CGPDFDocumentGetOutline"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentGetOutline
// extra usings

INTERPOSE(CGPDFDocumentGetOutline)(CGPDFDocumentRef arg0)
{
    #define RUN_FUNC  CFDictionaryRef ret = real::CGPDFDocumentGetOutline(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPatternRetain"
#pragma push_macro(FUNC_ID)
#undef CGPatternRetain
// extra usings

INTERPOSE(CGPatternRetain)(CGPatternRef arg0)
{
    #define RUN_FUNC  CGPatternRef ret = real::CGPatternRetain(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDataProviderGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CGDataProviderGetTypeID
// extra usings

INTERPOSE(CGDataProviderGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGDataProviderGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGSetLocalEventsSuppressionInterval"
#pragma push_macro(FUNC_ID)
#undef CGSetLocalEventsSuppressionInterval
// extra usings

INTERPOSE(CGSetLocalEventsSuppressionInterval)(CGFloat arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGSetLocalEventsSuppressionInterval(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFArrayGetCount"
#pragma push_macro(FUNC_ID)
#undef CGPDFArrayGetCount
// extra usings

INTERPOSE(CGPDFArrayGetCount)(CGPDFArrayRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGPDFArrayGetCount(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFContextClose"
#pragma push_macro(FUNC_ID)
#undef CGPDFContextClose
// extra usings

INTERPOSE(CGPDFContextClose)(CGContextRef arg0)
{
    #define RUN_FUNC  real::CGPDFContextClose(arg0)

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

#define FUNC_ID "CGDisplayIsBuiltin"
#pragma push_macro(FUNC_ID)
#undef CGDisplayIsBuiltin
// extra usings

INTERPOSE(CGDisplayIsBuiltin)(__uint32_t arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGDisplayIsBuiltin(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextIsPathEmpty"
#pragma push_macro(FUNC_ID)
#undef CGContextIsPathEmpty
// extra usings

INTERPOSE(CGContextIsPathEmpty)(CGContextRef arg0)
{
    #define RUN_FUNC  bool ret = real::CGContextIsPathEmpty(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextSetShadow"
#pragma push_macro(FUNC_ID)
#undef CGContextSetShadow
// extra usings

INTERPOSE(CGContextSetShadow)(CGContextRef arg0, CGSize arg1, CGFloat arg2)
{
    #define RUN_FUNC  real::CGContextSetShadow(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPathGetBoundingBox"
#pragma push_macro(FUNC_ID)
#undef CGPathGetBoundingBox
// extra usings

INTERPOSE(CGPathGetBoundingBox)(CGPathRef arg0)
{
    #define RUN_FUNC  CGRect ret = real::CGPathGetBoundingBox(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGColorGetNumberOfComponents"
#pragma push_macro(FUNC_ID)
#undef CGColorGetNumberOfComponents
// extra usings

INTERPOSE(CGColorGetNumberOfComponents)(CGColorRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGColorGetNumberOfComponents(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGColorSpaceRelease"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceRelease
// extra usings

INTERPOSE(CGColorSpaceRelease)(CGColorSpaceRef arg0)
{
    #define RUN_FUNC  real::CGColorSpaceRelease(arg0)

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

#define FUNC_ID "CGGetDisplayTransferByTable"
#pragma push_macro(FUNC_ID)
#undef CGGetDisplayTransferByTable
// extra usings
using CGGetDisplayTransferByTable_T_arg2 = float *;
using CGGetDisplayTransferByTable_T_arg3 = float *;
using CGGetDisplayTransferByTable_T_arg4 = float *;
using CGGetDisplayTransferByTable_T_arg2 = float *;
using CGGetDisplayTransferByTable_T_arg3 = float *;
using CGGetDisplayTransferByTable_T_arg4 = float *;
INTERPOSE(CGGetDisplayTransferByTable)(__uint32_t arg0, __uint32_t arg1, CGGetDisplayTransferByTable_T_arg2 arg2, CGGetDisplayTransferByTable_T_arg3 arg3, CGGetDisplayTransferByTable_T_arg4 arg4, UnsignedFixedPtr arg5)
{
    #define RUN_FUNC  __int32_t ret = real::CGGetDisplayTransferByTable(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFDictionaryApplyBlock"
#pragma push_macro(FUNC_ID)
#undef CGPDFDictionaryApplyBlock
// extra usings

INTERPOSE(CGPDFDictionaryApplyBlock)(CGPDFDictionaryRef arg0, CGPDFDictionaryApplierBlock arg1, void * arg2)
{
    #define RUN_FUNC  real::CGPDFDictionaryApplyBlock(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGContextShowGlyphsAtPoint"
#pragma push_macro(FUNC_ID)
#undef CGContextShowGlyphsAtPoint
// extra usings

INTERPOSE(CGContextShowGlyphsAtPoint)(CGContextRef arg0, CGFloat arg1, CGFloat arg2, const unsigned short * arg3, __darwin_size_t arg4)
{
    #define RUN_FUNC  real::CGContextShowGlyphsAtPoint(arg0, arg1, arg2, arg3, arg4)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPathAddLines"
#pragma push_macro(FUNC_ID)
#undef CGPathAddLines
// extra usings
using CGPathAddLines_T_arg1 = const CGAffineTransform *;
using CGPathAddLines_T_arg2 = const CGPoint *;
using CGPathAddLines_T_arg1 = const CGAffineTransform *;
using CGPathAddLines_T_arg2 = const CGPoint *;
INTERPOSE(CGPathAddLines)(CGMutablePathRef arg0, CGPathAddLines_T_arg1 arg1, CGPathAddLines_T_arg2 arg2, __darwin_size_t arg3)
{
    #define RUN_FUNC  real::CGPathAddLines(arg0, arg1, arg2, arg3)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGColorCreateGenericRGB"
#pragma push_macro(FUNC_ID)
#undef CGColorCreateGenericRGB
// extra usings

INTERPOSE(CGColorCreateGenericRGB)(CGFloat arg0, CGFloat arg1, CGFloat arg2, CGFloat arg3)
{
    #define RUN_FUNC  CGColorRef ret = real::CGColorCreateGenericRGB(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextDrawPDFPage"
#pragma push_macro(FUNC_ID)
#undef CGContextDrawPDFPage
// extra usings

INTERPOSE(CGContextDrawPDFPage)(CGContextRef arg0, CGPDFPageRef arg1)
{
    #define RUN_FUNC  real::CGContextDrawPDFPage(arg0, arg1)

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

#define FUNC_ID "CGDisplayModeRetain"
#pragma push_macro(FUNC_ID)
#undef CGDisplayModeRetain
// extra usings

INTERPOSE(CGDisplayModeRetain)(CGDisplayModeRef arg0)
{
    #define RUN_FUNC  CGDisplayModeRef ret = real::CGDisplayModeRetain(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayGammaTableCapacity"
#pragma push_macro(FUNC_ID)
#undef CGDisplayGammaTableCapacity
// extra usings

INTERPOSE(CGDisplayGammaTableCapacity)(__uint32_t arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGDisplayGammaTableCapacity(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGFontCreateWithFontName"
#pragma push_macro(FUNC_ID)
#undef CGFontCreateWithFontName
// extra usings

INTERPOSE(CGFontCreateWithFontName)(CFStringRef arg0)
{
    #define RUN_FUNC  CGFontRef ret = real::CGFontCreateWithFontName(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayCopyAllDisplayModes"
#pragma push_macro(FUNC_ID)
#undef CGDisplayCopyAllDisplayModes
// extra usings

INTERPOSE(CGDisplayCopyAllDisplayModes)(__uint32_t arg0, CFDictionaryRef arg1)
{
    #define RUN_FUNC  CFArrayRef ret = real::CGDisplayCopyAllDisplayModes(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextScaleCTM"
#pragma push_macro(FUNC_ID)
#undef CGContextScaleCTM
// extra usings

INTERPOSE(CGContextScaleCTM)(CGContextRef arg0, CGFloat arg1, CGFloat arg2)
{
    #define RUN_FUNC  real::CGContextScaleCTM(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGInhibitLocalEvents"
#pragma push_macro(FUNC_ID)
#undef CGInhibitLocalEvents
// extra usings

INTERPOSE(CGInhibitLocalEvents)(__uint32_t arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGInhibitLocalEvents(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextSetLineCap"
#pragma push_macro(FUNC_ID)
#undef CGContextSetLineCap
// extra usings

INTERPOSE(CGContextSetLineCap)(CGContextRef arg0, __int32_t arg1)
{
    #define RUN_FUNC  real::CGContextSetLineCap(arg0, arg1)

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

#define FUNC_ID "CGContextDrawRadialGradient"
#pragma push_macro(FUNC_ID)
#undef CGContextDrawRadialGradient
// extra usings

INTERPOSE(CGContextDrawRadialGradient)(CGContextRef arg0, CGGradientRef arg1, CGPoint arg2, CGFloat arg3, CGPoint arg4, CGFloat arg5, __uint32_t arg6)
{
    #define RUN_FUNC  real::CGContextDrawRadialGradient(arg0, arg1, arg2, arg3, arg4, arg5, arg6)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGFontCopyVariations"
#pragma push_macro(FUNC_ID)
#undef CGFontCopyVariations
// extra usings

INTERPOSE(CGFontCopyVariations)(CGFontRef arg0)
{
    #define RUN_FUNC  CFDictionaryRef ret = real::CGFontCopyVariations(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGConfigureDisplayMirrorOfDisplay"
#pragma push_macro(FUNC_ID)
#undef CGConfigureDisplayMirrorOfDisplay
// extra usings

INTERPOSE(CGConfigureDisplayMirrorOfDisplay)(CGDisplayConfigRef arg0, __uint32_t arg1, __uint32_t arg2)
{
    #define RUN_FUNC  __int32_t ret = real::CGConfigureDisplayMirrorOfDisplay(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGFontCreateCopyWithVariations"
#pragma push_macro(FUNC_ID)
#undef CGFontCreateCopyWithVariations
// extra usings

INTERPOSE(CGFontCreateCopyWithVariations)(CGFontRef arg0, CFDictionaryRef arg1)
{
    #define RUN_FUNC  CGFontRef ret = real::CGFontCreateCopyWithVariations(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGRectGetMidY"
#pragma push_macro(FUNC_ID)
#undef CGRectGetMidY
// extra usings

INTERPOSE(CGRectGetMidY)(CGRect arg0)
{
    #define RUN_FUNC  CGFloat ret = real::CGRectGetMidY(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextFillEllipseInRect"
#pragma push_macro(FUNC_ID)
#undef CGContextFillEllipseInRect
// extra usings

INTERPOSE(CGContextFillEllipseInRect)(CGContextRef arg0, CGRect arg1)
{
    #define RUN_FUNC  real::CGContextFillEllipseInRect(arg0, arg1)

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

#define FUNC_ID "CGContextSetAlpha"
#pragma push_macro(FUNC_ID)
#undef CGContextSetAlpha
// extra usings

INTERPOSE(CGContextSetAlpha)(CGContextRef arg0, CGFloat arg1)
{
    #define RUN_FUNC  real::CGContextSetAlpha(arg0, arg1)

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

#define FUNC_ID "CGContextAddQuadCurveToPoint"
#pragma push_macro(FUNC_ID)
#undef CGContextAddQuadCurveToPoint
// extra usings

INTERPOSE(CGContextAddQuadCurveToPoint)(CGContextRef arg0, CGFloat arg1, CGFloat arg2, CGFloat arg3, CGFloat arg4)
{
    #define RUN_FUNC  real::CGContextAddQuadCurveToPoint(arg0, arg1, arg2, arg3, arg4)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGColorSpaceGetNumberOfComponents"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceGetNumberOfComponents
// extra usings

INTERPOSE(CGColorSpaceGetNumberOfComponents)(CGColorSpaceRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGColorSpaceGetNumberOfComponents(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFDocumentGetMediaBox"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentGetMediaBox
// extra usings

INTERPOSE(CGPDFDocumentGetMediaBox)(CGPDFDocumentRef arg0, __int32_t arg1)
{
    #define RUN_FUNC  CGRect ret = real::CGPDFDocumentGetMediaBox(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFDictionaryGetString"
#pragma push_macro(FUNC_ID)
#undef CGPDFDictionaryGetString
// extra usings
using CGPDFDictionaryGetString_T_arg2 = CGPDFString **;
using CGPDFDictionaryGetString_T_arg2 = CGPDFString **;
INTERPOSE(CGPDFDictionaryGetString)(CGPDFDictionaryRef arg0, const char * arg1, CGPDFDictionaryGetString_T_arg2 arg2)
{
    #define RUN_FUNC  bool ret = real::CGPDFDictionaryGetString(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGRegisterScreenRefreshCallback"
#pragma push_macro(FUNC_ID)
#undef CGRegisterScreenRefreshCallback
// extra usings

INTERPOSE(CGRegisterScreenRefreshCallback)(CGScreenRefreshCallback arg0, void * arg1)
{
    #define RUN_FUNC  __int32_t ret = real::CGRegisterScreenRefreshCallback(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGFontGetUnitsPerEm"
#pragma push_macro(FUNC_ID)
#undef CGFontGetUnitsPerEm
// extra usings

INTERPOSE(CGFontGetUnitsPerEm)(CGFontRef arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGFontGetUnitsPerEm(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextEOClip"
#pragma push_macro(FUNC_ID)
#undef CGContextEOClip
// extra usings

INTERPOSE(CGContextEOClip)(CGContextRef arg0)
{
    #define RUN_FUNC  real::CGContextEOClip(arg0)

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

#define FUNC_ID "CGAcquireDisplayFadeReservation"
#pragma push_macro(FUNC_ID)
#undef CGAcquireDisplayFadeReservation
// extra usings

INTERPOSE(CGAcquireDisplayFadeReservation)(Float32 arg0, UnsignedFixedPtr arg1)
{
    #define RUN_FUNC  __int32_t ret = real::CGAcquireDisplayFadeReservation(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGBitmapContextGetData"
#pragma push_macro(FUNC_ID)
#undef CGBitmapContextGetData
// extra usings

INTERPOSE(CGBitmapContextGetData)(CGContextRef arg0)
{
    #define RUN_FUNC  void * ret = real::CGBitmapContextGetData(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGAffineTransformIsIdentity"
#pragma push_macro(FUNC_ID)
#undef CGAffineTransformIsIdentity
// extra usings

INTERPOSE(CGAffineTransformIsIdentity)(CGAffineTransform arg0)
{
    #define RUN_FUNC  bool ret = real::CGAffineTransformIsIdentity(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextGetInterpolationQuality"
#pragma push_macro(FUNC_ID)
#undef CGContextGetInterpolationQuality
// extra usings

INTERPOSE(CGContextGetInterpolationQuality)(CGContextRef arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGContextGetInterpolationQuality(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPathGetPathBoundingBox"
#pragma push_macro(FUNC_ID)
#undef CGPathGetPathBoundingBox
// extra usings

INTERPOSE(CGPathGetPathBoundingBox)(CGPathRef arg0)
{
    #define RUN_FUNC  CGRect ret = real::CGPathGetPathBoundingBox(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextRotateCTM"
#pragma push_macro(FUNC_ID)
#undef CGContextRotateCTM
// extra usings

INTERPOSE(CGContextRotateCTM)(CGContextRef arg0, CGFloat arg1)
{
    #define RUN_FUNC  real::CGContextRotateCTM(arg0, arg1)

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

#define FUNC_ID "CGImageCreateCopy"
#pragma push_macro(FUNC_ID)
#undef CGImageCreateCopy
// extra usings

INTERPOSE(CGImageCreateCopy)(CGImageRef arg0)
{
    #define RUN_FUNC  CGImageRef ret = real::CGImageCreateCopy(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGImageGetShouldInterpolate"
#pragma push_macro(FUNC_ID)
#undef CGImageGetShouldInterpolate
// extra usings

INTERPOSE(CGImageGetShouldInterpolate)(CGImageRef arg0)
{
    #define RUN_FUNC  bool ret = real::CGImageGetShouldInterpolate(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGFontRelease"
#pragma push_macro(FUNC_ID)
#undef CGFontRelease
// extra usings

INTERPOSE(CGFontRelease)(CGFontRef arg0)
{
    #define RUN_FUNC  real::CGFontRelease(arg0)

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

#define FUNC_ID "CGColorCreateCopyByMatchingToColorSpace"
#pragma push_macro(FUNC_ID)
#undef CGColorCreateCopyByMatchingToColorSpace
// extra usings

INTERPOSE(CGColorCreateCopyByMatchingToColorSpace)(CGColorSpaceRef arg0, __int32_t arg1, CGColorRef arg2, CFDictionaryRef arg3)
{
    #define RUN_FUNC  CGColorRef ret = real::CGColorCreateCopyByMatchingToColorSpace(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextSetAllowsAntialiasing"
#pragma push_macro(FUNC_ID)
#undef CGContextSetAllowsAntialiasing
// extra usings

INTERPOSE(CGContextSetAllowsAntialiasing)(CGContextRef arg0, bool arg1)
{
    #define RUN_FUNC  real::CGContextSetAllowsAntialiasing(arg0, arg1)

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

#define FUNC_ID "CGPDFScannerPopDictionary"
#pragma push_macro(FUNC_ID)
#undef CGPDFScannerPopDictionary
// extra usings
using CGPDFScannerPopDictionary_T_arg1 = CGPDFDictionary **;
using CGPDFScannerPopDictionary_T_arg1 = CGPDFDictionary **;
INTERPOSE(CGPDFScannerPopDictionary)(CGPDFScannerRef arg0, CGPDFScannerPopDictionary_T_arg1 arg1)
{
    #define RUN_FUNC  bool ret = real::CGPDFScannerPopDictionary(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGFontCopyTableForTag"
#pragma push_macro(FUNC_ID)
#undef CGFontCopyTableForTag
// extra usings

INTERPOSE(CGFontCopyTableForTag)(CGFontRef arg0, __uint32_t arg1)
{
    #define RUN_FUNC  CFDataRef ret = real::CGFontCopyTableForTag(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGRectIntersection"
#pragma push_macro(FUNC_ID)
#undef CGRectIntersection
// extra usings

INTERPOSE(CGRectIntersection)(CGRect arg0, CGRect arg1)
{
    #define RUN_FUNC  CGRect ret = real::CGRectIntersection(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGColorGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CGColorGetTypeID
// extra usings

INTERPOSE(CGColorGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGColorGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGSetDisplayTransferByFormula"
#pragma push_macro(FUNC_ID)
#undef CGSetDisplayTransferByFormula
// extra usings

INTERPOSE(CGSetDisplayTransferByFormula)(__uint32_t arg0, Float32 arg1, Float32 arg2, Float32 arg3, Float32 arg4, Float32 arg5, Float32 arg6, Float32 arg7, Float32 arg8, Float32 arg9)
{
    #define RUN_FUNC  __int32_t ret = real::CGSetDisplayTransferByFormula(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFStreamGetDictionary"
#pragma push_macro(FUNC_ID)
#undef CGPDFStreamGetDictionary
// extra usings

INTERPOSE(CGPDFStreamGetDictionary)(CGPDFStreamRef arg0)
{
    #define RUN_FUNC  CGPDFDictionaryRef ret = real::CGPDFStreamGetDictionary(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGRectContainsRect"
#pragma push_macro(FUNC_ID)
#undef CGRectContainsRect
// extra usings

INTERPOSE(CGRectContainsRect)(CGRect arg0, CGRect arg1)
{
    #define RUN_FUNC  bool ret = real::CGRectContainsRect(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGColorGetPattern"
#pragma push_macro(FUNC_ID)
#undef CGColorGetPattern
// extra usings

INTERPOSE(CGColorGetPattern)(CGColorRef arg0)
{
    #define RUN_FUNC  CGPatternRef ret = real::CGColorGetPattern(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGFontCreatePostScriptSubset"
#pragma push_macro(FUNC_ID)
#undef CGFontCreatePostScriptSubset
// extra usings

INTERPOSE(CGFontCreatePostScriptSubset)(CGFontRef arg0, CFStringRef arg1, __int32_t arg2, const unsigned short * arg3, __darwin_size_t arg4, const unsigned short * arg5)
{
    #define RUN_FUNC  CFDataRef ret = real::CGFontCreatePostScriptSubset(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFDocumentGetCatalog"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentGetCatalog
// extra usings

INTERPOSE(CGPDFDocumentGetCatalog)(CGPDFDocumentRef arg0)
{
    #define RUN_FUNC  CGPDFDictionaryRef ret = real::CGPDFDocumentGetCatalog(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGColorSpaceGetModel"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceGetModel
// extra usings

INTERPOSE(CGColorSpaceGetModel)(CGColorSpaceRef arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGColorSpaceGetModel(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGImageGetColorSpace"
#pragma push_macro(FUNC_ID)
#undef CGImageGetColorSpace
// extra usings

INTERPOSE(CGImageGetColorSpace)(CGImageRef arg0)
{
    #define RUN_FUNC  CGColorSpaceRef ret = real::CGImageGetColorSpace(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFArrayGetString"
#pragma push_macro(FUNC_ID)
#undef CGPDFArrayGetString
// extra usings
using CGPDFArrayGetString_T_arg2 = CGPDFString **;
using CGPDFArrayGetString_T_arg2 = CGPDFString **;
INTERPOSE(CGPDFArrayGetString)(CGPDFArrayRef arg0, __darwin_size_t arg1, CGPDFArrayGetString_T_arg2 arg2)
{
    #define RUN_FUNC  bool ret = real::CGPDFArrayGetString(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPointMake"
#pragma push_macro(FUNC_ID)
#undef CGPointMake
// extra usings

INTERPOSE(CGPointMake)(CGFloat arg0, CGFloat arg1)
{
    #define RUN_FUNC  CGPoint ret = real::CGPointMake(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFDictionaryGetObject"
#pragma push_macro(FUNC_ID)
#undef CGPDFDictionaryGetObject
// extra usings
using CGPDFDictionaryGetObject_T_arg2 = CGPDFObject **;
using CGPDFDictionaryGetObject_T_arg2 = CGPDFObject **;
INTERPOSE(CGPDFDictionaryGetObject)(CGPDFDictionaryRef arg0, const char * arg1, CGPDFDictionaryGetObject_T_arg2 arg2)
{
    #define RUN_FUNC  bool ret = real::CGPDFDictionaryGetObject(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGReleaseDisplayFadeReservation"
#pragma push_macro(FUNC_ID)
#undef CGReleaseDisplayFadeReservation
// extra usings

INTERPOSE(CGReleaseDisplayFadeReservation)(__uint32_t arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGReleaseDisplayFadeReservation(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplaySwitchToMode"
#pragma push_macro(FUNC_ID)
#undef CGDisplaySwitchToMode
// extra usings

INTERPOSE(CGDisplaySwitchToMode)(__uint32_t arg0, CFDictionaryRef arg1)
{
    #define RUN_FUNC  __int32_t ret = real::CGDisplaySwitchToMode(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFPageRetain"
#pragma push_macro(FUNC_ID)
#undef CGPDFPageRetain
// extra usings

INTERPOSE(CGPDFPageRetain)(CGPDFPageRef arg0)
{
    #define RUN_FUNC  CGPDFPageRef ret = real::CGPDFPageRetain(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextStrokeLineSegments"
#pragma push_macro(FUNC_ID)
#undef CGContextStrokeLineSegments
// extra usings
using CGContextStrokeLineSegments_T_arg1 = const CGPoint *;
using CGContextStrokeLineSegments_T_arg1 = const CGPoint *;
INTERPOSE(CGContextStrokeLineSegments)(CGContextRef arg0, CGContextStrokeLineSegments_T_arg1 arg1, __darwin_size_t arg2)
{
    #define RUN_FUNC  real::CGContextStrokeLineSegments(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPDFObjectGetType"
#pragma push_macro(FUNC_ID)
#undef CGPDFObjectGetType
// extra usings

INTERPOSE(CGPDFObjectGetType)(CGPDFObjectRef arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGPDFObjectGetType(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextSetStrokeColor"
#pragma push_macro(FUNC_ID)
#undef CGContextSetStrokeColor
// extra usings

INTERPOSE(CGContextSetStrokeColor)(CGContextRef arg0, const double * arg1)
{
    #define RUN_FUNC  real::CGContextSetStrokeColor(arg0, arg1)

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

#define FUNC_ID "CGPDFContextEndTag"
#pragma push_macro(FUNC_ID)
#undef CGPDFContextEndTag
// extra usings

INTERPOSE(CGPDFContextEndTag)(CGContextRef arg0)
{
    #define RUN_FUNC  real::CGPDFContextEndTag(arg0)

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

#define FUNC_ID "CGPDFScannerPopBoolean"
#pragma push_macro(FUNC_ID)
#undef CGPDFScannerPopBoolean
// extra usings

INTERPOSE(CGPDFScannerPopBoolean)(CGPDFScannerRef arg0, BytePtr arg1)
{
    #define RUN_FUNC  bool ret = real::CGPDFScannerPopBoolean(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGGradientRelease"
#pragma push_macro(FUNC_ID)
#undef CGGradientRelease
// extra usings

INTERPOSE(CGGradientRelease)(CGGradientRef arg0)
{
    #define RUN_FUNC  real::CGGradientRelease(arg0)

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

#define FUNC_ID "CGConfigureDisplayMode"
#pragma push_macro(FUNC_ID)
#undef CGConfigureDisplayMode
// extra usings

INTERPOSE(CGConfigureDisplayMode)(CGDisplayConfigRef arg0, __uint32_t arg1, CFDictionaryRef arg2)
{
    #define RUN_FUNC  __int32_t ret = real::CGConfigureDisplayMode(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGWarpMouseCursorPosition"
#pragma push_macro(FUNC_ID)
#undef CGWarpMouseCursorPosition
// extra usings

INTERPOSE(CGWarpMouseCursorPosition)(CGPoint arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGWarpMouseCursorPosition(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPathCreateWithRoundedRect"
#pragma push_macro(FUNC_ID)
#undef CGPathCreateWithRoundedRect
// extra usings
using CGPathCreateWithRoundedRect_T_arg3 = const CGAffineTransform *;
using CGPathCreateWithRoundedRect_T_arg3 = const CGAffineTransform *;
INTERPOSE(CGPathCreateWithRoundedRect)(CGRect arg0, CGFloat arg1, CGFloat arg2, CGPathCreateWithRoundedRect_T_arg3 arg3)
{
    #define RUN_FUNC  CGPathRef ret = real::CGPathCreateWithRoundedRect(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFDocumentGetInfo"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentGetInfo
// extra usings

INTERPOSE(CGPDFDocumentGetInfo)(CGPDFDocumentRef arg0)
{
    #define RUN_FUNC  CGPDFDictionaryRef ret = real::CGPDFDocumentGetInfo(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextSetStrokePattern"
#pragma push_macro(FUNC_ID)
#undef CGContextSetStrokePattern
// extra usings

INTERPOSE(CGContextSetStrokePattern)(CGContextRef arg0, CGPatternRef arg1, const double * arg2)
{
    #define RUN_FUNC  real::CGContextSetStrokePattern(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGImageGetDecode"
#pragma push_macro(FUNC_ID)
#undef CGImageGetDecode
// extra usings

INTERPOSE(CGImageGetDecode)(CGImageRef arg0)
{
    #define RUN_FUNC  const double * ret = real::CGImageGetDecode(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextFlush"
#pragma push_macro(FUNC_ID)
#undef CGContextFlush
// extra usings

INTERPOSE(CGContextFlush)(CGContextRef arg0)
{
    #define RUN_FUNC  real::CGContextFlush(arg0)

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

#define FUNC_ID "CGFontGetXHeight"
#pragma push_macro(FUNC_ID)
#undef CGFontGetXHeight
// extra usings

INTERPOSE(CGFontGetXHeight)(CGFontRef arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGFontGetXHeight(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFContextCreate"
#pragma push_macro(FUNC_ID)
#undef CGPDFContextCreate
// extra usings
using CGPDFContextCreate_T_arg1 = const CGRect *;
using CGPDFContextCreate_T_arg1 = const CGRect *;
INTERPOSE(CGPDFContextCreate)(CGDataConsumerRef arg0, CGPDFContextCreate_T_arg1 arg1, CFDictionaryRef arg2)
{
    #define RUN_FUNC  CGContextRef ret = real::CGPDFContextCreate(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGImageCreateWithJPEGDataProvider"
#pragma push_macro(FUNC_ID)
#undef CGImageCreateWithJPEGDataProvider
// extra usings

INTERPOSE(CGImageCreateWithJPEGDataProvider)(CGDataProviderRef arg0, const double * arg1, bool arg2, __int32_t arg3)
{
    #define RUN_FUNC  CGImageRef ret = real::CGImageCreateWithJPEGDataProvider(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFDocumentCreateWithURL"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentCreateWithURL
// extra usings

INTERPOSE(CGPDFDocumentCreateWithURL)(CFURLRef arg0)
{
    #define RUN_FUNC  CGPDFDocumentRef ret = real::CGPDFDocumentCreateWithURL(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPathAddArcToPoint"
#pragma push_macro(FUNC_ID)
#undef CGPathAddArcToPoint
// extra usings
using CGPathAddArcToPoint_T_arg1 = const CGAffineTransform *;
using CGPathAddArcToPoint_T_arg1 = const CGAffineTransform *;
INTERPOSE(CGPathAddArcToPoint)(CGMutablePathRef arg0, CGPathAddArcToPoint_T_arg1 arg1, CGFloat arg2, CGFloat arg3, CGFloat arg4, CGFloat arg5, CGFloat arg6)
{
    #define RUN_FUNC  real::CGPathAddArcToPoint(arg0, arg1, arg2, arg3, arg4, arg5, arg6)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGVectorMake"
#pragma push_macro(FUNC_ID)
#undef CGVectorMake
// extra usings

INTERPOSE(CGVectorMake)(CGFloat arg0, CGFloat arg1)
{
    #define RUN_FUNC  CGVector ret = real::CGVectorMake(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGDisplayIsActive"
#pragma push_macro(FUNC_ID)
#undef CGDisplayIsActive
// extra usings

INTERPOSE(CGDisplayIsActive)(__uint32_t arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGDisplayIsActive(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFScannerScan"
#pragma push_macro(FUNC_ID)
#undef CGPDFScannerScan
// extra usings

INTERPOSE(CGPDFScannerScan)(CGPDFScannerRef arg0)
{
    #define RUN_FUNC  bool ret = real::CGPDFScannerScan(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPathCreateMutableCopyByTransformingPath"
#pragma push_macro(FUNC_ID)
#undef CGPathCreateMutableCopyByTransformingPath
// extra usings
using CGPathCreateMutableCopyByTransformingPath_T_arg1 = const CGAffineTransform *;
using CGPathCreateMutableCopyByTransformingPath_T_arg1 = const CGAffineTransform *;
INTERPOSE(CGPathCreateMutableCopyByTransformingPath)(CGPathRef arg0, CGPathCreateMutableCopyByTransformingPath_T_arg1 arg1)
{
    #define RUN_FUNC  CGMutablePathRef ret = real::CGPathCreateMutableCopyByTransformingPath(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGSetDisplayTransferByTable"
#pragma push_macro(FUNC_ID)
#undef CGSetDisplayTransferByTable
// extra usings

INTERPOSE(CGSetDisplayTransferByTable)(__uint32_t arg0, __uint32_t arg1, const float * arg2, const float * arg3, const float * arg4)
{
    #define RUN_FUNC  __int32_t ret = real::CGSetDisplayTransferByTable(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGSetDisplayTransferByByteTable"
#pragma push_macro(FUNC_ID)
#undef CGSetDisplayTransferByByteTable
// extra usings

INTERPOSE(CGSetDisplayTransferByByteTable)(__uint32_t arg0, __uint32_t arg1, ConstStringPtr arg2, ConstStringPtr arg3, ConstStringPtr arg4)
{
    #define RUN_FUNC  __int32_t ret = real::CGSetDisplayTransferByByteTable(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGImageGetPixelFormatInfo"
#pragma push_macro(FUNC_ID)
#undef CGImageGetPixelFormatInfo
// extra usings

INTERPOSE(CGImageGetPixelFormatInfo)(CGImageRef arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGImageGetPixelFormatInfo(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGImageGetRenderingIntent"
#pragma push_macro(FUNC_ID)
#undef CGImageGetRenderingIntent
// extra usings

INTERPOSE(CGImageGetRenderingIntent)(CGImageRef arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGImageGetRenderingIntent(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFContextSetURLForRect"
#pragma push_macro(FUNC_ID)
#undef CGPDFContextSetURLForRect
// extra usings

INTERPOSE(CGPDFContextSetURLForRect)(CGContextRef arg0, CFURLRef arg1, CGRect arg2)
{
    #define RUN_FUNC  real::CGPDFContextSetURLForRect(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGEnableEventStateCombining"
#pragma push_macro(FUNC_ID)
#undef CGEnableEventStateCombining
// extra usings

INTERPOSE(CGEnableEventStateCombining)(__uint32_t arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGEnableEventStateCombining(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGColorSpaceCreateDeviceRGB"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceCreateDeviceRGB
// extra usings

INTERPOSE(CGColorSpaceCreateDeviceRGB)()
{
    #define RUN_FUNC  CGColorSpaceRef ret = real::CGColorSpaceCreateDeviceRGB()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPathEqualToPath"
#pragma push_macro(FUNC_ID)
#undef CGPathEqualToPath
// extra usings

INTERPOSE(CGPathEqualToPath)(CGPathRef arg0, CGPathRef arg1)
{
    #define RUN_FUNC  bool ret = real::CGPathEqualToPath(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFScannerPopObject"
#pragma push_macro(FUNC_ID)
#undef CGPDFScannerPopObject
// extra usings
using CGPDFScannerPopObject_T_arg1 = CGPDFObject **;
using CGPDFScannerPopObject_T_arg1 = CGPDFObject **;
INTERPOSE(CGPDFScannerPopObject)(CGPDFScannerRef arg0, CGPDFScannerPopObject_T_arg1 arg1)
{
    #define RUN_FUNC  bool ret = real::CGPDFScannerPopObject(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGDisplayIsCaptured"
#pragma push_macro(FUNC_ID)
#undef CGDisplayIsCaptured
// extra usings

INTERPOSE(CGDisplayIsCaptured)(__uint32_t arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGDisplayIsCaptured(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFPageRelease"
#pragma push_macro(FUNC_ID)
#undef CGPDFPageRelease
// extra usings

INTERPOSE(CGPDFPageRelease)(CGPDFPageRef arg0)
{
    #define RUN_FUNC  real::CGPDFPageRelease(arg0)

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

#define FUNC_ID "CGDisplayStreamStart"
#pragma push_macro(FUNC_ID)
#undef CGDisplayStreamStart
// extra usings

INTERPOSE(CGDisplayStreamStart)(CGDisplayStreamRef arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGDisplayStreamStart(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGRectIsEmpty"
#pragma push_macro(FUNC_ID)
#undef CGRectIsEmpty
// extra usings

INTERPOSE(CGRectIsEmpty)(CGRect arg0)
{
    #define RUN_FUNC  bool ret = real::CGRectIsEmpty(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayMoveCursorToPoint"
#pragma push_macro(FUNC_ID)
#undef CGDisplayMoveCursorToPoint
// extra usings

INTERPOSE(CGDisplayMoveCursorToPoint)(__uint32_t arg0, CGPoint arg1)
{
    #define RUN_FUNC  __int32_t ret = real::CGDisplayMoveCursorToPoint(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFScannerPopInteger"
#pragma push_macro(FUNC_ID)
#undef CGPDFScannerPopInteger
// extra usings
using CGPDFScannerPopInteger_T_arg1 = long *;
using CGPDFScannerPopInteger_T_arg1 = long *;
INTERPOSE(CGPDFScannerPopInteger)(CGPDFScannerRef arg0, CGPDFScannerPopInteger_T_arg1 arg1)
{
    #define RUN_FUNC  bool ret = real::CGPDFScannerPopInteger(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextStrokePath"
#pragma push_macro(FUNC_ID)
#undef CGContextStrokePath
// extra usings

INTERPOSE(CGContextStrokePath)(CGContextRef arg0)
{
    #define RUN_FUNC  real::CGContextStrokePath(arg0)

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

#define FUNC_ID "CGAffineTransformScale"
#pragma push_macro(FUNC_ID)
#undef CGAffineTransformScale
// extra usings

INTERPOSE(CGAffineTransformScale)(CGAffineTransform arg0, CGFloat arg1, CGFloat arg2)
{
    #define RUN_FUNC  CGAffineTransform ret = real::CGAffineTransformScale(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFDocumentGetArtBox"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentGetArtBox
// extra usings

INTERPOSE(CGPDFDocumentGetArtBox)(CGPDFDocumentRef arg0, __int32_t arg1)
{
    #define RUN_FUNC  CGRect ret = real::CGPDFDocumentGetArtBox(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGLayerRelease"
#pragma push_macro(FUNC_ID)
#undef CGLayerRelease
// extra usings

INTERPOSE(CGLayerRelease)(CGLayerRef arg0)
{
    #define RUN_FUNC  real::CGLayerRelease(arg0)

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

#define FUNC_ID "CGPDFArrayGetArray"
#pragma push_macro(FUNC_ID)
#undef CGPDFArrayGetArray
// extra usings
using CGPDFArrayGetArray_T_arg2 = CGPDFArray **;
using CGPDFArrayGetArray_T_arg2 = CGPDFArray **;
INTERPOSE(CGPDFArrayGetArray)(CGPDFArrayRef arg0, __darwin_size_t arg1, CGPDFArrayGetArray_T_arg2 arg2)
{
    #define RUN_FUNC  bool ret = real::CGPDFArrayGetArray(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGColorSpaceCopyPropertyList"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceCopyPropertyList
// extra usings

INTERPOSE(CGColorSpaceCopyPropertyList)(CGColorSpaceRef arg0)
{
    #define RUN_FUNC  const void * ret = real::CGColorSpaceCopyPropertyList(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDataProviderRelease"
#pragma push_macro(FUNC_ID)
#undef CGDataProviderRelease
// extra usings

INTERPOSE(CGDataProviderRelease)(CGDataProviderRef arg0)
{
    #define RUN_FUNC  real::CGDataProviderRelease(arg0)

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

#define FUNC_ID "CGPDFOperatorTableRetain"
#pragma push_macro(FUNC_ID)
#undef CGPDFOperatorTableRetain
// extra usings

INTERPOSE(CGPDFOperatorTableRetain)(CGPDFOperatorTableRef arg0)
{
    #define RUN_FUNC  CGPDFOperatorTableRef ret = real::CGPDFOperatorTableRetain(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGMainDisplayID"
#pragma push_macro(FUNC_ID)
#undef CGMainDisplayID
// extra usings

INTERPOSE(CGMainDisplayID)()
{
    #define RUN_FUNC  __uint32_t ret = real::CGMainDisplayID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGFontGetDescent"
#pragma push_macro(FUNC_ID)
#undef CGFontGetDescent
// extra usings

INTERPOSE(CGFontGetDescent)(CGFontRef arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGFontGetDescent(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPathAddRoundedRect"
#pragma push_macro(FUNC_ID)
#undef CGPathAddRoundedRect
// extra usings
using CGPathAddRoundedRect_T_arg1 = const CGAffineTransform *;
using CGPathAddRoundedRect_T_arg1 = const CGAffineTransform *;
INTERPOSE(CGPathAddRoundedRect)(CGMutablePathRef arg0, CGPathAddRoundedRect_T_arg1 arg1, CGRect arg2, CGFloat arg3, CGFloat arg4)
{
    #define RUN_FUNC  real::CGPathAddRoundedRect(arg0, arg1, arg2, arg3, arg4)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGRectGetMaxY"
#pragma push_macro(FUNC_ID)
#undef CGRectGetMaxY
// extra usings

INTERPOSE(CGRectGetMaxY)(CGRect arg0)
{
    #define RUN_FUNC  CGFloat ret = real::CGRectGetMaxY(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGBitmapContextGetWidth"
#pragma push_macro(FUNC_ID)
#undef CGBitmapContextGetWidth
// extra usings

INTERPOSE(CGBitmapContextGetWidth)(CGContextRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGBitmapContextGetWidth(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGShadingCreateRadial"
#pragma push_macro(FUNC_ID)
#undef CGShadingCreateRadial
// extra usings

INTERPOSE(CGShadingCreateRadial)(CGColorSpaceRef arg0, CGPoint arg1, CGFloat arg2, CGPoint arg3, CGFloat arg4, CGFunctionRef arg5, bool arg6, bool arg7)
{
    #define RUN_FUNC  CGShadingRef ret = real::CGShadingCreateRadial(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFScannerRetain"
#pragma push_macro(FUNC_ID)
#undef CGPDFScannerRetain
// extra usings

INTERPOSE(CGPDFScannerRetain)(CGPDFScannerRef arg0)
{
    #define RUN_FUNC  CGPDFScannerRef ret = real::CGPDFScannerRetain(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayMirrorsDisplay"
#pragma push_macro(FUNC_ID)
#undef CGDisplayMirrorsDisplay
// extra usings

INTERPOSE(CGDisplayMirrorsDisplay)(__uint32_t arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGDisplayMirrorsDisplay(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextAddRects"
#pragma push_macro(FUNC_ID)
#undef CGContextAddRects
// extra usings
using CGContextAddRects_T_arg1 = const CGRect *;
using CGContextAddRects_T_arg1 = const CGRect *;
INTERPOSE(CGContextAddRects)(CGContextRef arg0, CGContextAddRects_T_arg1 arg1, __darwin_size_t arg2)
{
    #define RUN_FUNC  real::CGContextAddRects(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGDataConsumerCreateWithURL"
#pragma push_macro(FUNC_ID)
#undef CGDataConsumerCreateWithURL
// extra usings

INTERPOSE(CGDataConsumerCreateWithURL)(CFURLRef arg0)
{
    #define RUN_FUNC  CGDataConsumerRef ret = real::CGDataConsumerCreateWithURL(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPathApply"
#pragma push_macro(FUNC_ID)
#undef CGPathApply
// extra usings

INTERPOSE(CGPathApply)(CGPathRef arg0, void * arg1, CGPathApplierFunction arg2)
{
    #define RUN_FUNC  real::CGPathApply(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGContextConvertRectToUserSpace"
#pragma push_macro(FUNC_ID)
#undef CGContextConvertRectToUserSpace
// extra usings

INTERPOSE(CGContextConvertRectToUserSpace)(CGContextRef arg0, CGRect arg1)
{
    #define RUN_FUNC  CGRect ret = real::CGContextConvertRectToUserSpace(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGGradientCreateWithColors"
#pragma push_macro(FUNC_ID)
#undef CGGradientCreateWithColors
// extra usings

INTERPOSE(CGGradientCreateWithColors)(CGColorSpaceRef arg0, CFArrayRef arg1, const double * arg2)
{
    #define RUN_FUNC  CGGradientRef ret = real::CGGradientCreateWithColors(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPathIsRect"
#pragma push_macro(FUNC_ID)
#undef CGPathIsRect
// extra usings

INTERPOSE(CGPathIsRect)(CGPathRef arg0, CGRect * arg1)
{
    #define RUN_FUNC  bool ret = real::CGPathIsRect(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGGetDisplaysWithOpenGLDisplayMask"
#pragma push_macro(FUNC_ID)
#undef CGGetDisplaysWithOpenGLDisplayMask
// extra usings

INTERPOSE(CGGetDisplaysWithOpenGLDisplayMask)(__uint32_t arg0, __uint32_t arg1, UnsignedFixedPtr arg2, UnsignedFixedPtr arg3)
{
    #define RUN_FUNC  __int32_t ret = real::CGGetDisplaysWithOpenGLDisplayMask(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGImageRetain"
#pragma push_macro(FUNC_ID)
#undef CGImageRetain
// extra usings

INTERPOSE(CGImageRetain)(CGImageRef arg0)
{
    #define RUN_FUNC  CGImageRef ret = real::CGImageRetain(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextAddArc"
#pragma push_macro(FUNC_ID)
#undef CGContextAddArc
// extra usings

INTERPOSE(CGContextAddArc)(CGContextRef arg0, CGFloat arg1, CGFloat arg2, CGFloat arg3, CGFloat arg4, CGFloat arg5, __int32_t arg6)
{
    #define RUN_FUNC  real::CGContextAddArc(arg0, arg1, arg2, arg3, arg4, arg5, arg6)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGFontCreateWithPlatformFont"
#pragma push_macro(FUNC_ID)
#undef CGFontCreateWithPlatformFont
// extra usings

INTERPOSE(CGFontCreateWithPlatformFont)(void * arg0)
{
    #define RUN_FUNC  CGFontRef ret = real::CGFontCreateWithPlatformFont(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGRectIntersectsRect"
#pragma push_macro(FUNC_ID)
#undef CGRectIntersectsRect
// extra usings

INTERPOSE(CGRectIntersectsRect)(CGRect arg0, CGRect arg1)
{
    #define RUN_FUNC  bool ret = real::CGRectIntersectsRect(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGCompleteDisplayConfiguration"
#pragma push_macro(FUNC_ID)
#undef CGCompleteDisplayConfiguration
// extra usings

INTERPOSE(CGCompleteDisplayConfiguration)(CGDisplayConfigRef arg0, __uint32_t arg1)
{
    #define RUN_FUNC  __int32_t ret = real::CGCompleteDisplayConfiguration(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGAffineTransformTranslate"
#pragma push_macro(FUNC_ID)
#undef CGAffineTransformTranslate
// extra usings

INTERPOSE(CGAffineTransformTranslate)(CGAffineTransform arg0, CGFloat arg1, CGFloat arg2)
{
    #define RUN_FUNC  CGAffineTransform ret = real::CGAffineTransformTranslate(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextAddCurveToPoint"
#pragma push_macro(FUNC_ID)
#undef CGContextAddCurveToPoint
// extra usings

INTERPOSE(CGContextAddCurveToPoint)(CGContextRef arg0, CGFloat arg1, CGFloat arg2, CGFloat arg3, CGFloat arg4, CGFloat arg5, CGFloat arg6)
{
    #define RUN_FUNC  real::CGContextAddCurveToPoint(arg0, arg1, arg2, arg3, arg4, arg5, arg6)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPDFContentStreamCreateWithPage"
#pragma push_macro(FUNC_ID)
#undef CGPDFContentStreamCreateWithPage
// extra usings

INTERPOSE(CGPDFContentStreamCreateWithPage)(CGPDFPageRef arg0)
{
    #define RUN_FUNC  CGPDFContentStreamRef ret = real::CGPDFContentStreamCreateWithPage(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGScreenUnregisterMoveCallback"
#pragma push_macro(FUNC_ID)
#undef CGScreenUnregisterMoveCallback
// extra usings

INTERPOSE(CGScreenUnregisterMoveCallback)(CGScreenUpdateMoveCallback arg0, void * arg1)
{
    #define RUN_FUNC  real::CGScreenUnregisterMoveCallback(arg0, arg1)

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

#define FUNC_ID "CGPDFScannerPopStream"
#pragma push_macro(FUNC_ID)
#undef CGPDFScannerPopStream
// extra usings
using CGPDFScannerPopStream_T_arg1 = CGPDFStream **;
using CGPDFScannerPopStream_T_arg1 = CGPDFStream **;
INTERPOSE(CGPDFScannerPopStream)(CGPDFScannerRef arg0, CGPDFScannerPopStream_T_arg1 arg1)
{
    #define RUN_FUNC  bool ret = real::CGPDFScannerPopStream(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextSetFillColorSpace"
#pragma push_macro(FUNC_ID)
#undef CGContextSetFillColorSpace
// extra usings

INTERPOSE(CGContextSetFillColorSpace)(CGContextRef arg0, CGColorSpaceRef arg1)
{
    #define RUN_FUNC  real::CGContextSetFillColorSpace(arg0, arg1)

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

#define FUNC_ID "CGFontGetGlyphWithGlyphName"
#pragma push_macro(FUNC_ID)
#undef CGFontGetGlyphWithGlyphName
// extra usings

INTERPOSE(CGFontGetGlyphWithGlyphName)(CGFontRef arg0, CFStringRef arg1)
{
    #define RUN_FUNC  __uint16_t ret = real::CGFontGetGlyphWithGlyphName(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGFunctionRetain"
#pragma push_macro(FUNC_ID)
#undef CGFunctionRetain
// extra usings

INTERPOSE(CGFunctionRetain)(CGFunctionRef arg0)
{
    #define RUN_FUNC  CGFunctionRef ret = real::CGFunctionRetain(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextConvertPointToUserSpace"
#pragma push_macro(FUNC_ID)
#undef CGContextConvertPointToUserSpace
// extra usings

INTERPOSE(CGContextConvertPointToUserSpace)(CGContextRef arg0, CGPoint arg1)
{
    #define RUN_FUNC  CGPoint ret = real::CGContextConvertPointToUserSpace(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGColorSpaceCopyName"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceCopyName
// extra usings

INTERPOSE(CGColorSpaceCopyName)(CGColorSpaceRef arg0)
{
    #define RUN_FUNC  CFStringRef ret = real::CGColorSpaceCopyName(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPatternRelease"
#pragma push_macro(FUNC_ID)
#undef CGPatternRelease
// extra usings

INTERPOSE(CGPatternRelease)(CGPatternRef arg0)
{
    #define RUN_FUNC  real::CGPatternRelease(arg0)

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

#define FUNC_ID "CGPointEqualToPoint"
#pragma push_macro(FUNC_ID)
#undef CGPointEqualToPoint
// extra usings

INTERPOSE(CGPointEqualToPoint)(CGPoint arg0, CGPoint arg1)
{
    #define RUN_FUNC  bool ret = real::CGPointEqualToPoint(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGCursorIsDrawnInFramebuffer"
#pragma push_macro(FUNC_ID)
#undef CGCursorIsDrawnInFramebuffer
// extra usings

INTERPOSE(CGCursorIsDrawnInFramebuffer)()
{
    #define RUN_FUNC  __uint32_t ret = real::CGCursorIsDrawnInFramebuffer()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGDisplayCaptureWithOptions"
#pragma push_macro(FUNC_ID)
#undef CGDisplayCaptureWithOptions
// extra usings

INTERPOSE(CGDisplayCaptureWithOptions)(__uint32_t arg0, __uint32_t arg1)
{
    #define RUN_FUNC  __int32_t ret = real::CGDisplayCaptureWithOptions(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGDisplayIsStereo"
#pragma push_macro(FUNC_ID)
#undef CGDisplayIsStereo
// extra usings

INTERPOSE(CGDisplayIsStereo)(__uint32_t arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGDisplayIsStereo(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFTagTypeGetName"
#pragma push_macro(FUNC_ID)
#undef CGPDFTagTypeGetName
// extra usings

INTERPOSE(CGPDFTagTypeGetName)(__int32_t arg0)
{
    #define RUN_FUNC  const char * ret = real::CGPDFTagTypeGetName(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGBitmapContextGetBytesPerRow"
#pragma push_macro(FUNC_ID)
#undef CGBitmapContextGetBytesPerRow
// extra usings

INTERPOSE(CGBitmapContextGetBytesPerRow)(CGContextRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGBitmapContextGetBytesPerRow(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextBeginTransparencyLayer"
#pragma push_macro(FUNC_ID)
#undef CGContextBeginTransparencyLayer
// extra usings

INTERPOSE(CGContextBeginTransparencyLayer)(CGContextRef arg0, CFDictionaryRef arg1)
{
    #define RUN_FUNC  real::CGContextBeginTransparencyLayer(arg0, arg1)

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

#define FUNC_ID "CGFontRetain"
#pragma push_macro(FUNC_ID)
#undef CGFontRetain
// extra usings

INTERPOSE(CGFontRetain)(CGFontRef arg0)
{
    #define RUN_FUNC  CGFontRef ret = real::CGFontRetain(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextSetLineDash"
#pragma push_macro(FUNC_ID)
#undef CGContextSetLineDash
// extra usings

INTERPOSE(CGContextSetLineDash)(CGContextRef arg0, CGFloat arg1, const double * arg2, __darwin_size_t arg3)
{
    #define RUN_FUNC  real::CGContextSetLineDash(arg0, arg1, arg2, arg3)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGColorSpaceCreateICCBased"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceCreateICCBased
// extra usings

INTERPOSE(CGColorSpaceCreateICCBased)(__darwin_size_t arg0, const double * arg1, CGDataProviderRef arg2, CGColorSpaceRef arg3)
{
    #define RUN_FUNC  CGColorSpaceRef ret = real::CGColorSpaceCreateICCBased(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextSetGrayStrokeColor"
#pragma push_macro(FUNC_ID)
#undef CGContextSetGrayStrokeColor
// extra usings

INTERPOSE(CGContextSetGrayStrokeColor)(CGContextRef arg0, CGFloat arg1, CGFloat arg2)
{
    #define RUN_FUNC  real::CGContextSetGrayStrokeColor(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPDFOperatorTableRelease"
#pragma push_macro(FUNC_ID)
#undef CGPDFOperatorTableRelease
// extra usings

INTERPOSE(CGPDFOperatorTableRelease)(CGPDFOperatorTableRef arg0)
{
    #define RUN_FUNC  real::CGPDFOperatorTableRelease(arg0)

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

#define FUNC_ID "CGContextGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CGContextGetTypeID
// extra usings

INTERPOSE(CGContextGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGContextGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGRectOffset"
#pragma push_macro(FUNC_ID)
#undef CGRectOffset
// extra usings

INTERPOSE(CGRectOffset)(CGRect arg0, CGFloat arg1, CGFloat arg2)
{
    #define RUN_FUNC  CGRect ret = real::CGRectOffset(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGColorSpaceCreateCalibratedGray"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceCreateCalibratedGray
// extra usings

INTERPOSE(CGColorSpaceCreateCalibratedGray)(const double * arg0, const double * arg1, CGFloat arg2)
{
    #define RUN_FUNC  CGColorSpaceRef ret = real::CGColorSpaceCreateCalibratedGray(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextSetRenderingIntent"
#pragma push_macro(FUNC_ID)
#undef CGContextSetRenderingIntent
// extra usings

INTERPOSE(CGContextSetRenderingIntent)(CGContextRef arg0, __int32_t arg1)
{
    #define RUN_FUNC  real::CGContextSetRenderingIntent(arg0, arg1)

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

#define FUNC_ID "CGDisplayCurrentMode"
#pragma push_macro(FUNC_ID)
#undef CGDisplayCurrentMode
// extra usings

INTERPOSE(CGDisplayCurrentMode)(__uint32_t arg0)
{
    #define RUN_FUNC  CFDictionaryRef ret = real::CGDisplayCurrentMode(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGConfigureDisplayWithDisplayMode"
#pragma push_macro(FUNC_ID)
#undef CGConfigureDisplayWithDisplayMode
// extra usings

INTERPOSE(CGConfigureDisplayWithDisplayMode)(CGDisplayConfigRef arg0, __uint32_t arg1, CGDisplayModeRef arg2, CFDictionaryRef arg3)
{
    #define RUN_FUNC  __int32_t ret = real::CGConfigureDisplayWithDisplayMode(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGCursorIsVisible"
#pragma push_macro(FUNC_ID)
#undef CGCursorIsVisible
// extra usings

INTERPOSE(CGCursorIsVisible)()
{
    #define RUN_FUNC  __uint32_t ret = real::CGCursorIsVisible()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGDisplayIsMain"
#pragma push_macro(FUNC_ID)
#undef CGDisplayIsMain
// extra usings

INTERPOSE(CGDisplayIsMain)(__uint32_t arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGDisplayIsMain(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGSetLocalEventsFilterDuringSuppressionState"
#pragma push_macro(FUNC_ID)
#undef CGSetLocalEventsFilterDuringSuppressionState
// extra usings

INTERPOSE(CGSetLocalEventsFilterDuringSuppressionState)(__uint32_t arg0, __uint32_t arg1)
{
    #define RUN_FUNC  __int32_t ret = real::CGSetLocalEventsFilterDuringSuppressionState(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFDictionaryGetNumber"
#pragma push_macro(FUNC_ID)
#undef CGPDFDictionaryGetNumber
// extra usings
using CGPDFDictionaryGetNumber_T_arg2 = double *;
using CGPDFDictionaryGetNumber_T_arg2 = double *;
INTERPOSE(CGPDFDictionaryGetNumber)(CGPDFDictionaryRef arg0, const char * arg1, CGPDFDictionaryGetNumber_T_arg2 arg2)
{
    #define RUN_FUNC  bool ret = real::CGPDFDictionaryGetNumber(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGAssociateMouseAndMouseCursorPosition"
#pragma push_macro(FUNC_ID)
#undef CGAssociateMouseAndMouseCursorPosition
// extra usings

INTERPOSE(CGAssociateMouseAndMouseCursorPosition)(__uint32_t arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGAssociateMouseAndMouseCursorPosition(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFDocumentAllowsPrinting"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentAllowsPrinting
// extra usings

INTERPOSE(CGPDFDocumentAllowsPrinting)(CGPDFDocumentRef arg0)
{
    #define RUN_FUNC  bool ret = real::CGPDFDocumentAllowsPrinting(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextSetBlendMode"
#pragma push_macro(FUNC_ID)
#undef CGContextSetBlendMode
// extra usings

INTERPOSE(CGContextSetBlendMode)(CGContextRef arg0, __int32_t arg1)
{
    #define RUN_FUNC  real::CGContextSetBlendMode(arg0, arg1)

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

#define FUNC_ID "CGFontGetGlyphAdvances"
#pragma push_macro(FUNC_ID)
#undef CGFontGetGlyphAdvances
// extra usings

INTERPOSE(CGFontGetGlyphAdvances)(CGFontRef arg0, const unsigned short * arg1, __darwin_size_t arg2, FixedPtr arg3)
{
    #define RUN_FUNC  bool ret = real::CGFontGetGlyphAdvances(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextReplacePathWithStrokedPath"
#pragma push_macro(FUNC_ID)
#undef CGContextReplacePathWithStrokedPath
// extra usings

INTERPOSE(CGContextReplacePathWithStrokedPath)(CGContextRef arg0)
{
    #define RUN_FUNC  real::CGContextReplacePathWithStrokedPath(arg0)

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

#define FUNC_ID "CGGetDisplayTransferByFormula"
#pragma push_macro(FUNC_ID)
#undef CGGetDisplayTransferByFormula
// extra usings
using CGGetDisplayTransferByFormula_T_arg1 = float *;
using CGGetDisplayTransferByFormula_T_arg2 = float *;
using CGGetDisplayTransferByFormula_T_arg3 = float *;
using CGGetDisplayTransferByFormula_T_arg4 = float *;
using CGGetDisplayTransferByFormula_T_arg5 = float *;
using CGGetDisplayTransferByFormula_T_arg6 = float *;
using CGGetDisplayTransferByFormula_T_arg7 = float *;
using CGGetDisplayTransferByFormula_T_arg8 = float *;
using CGGetDisplayTransferByFormula_T_arg9 = float *;
using CGGetDisplayTransferByFormula_T_arg1 = float *;
using CGGetDisplayTransferByFormula_T_arg2 = float *;
using CGGetDisplayTransferByFormula_T_arg3 = float *;
using CGGetDisplayTransferByFormula_T_arg4 = float *;
using CGGetDisplayTransferByFormula_T_arg5 = float *;
using CGGetDisplayTransferByFormula_T_arg6 = float *;
using CGGetDisplayTransferByFormula_T_arg7 = float *;
using CGGetDisplayTransferByFormula_T_arg8 = float *;
using CGGetDisplayTransferByFormula_T_arg9 = float *;
INTERPOSE(CGGetDisplayTransferByFormula)(__uint32_t arg0, CGGetDisplayTransferByFormula_T_arg1 arg1, CGGetDisplayTransferByFormula_T_arg2 arg2, CGGetDisplayTransferByFormula_T_arg3 arg3, CGGetDisplayTransferByFormula_T_arg4 arg4, CGGetDisplayTransferByFormula_T_arg5 arg5, CGGetDisplayTransferByFormula_T_arg6 arg6, CGGetDisplayTransferByFormula_T_arg7 arg7, CGGetDisplayTransferByFormula_T_arg8 arg8, CGGetDisplayTransferByFormula_T_arg9 arg9)
{
    #define RUN_FUNC  __int32_t ret = real::CGGetDisplayTransferByFormula(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGDisplayIsInHWMirrorSet"
#pragma push_macro(FUNC_ID)
#undef CGDisplayIsInHWMirrorSet
// extra usings

INTERPOSE(CGDisplayIsInHWMirrorSet)(__uint32_t arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGDisplayIsInHWMirrorSet(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayCapture"
#pragma push_macro(FUNC_ID)
#undef CGDisplayCapture
// extra usings

INTERPOSE(CGDisplayCapture)(__uint32_t arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGDisplayCapture(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGColorSpaceGetName"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceGetName
// extra usings

INTERPOSE(CGColorSpaceGetName)(CGColorSpaceRef arg0)
{
    #define RUN_FUNC  CFStringRef ret = real::CGColorSpaceGetName(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGImageGetAlphaInfo"
#pragma push_macro(FUNC_ID)
#undef CGImageGetAlphaInfo
// extra usings

INTERPOSE(CGImageGetAlphaInfo)(CGImageRef arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGImageGetAlphaInfo(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGSizeCreateDictionaryRepresentation"
#pragma push_macro(FUNC_ID)
#undef CGSizeCreateDictionaryRepresentation
// extra usings

INTERPOSE(CGSizeCreateDictionaryRepresentation)(CGSize arg0)
{
    #define RUN_FUNC  CFDictionaryRef ret = real::CGSizeCreateDictionaryRepresentation(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFStringGetLength"
#pragma push_macro(FUNC_ID)
#undef CGPDFStringGetLength
// extra usings

INTERPOSE(CGPDFStringGetLength)(CGPDFStringRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGPDFStringGetLength(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGScreenRegisterMoveCallback"
#pragma push_macro(FUNC_ID)
#undef CGScreenRegisterMoveCallback
// extra usings

INTERPOSE(CGScreenRegisterMoveCallback)(CGScreenUpdateMoveCallback arg0, void * arg1)
{
    #define RUN_FUNC  __int32_t ret = real::CGScreenRegisterMoveCallback(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGColorConversionInfoGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CGColorConversionInfoGetTypeID
// extra usings

INTERPOSE(CGColorConversionInfoGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGColorConversionInfoGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPDFDocumentRetain"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentRetain
// extra usings

INTERPOSE(CGPDFDocumentRetain)(CGPDFDocumentRef arg0)
{
    #define RUN_FUNC  CGPDFDocumentRef ret = real::CGPDFDocumentRetain(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGWaitForScreenUpdateRects"
#pragma push_macro(FUNC_ID)
#undef CGWaitForScreenUpdateRects
// extra usings

INTERPOSE(CGWaitForScreenUpdateRects)(__uint32_t arg0, UnsignedFixedPtr arg1, CGRect ** arg2, UniCharCountPtr arg3, CGScreenUpdateMoveDelta * arg4)
{
    #define RUN_FUNC  __int32_t ret = real::CGWaitForScreenUpdateRects(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGDisplayModeGetPixelHeight"
#pragma push_macro(FUNC_ID)
#undef CGDisplayModeGetPixelHeight
// extra usings

INTERPOSE(CGDisplayModeGetPixelHeight)(CGDisplayModeRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGDisplayModeGetPixelHeight(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextDrawTiledImage"
#pragma push_macro(FUNC_ID)
#undef CGContextDrawTiledImage
// extra usings

INTERPOSE(CGContextDrawTiledImage)(CGContextRef arg0, CGRect arg1, CGImageRef arg2)
{
    #define RUN_FUNC  real::CGContextDrawTiledImage(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGBitmapContextGetBitsPerComponent"
#pragma push_macro(FUNC_ID)
#undef CGBitmapContextGetBitsPerComponent
// extra usings

INTERPOSE(CGBitmapContextGetBitsPerComponent)(CGContextRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGBitmapContextGetBitsPerComponent(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextAddPath"
#pragma push_macro(FUNC_ID)
#undef CGContextAddPath
// extra usings

INTERPOSE(CGContextAddPath)(CGContextRef arg0, CGPathRef arg1)
{
    #define RUN_FUNC  real::CGContextAddPath(arg0, arg1)

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

#define FUNC_ID "CGConfigureDisplayOrigin"
#pragma push_macro(FUNC_ID)
#undef CGConfigureDisplayOrigin
// extra usings

INTERPOSE(CGConfigureDisplayOrigin)(CGDisplayConfigRef arg0, __uint32_t arg1, __int32_t arg2, __int32_t arg3)
{
    #define RUN_FUNC  __int32_t ret = real::CGConfigureDisplayOrigin(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextSetCharacterSpacing"
#pragma push_macro(FUNC_ID)
#undef CGContextSetCharacterSpacing
// extra usings

INTERPOSE(CGContextSetCharacterSpacing)(CGContextRef arg0, CGFloat arg1)
{
    #define RUN_FUNC  real::CGContextSetCharacterSpacing(arg0, arg1)

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

#define FUNC_ID "CGOpenGLDisplayMaskToDisplayID"
#pragma push_macro(FUNC_ID)
#undef CGOpenGLDisplayMaskToDisplayID
// extra usings

INTERPOSE(CGOpenGLDisplayMaskToDisplayID)(__uint32_t arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGOpenGLDisplayMaskToDisplayID(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFArrayGetNumber"
#pragma push_macro(FUNC_ID)
#undef CGPDFArrayGetNumber
// extra usings
using CGPDFArrayGetNumber_T_arg2 = double *;
using CGPDFArrayGetNumber_T_arg2 = double *;
INTERPOSE(CGPDFArrayGetNumber)(CGPDFArrayRef arg0, __darwin_size_t arg1, CGPDFArrayGetNumber_T_arg2 arg2)
{
    #define RUN_FUNC  bool ret = real::CGPDFArrayGetNumber(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGDisplaySetDisplayMode"
#pragma push_macro(FUNC_ID)
#undef CGDisplaySetDisplayMode
// extra usings

INTERPOSE(CGDisplaySetDisplayMode)(__uint32_t arg0, CGDisplayModeRef arg1, CFDictionaryRef arg2)
{
    #define RUN_FUNC  __int32_t ret = real::CGDisplaySetDisplayMode(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGRectIsNull"
#pragma push_macro(FUNC_ID)
#undef CGRectIsNull
// extra usings

INTERPOSE(CGRectIsNull)(CGRect arg0)
{
    #define RUN_FUNC  bool ret = real::CGRectIsNull(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDataConsumerRelease"
#pragma push_macro(FUNC_ID)
#undef CGDataConsumerRelease
// extra usings

INTERPOSE(CGDataConsumerRelease)(CGDataConsumerRef arg0)
{
    #define RUN_FUNC  real::CGDataConsumerRelease(arg0)

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

#define FUNC_ID "CGColorSpaceCreateWithICCProfile"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceCreateWithICCProfile
// extra usings

INTERPOSE(CGColorSpaceCreateWithICCProfile)(CFDataRef arg0)
{
    #define RUN_FUNC  CGColorSpaceRef ret = real::CGColorSpaceCreateWithICCProfile(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayModeGetWidth"
#pragma push_macro(FUNC_ID)
#undef CGDisplayModeGetWidth
// extra usings

INTERPOSE(CGDisplayModeGetWidth)(CGDisplayModeRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGDisplayModeGetWidth(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGCaptureAllDisplays"
#pragma push_macro(FUNC_ID)
#undef CGCaptureAllDisplays
// extra usings

INTERPOSE(CGCaptureAllDisplays)()
{
    #define RUN_FUNC  __int32_t ret = real::CGCaptureAllDisplays()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPDFScannerPopArray"
#pragma push_macro(FUNC_ID)
#undef CGPDFScannerPopArray
// extra usings
using CGPDFScannerPopArray_T_arg1 = CGPDFArray **;
using CGPDFScannerPopArray_T_arg1 = CGPDFArray **;
INTERPOSE(CGPDFScannerPopArray)(CGPDFScannerRef arg0, CGPDFScannerPopArray_T_arg1 arg1)
{
    #define RUN_FUNC  bool ret = real::CGPDFScannerPopArray(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextClipToRect"
#pragma push_macro(FUNC_ID)
#undef CGContextClipToRect
// extra usings

INTERPOSE(CGContextClipToRect)(CGContextRef arg0, CGRect arg1)
{
    #define RUN_FUNC  real::CGContextClipToRect(arg0, arg1)

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

#define FUNC_ID "CGDisplayStreamUpdateCreateMergedUpdate"
#pragma push_macro(FUNC_ID)
#undef CGDisplayStreamUpdateCreateMergedUpdate
// extra usings

INTERPOSE(CGDisplayStreamUpdateCreateMergedUpdate)(CGDisplayStreamUpdateRef arg0, CGDisplayStreamUpdateRef arg1)
{
    #define RUN_FUNC  CGDisplayStreamUpdateRef ret = real::CGDisplayStreamUpdateCreateMergedUpdate(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGDisplayHideCursor"
#pragma push_macro(FUNC_ID)
#undef CGDisplayHideCursor
// extra usings

INTERPOSE(CGDisplayHideCursor)(__uint32_t arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGDisplayHideCursor(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFDocumentGetPage"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentGetPage
// extra usings

INTERPOSE(CGPDFDocumentGetPage)(CGPDFDocumentRef arg0, __darwin_size_t arg1)
{
    #define RUN_FUNC  CGPDFPageRef ret = real::CGPDFDocumentGetPage(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGSessionCopyCurrentDictionary"
#pragma push_macro(FUNC_ID)
#undef CGSessionCopyCurrentDictionary
// extra usings

INTERPOSE(CGSessionCopyCurrentDictionary)()
{
    #define RUN_FUNC  CFDictionaryRef ret = real::CGSessionCopyCurrentDictionary()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGFontGetFontBBox"
#pragma push_macro(FUNC_ID)
#undef CGFontGetFontBBox
// extra usings

INTERPOSE(CGFontGetFontBBox)(CGFontRef arg0)
{
    #define RUN_FUNC  CGRect ret = real::CGFontGetFontBBox(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGImageGetBitsPerComponent"
#pragma push_macro(FUNC_ID)
#undef CGImageGetBitsPerComponent
// extra usings

INTERPOSE(CGImageGetBitsPerComponent)(CGImageRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGImageGetBitsPerComponent(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGFontCopyTableTags"
#pragma push_macro(FUNC_ID)
#undef CGFontCopyTableTags
// extra usings

INTERPOSE(CGFontCopyTableTags)(CGFontRef arg0)
{
    #define RUN_FUNC  CFArrayRef ret = real::CGFontCopyTableTags(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGWaitForScreenRefreshRects"
#pragma push_macro(FUNC_ID)
#undef CGWaitForScreenRefreshRects
// extra usings

INTERPOSE(CGWaitForScreenRefreshRects)(CGRect ** arg0, UnsignedFixedPtr arg1)
{
    #define RUN_FUNC  __int32_t ret = real::CGWaitForScreenRefreshRects(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGDataProviderCreateDirect"
#pragma push_macro(FUNC_ID)
#undef CGDataProviderCreateDirect
// extra usings

INTERPOSE(CGDataProviderCreateDirect)(void * arg0, __int64_t arg1, const CGDataProviderDirectCallbacks * arg2)
{
    #define RUN_FUNC  CGDataProviderRef ret = real::CGDataProviderCreateDirect(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGDisplayStreamStop"
#pragma push_macro(FUNC_ID)
#undef CGDisplayStreamStop
// extra usings

INTERPOSE(CGDisplayStreamStop)(CGDisplayStreamRef arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGDisplayStreamStop(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGShadingRetain"
#pragma push_macro(FUNC_ID)
#undef CGShadingRetain
// extra usings

INTERPOSE(CGShadingRetain)(CGShadingRef arg0)
{
    #define RUN_FUNC  CGShadingRef ret = real::CGShadingRetain(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGBitmapContextGetColorSpace"
#pragma push_macro(FUNC_ID)
#undef CGBitmapContextGetColorSpace
// extra usings

INTERPOSE(CGBitmapContextGetColorSpace)(CGContextRef arg0)
{
    #define RUN_FUNC  CGColorSpaceRef ret = real::CGBitmapContextGetColorSpace(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextShowTextAtPoint"
#pragma push_macro(FUNC_ID)
#undef CGContextShowTextAtPoint
// extra usings

INTERPOSE(CGContextShowTextAtPoint)(CGContextRef arg0, CGFloat arg1, CGFloat arg2, const char * arg3, __darwin_size_t arg4)
{
    #define RUN_FUNC  real::CGContextShowTextAtPoint(arg0, arg1, arg2, arg3, arg4)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGBitmapContextCreateImage"
#pragma push_macro(FUNC_ID)
#undef CGBitmapContextCreateImage
// extra usings

INTERPOSE(CGBitmapContextCreateImage)(CGContextRef arg0)
{
    #define RUN_FUNC  CGImageRef ret = real::CGBitmapContextCreateImage(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextTranslateCTM"
#pragma push_macro(FUNC_ID)
#undef CGContextTranslateCTM
// extra usings

INTERPOSE(CGContextTranslateCTM)(CGContextRef arg0, CGFloat arg1, CGFloat arg2)
{
    #define RUN_FUNC  real::CGContextTranslateCTM(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGDisplayModelNumber"
#pragma push_macro(FUNC_ID)
#undef CGDisplayModelNumber
// extra usings

INTERPOSE(CGDisplayModelNumber)(__uint32_t arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGDisplayModelNumber(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFContextCreateWithURL"
#pragma push_macro(FUNC_ID)
#undef CGPDFContextCreateWithURL
// extra usings
using CGPDFContextCreateWithURL_T_arg1 = const CGRect *;
using CGPDFContextCreateWithURL_T_arg1 = const CGRect *;
INTERPOSE(CGPDFContextCreateWithURL)(CFURLRef arg0, CGPDFContextCreateWithURL_T_arg1 arg1, CFDictionaryRef arg2)
{
    #define RUN_FUNC  CGContextRef ret = real::CGPDFContextCreateWithURL(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGColorSpaceCopyICCProfile"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceCopyICCProfile
// extra usings

INTERPOSE(CGColorSpaceCopyICCProfile)(CGColorSpaceRef arg0)
{
    #define RUN_FUNC  CFDataRef ret = real::CGColorSpaceCopyICCProfile(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextSetRGBStrokeColor"
#pragma push_macro(FUNC_ID)
#undef CGContextSetRGBStrokeColor
// extra usings

INTERPOSE(CGContextSetRGBStrokeColor)(CGContextRef arg0, CGFloat arg1, CGFloat arg2, CGFloat arg3, CGFloat arg4)
{
    #define RUN_FUNC  real::CGContextSetRGBStrokeColor(arg0, arg1, arg2, arg3, arg4)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGRectGetMidX"
#pragma push_macro(FUNC_ID)
#undef CGRectGetMidX
// extra usings

INTERPOSE(CGRectGetMidX)(CGRect arg0)
{
    #define RUN_FUNC  CGFloat ret = real::CGRectGetMidX(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayModeRelease"
#pragma push_macro(FUNC_ID)
#undef CGDisplayModeRelease
// extra usings

INTERPOSE(CGDisplayModeRelease)(CGDisplayModeRef arg0)
{
    #define RUN_FUNC  real::CGDisplayModeRelease(arg0)

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

#define FUNC_ID "CGImageGetDataProvider"
#pragma push_macro(FUNC_ID)
#undef CGImageGetDataProvider
// extra usings

INTERPOSE(CGImageGetDataProvider)(CGImageRef arg0)
{
    #define RUN_FUNC  CGDataProviderRef ret = real::CGImageGetDataProvider(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextConvertRectToDeviceSpace"
#pragma push_macro(FUNC_ID)
#undef CGContextConvertRectToDeviceSpace
// extra usings

INTERPOSE(CGContextConvertRectToDeviceSpace)(CGContextRef arg0, CGRect arg1)
{
    #define RUN_FUNC  CGRect ret = real::CGContextConvertRectToDeviceSpace(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGImageCreateWithMaskingColors"
#pragma push_macro(FUNC_ID)
#undef CGImageCreateWithMaskingColors
// extra usings

INTERPOSE(CGImageCreateWithMaskingColors)(CGImageRef arg0, const double * arg1)
{
    #define RUN_FUNC  CGImageRef ret = real::CGImageCreateWithMaskingColors(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFDictionaryGetInteger"
#pragma push_macro(FUNC_ID)
#undef CGPDFDictionaryGetInteger
// extra usings
using CGPDFDictionaryGetInteger_T_arg2 = long *;
using CGPDFDictionaryGetInteger_T_arg2 = long *;
INTERPOSE(CGPDFDictionaryGetInteger)(CGPDFDictionaryRef arg0, const char * arg1, CGPDFDictionaryGetInteger_T_arg2 arg2)
{
    #define RUN_FUNC  bool ret = real::CGPDFDictionaryGetInteger(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGColorGetAlpha"
#pragma push_macro(FUNC_ID)
#undef CGColorGetAlpha
// extra usings

INTERPOSE(CGColorGetAlpha)(CGColorRef arg0)
{
    #define RUN_FUNC  CGFloat ret = real::CGColorGetAlpha(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextSetAllowsFontSubpixelPositioning"
#pragma push_macro(FUNC_ID)
#undef CGContextSetAllowsFontSubpixelPositioning
// extra usings

INTERPOSE(CGContextSetAllowsFontSubpixelPositioning)(CGContextRef arg0, bool arg1)
{
    #define RUN_FUNC  real::CGContextSetAllowsFontSubpixelPositioning(arg0, arg1)

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

#define FUNC_ID "CGPDFDocumentIsEncrypted"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentIsEncrypted
// extra usings

INTERPOSE(CGPDFDocumentIsEncrypted)(CGPDFDocumentRef arg0)
{
    #define RUN_FUNC  bool ret = real::CGPDFDocumentIsEncrypted(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayBestModeForParameters"
#pragma push_macro(FUNC_ID)
#undef CGDisplayBestModeForParameters
// extra usings

INTERPOSE(CGDisplayBestModeForParameters)(__uint32_t arg0, __darwin_size_t arg1, __darwin_size_t arg2, __darwin_size_t arg3, UnsignedFixedPtr arg4)
{
    #define RUN_FUNC  CFDictionaryRef ret = real::CGDisplayBestModeForParameters(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFArrayGetBoolean"
#pragma push_macro(FUNC_ID)
#undef CGPDFArrayGetBoolean
// extra usings

INTERPOSE(CGPDFArrayGetBoolean)(CGPDFArrayRef arg0, __darwin_size_t arg1, BytePtr arg2)
{
    #define RUN_FUNC  bool ret = real::CGPDFArrayGetBoolean(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGShadingCreateAxial"
#pragma push_macro(FUNC_ID)
#undef CGShadingCreateAxial
// extra usings

INTERPOSE(CGShadingCreateAxial)(CGColorSpaceRef arg0, CGPoint arg1, CGPoint arg2, CGFunctionRef arg3, bool arg4, bool arg5)
{
    #define RUN_FUNC  CGShadingRef ret = real::CGShadingCreateAxial(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGRectMakeWithDictionaryRepresentation"
#pragma push_macro(FUNC_ID)
#undef CGRectMakeWithDictionaryRepresentation
// extra usings

INTERPOSE(CGRectMakeWithDictionaryRepresentation)(CFDictionaryRef arg0, CGRect * arg1)
{
    #define RUN_FUNC  bool ret = real::CGRectMakeWithDictionaryRepresentation(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFContentStreamRetain"
#pragma push_macro(FUNC_ID)
#undef CGPDFContentStreamRetain
// extra usings

INTERPOSE(CGPDFContentStreamRetain)(CGPDFContentStreamRef arg0)
{
    #define RUN_FUNC  CGPDFContentStreamRef ret = real::CGPDFContentStreamRetain(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGFunctionCreate"
#pragma push_macro(FUNC_ID)
#undef CGFunctionCreate
// extra usings

INTERPOSE(CGFunctionCreate)(void * arg0, __darwin_size_t arg1, const double * arg2, __darwin_size_t arg3, const double * arg4, const CGFunctionCallbacks * arg5)
{
    #define RUN_FUNC  CGFunctionRef ret = real::CGFunctionCreate(arg0, arg1, arg2, arg3, arg4, arg5)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextGetTextMatrix"
#pragma push_macro(FUNC_ID)
#undef CGContextGetTextMatrix
// extra usings

INTERPOSE(CGContextGetTextMatrix)(CGContextRef arg0)
{
    #define RUN_FUNC  CGAffineTransform ret = real::CGContextGetTextMatrix(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayModeGetIOFlags"
#pragma push_macro(FUNC_ID)
#undef CGDisplayModeGetIOFlags
// extra usings

INTERPOSE(CGDisplayModeGetIOFlags)(CGDisplayModeRef arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGDisplayModeGetIOFlags(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayIsAsleep"
#pragma push_macro(FUNC_ID)
#undef CGDisplayIsAsleep
// extra usings

INTERPOSE(CGDisplayIsAsleep)(__uint32_t arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGDisplayIsAsleep(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGGetDisplaysWithRect"
#pragma push_macro(FUNC_ID)
#undef CGGetDisplaysWithRect
// extra usings

INTERPOSE(CGGetDisplaysWithRect)(CGRect arg0, __uint32_t arg1, UnsignedFixedPtr arg2, UnsignedFixedPtr arg3)
{
    #define RUN_FUNC  __int32_t ret = real::CGGetDisplaysWithRect(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGFontCopyFullName"
#pragma push_macro(FUNC_ID)
#undef CGFontCopyFullName
// extra usings

INTERPOSE(CGFontCopyFullName)(CGFontRef arg0)
{
    #define RUN_FUNC  CFStringRef ret = real::CGFontCopyFullName(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGGetDisplaysWithPoint"
#pragma push_macro(FUNC_ID)
#undef CGGetDisplaysWithPoint
// extra usings

INTERPOSE(CGGetDisplaysWithPoint)(CGPoint arg0, __uint32_t arg1, UnsignedFixedPtr arg2, UnsignedFixedPtr arg3)
{
    #define RUN_FUNC  __int32_t ret = real::CGGetDisplaysWithPoint(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFStreamCopyData"
#pragma push_macro(FUNC_ID)
#undef CGPDFStreamCopyData
// extra usings

INTERPOSE(CGPDFStreamCopyData)(CGPDFStreamRef arg0, FixedPtr arg1)
{
    #define RUN_FUNC  CFDataRef ret = real::CGPDFStreamCopyData(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGImageGetHeight"
#pragma push_macro(FUNC_ID)
#undef CGImageGetHeight
// extra usings

INTERPOSE(CGImageGetHeight)(CGImageRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGImageGetHeight(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGLayerCreateWithContext"
#pragma push_macro(FUNC_ID)
#undef CGLayerCreateWithContext
// extra usings

INTERPOSE(CGLayerCreateWithContext)(CGContextRef arg0, CGSize arg1, CFDictionaryRef arg2)
{
    #define RUN_FUNC  CGLayerRef ret = real::CGLayerCreateWithContext(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFDocumentGetTrimBox"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentGetTrimBox
// extra usings

INTERPOSE(CGPDFDocumentGetTrimBox)(CGPDFDocumentRef arg0, __int32_t arg1)
{
    #define RUN_FUNC  CGRect ret = real::CGPDFDocumentGetTrimBox(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGGetActiveDisplayList"
#pragma push_macro(FUNC_ID)
#undef CGGetActiveDisplayList
// extra usings

INTERPOSE(CGGetActiveDisplayList)(__uint32_t arg0, UnsignedFixedPtr arg1, UnsignedFixedPtr arg2)
{
    #define RUN_FUNC  __int32_t ret = real::CGGetActiveDisplayList(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextGetClipBoundingBox"
#pragma push_macro(FUNC_ID)
#undef CGContextGetClipBoundingBox
// extra usings

INTERPOSE(CGContextGetClipBoundingBox)(CGContextRef arg0)
{
    #define RUN_FUNC  CGRect ret = real::CGContextGetClipBoundingBox(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextRetain"
#pragma push_macro(FUNC_ID)
#undef CGContextRetain
// extra usings

INTERPOSE(CGContextRetain)(CGContextRef arg0)
{
    #define RUN_FUNC  CGContextRef ret = real::CGContextRetain(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayRemoveReconfigurationCallback"
#pragma push_macro(FUNC_ID)
#undef CGDisplayRemoveReconfigurationCallback
// extra usings

INTERPOSE(CGDisplayRemoveReconfigurationCallback)(CGDisplayReconfigurationCallBack arg0, void * arg1)
{
    #define RUN_FUNC  __int32_t ret = real::CGDisplayRemoveReconfigurationCallback(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFDocumentGetRotationAngle"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentGetRotationAngle
// extra usings

INTERPOSE(CGPDFDocumentGetRotationAngle)(CGPDFDocumentRef arg0, __int32_t arg1)
{
    #define RUN_FUNC  __int32_t ret = real::CGPDFDocumentGetRotationAngle(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGDisplayModeGetPixelWidth"
#pragma push_macro(FUNC_ID)
#undef CGDisplayModeGetPixelWidth
// extra usings

INTERPOSE(CGDisplayModeGetPixelWidth)(CGDisplayModeRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGDisplayModeGetPixelWidth(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextClipToRects"
#pragma push_macro(FUNC_ID)
#undef CGContextClipToRects
// extra usings
using CGContextClipToRects_T_arg1 = const CGRect *;
using CGContextClipToRects_T_arg1 = const CGRect *;
INTERPOSE(CGContextClipToRects)(CGContextRef arg0, CGContextClipToRects_T_arg1 arg1, __darwin_size_t arg2)
{
    #define RUN_FUNC  real::CGContextClipToRects(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGContextClip"
#pragma push_macro(FUNC_ID)
#undef CGContextClip
// extra usings

INTERPOSE(CGContextClip)(CGContextRef arg0)
{
    #define RUN_FUNC  real::CGContextClip(arg0)

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

#define FUNC_ID "CGPDFDocumentGetBleedBox"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentGetBleedBox
// extra usings

INTERPOSE(CGPDFDocumentGetBleedBox)(CGPDFDocumentRef arg0, __int32_t arg1)
{
    #define RUN_FUNC  CGRect ret = real::CGPDFDocumentGetBleedBox(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPathGetCurrentPoint"
#pragma push_macro(FUNC_ID)
#undef CGPathGetCurrentPoint
// extra usings

INTERPOSE(CGPathGetCurrentPoint)(CGPathRef arg0)
{
    #define RUN_FUNC  CGPoint ret = real::CGPathGetCurrentPoint(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextShowGlyphsAtPositions"
#pragma push_macro(FUNC_ID)
#undef CGContextShowGlyphsAtPositions
// extra usings
using CGContextShowGlyphsAtPositions_T_arg2 = const CGPoint *;
using CGContextShowGlyphsAtPositions_T_arg2 = const CGPoint *;
INTERPOSE(CGContextShowGlyphsAtPositions)(CGContextRef arg0, const unsigned short * arg1, CGContextShowGlyphsAtPositions_T_arg2 arg2, __darwin_size_t arg3)
{
    #define RUN_FUNC  real::CGContextShowGlyphsAtPositions(arg0, arg1, arg2, arg3)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGContextSetStrokeColorWithColor"
#pragma push_macro(FUNC_ID)
#undef CGContextSetStrokeColorWithColor
// extra usings

INTERPOSE(CGContextSetStrokeColorWithColor)(CGContextRef arg0, CGColorRef arg1)
{
    #define RUN_FUNC  real::CGContextSetStrokeColorWithColor(arg0, arg1)

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

#define FUNC_ID "CGContextSetCMYKFillColor"
#pragma push_macro(FUNC_ID)
#undef CGContextSetCMYKFillColor
// extra usings

INTERPOSE(CGContextSetCMYKFillColor)(CGContextRef arg0, CGFloat arg1, CGFloat arg2, CGFloat arg3, CGFloat arg4, CGFloat arg5)
{
    #define RUN_FUNC  real::CGContextSetCMYKFillColor(arg0, arg1, arg2, arg3, arg4, arg5)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGImageCreateWithImageInRect"
#pragma push_macro(FUNC_ID)
#undef CGImageCreateWithImageInRect
// extra usings

INTERPOSE(CGImageCreateWithImageInRect)(CGImageRef arg0, CGRect arg1)
{
    #define RUN_FUNC  CGImageRef ret = real::CGImageCreateWithImageInRect(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextBeginPage"
#pragma push_macro(FUNC_ID)
#undef CGContextBeginPage
// extra usings
using CGContextBeginPage_T_arg1 = const CGRect *;
using CGContextBeginPage_T_arg1 = const CGRect *;
INTERPOSE(CGContextBeginPage)(CGContextRef arg0, CGContextBeginPage_T_arg1 arg1)
{
    #define RUN_FUNC  real::CGContextBeginPage(arg0, arg1)

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

#define FUNC_ID "CGImageCreateCopyWithColorSpace"
#pragma push_macro(FUNC_ID)
#undef CGImageCreateCopyWithColorSpace
// extra usings

INTERPOSE(CGImageCreateCopyWithColorSpace)(CGImageRef arg0, CGColorSpaceRef arg1)
{
    #define RUN_FUNC  CGImageRef ret = real::CGImageCreateCopyWithColorSpace(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextDrawPDFDocument"
#pragma push_macro(FUNC_ID)
#undef CGContextDrawPDFDocument
// extra usings

INTERPOSE(CGContextDrawPDFDocument)(CGContextRef arg0, CGRect arg1, CGPDFDocumentRef arg2, __int32_t arg3)
{
    #define RUN_FUNC  real::CGContextDrawPDFDocument(arg0, arg1, arg2, arg3)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGFunctionGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CGFunctionGetTypeID
// extra usings

INTERPOSE(CGFunctionGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGFunctionGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGCaptureAllDisplaysWithOptions"
#pragma push_macro(FUNC_ID)
#undef CGCaptureAllDisplaysWithOptions
// extra usings

INTERPOSE(CGCaptureAllDisplaysWithOptions)(__uint32_t arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGCaptureAllDisplaysWithOptions(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextSetShadowWithColor"
#pragma push_macro(FUNC_ID)
#undef CGContextSetShadowWithColor
// extra usings

INTERPOSE(CGContextSetShadowWithColor)(CGContextRef arg0, CGSize arg1, CGFloat arg2, CGColorRef arg3)
{
    #define RUN_FUNC  real::CGContextSetShadowWithColor(arg0, arg1, arg2, arg3)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGContextSetInterpolationQuality"
#pragma push_macro(FUNC_ID)
#undef CGContextSetInterpolationQuality
// extra usings

INTERPOSE(CGContextSetInterpolationQuality)(CGContextRef arg0, __int32_t arg1)
{
    #define RUN_FUNC  real::CGContextSetInterpolationQuality(arg0, arg1)

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

#define FUNC_ID "CGPDFPageGetDictionary"
#pragma push_macro(FUNC_ID)
#undef CGPDFPageGetDictionary
// extra usings

INTERPOSE(CGPDFPageGetDictionary)(CGPDFPageRef arg0)
{
    #define RUN_FUNC  CGPDFDictionaryRef ret = real::CGPDFPageGetDictionary(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextDrawLayerAtPoint"
#pragma push_macro(FUNC_ID)
#undef CGContextDrawLayerAtPoint
// extra usings

INTERPOSE(CGContextDrawLayerAtPoint)(CGContextRef arg0, CGPoint arg1, CGLayerRef arg2)
{
    #define RUN_FUNC  real::CGContextDrawLayerAtPoint(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGDisplayRestoreColorSyncSettings"
#pragma push_macro(FUNC_ID)
#undef CGDisplayRestoreColorSyncSettings
// extra usings

INTERPOSE(CGDisplayRestoreColorSyncSettings)()
{
    #define RUN_FUNC  real::CGDisplayRestoreColorSyncSettings()

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
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPathCreateWithEllipseInRect"
#pragma push_macro(FUNC_ID)
#undef CGPathCreateWithEllipseInRect
// extra usings
using CGPathCreateWithEllipseInRect_T_arg1 = const CGAffineTransform *;
using CGPathCreateWithEllipseInRect_T_arg1 = const CGAffineTransform *;
INTERPOSE(CGPathCreateWithEllipseInRect)(CGRect arg0, CGPathCreateWithEllipseInRect_T_arg1 arg1)
{
    #define RUN_FUNC  CGPathRef ret = real::CGPathCreateWithEllipseInRect(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFPageGetPageNumber"
#pragma push_macro(FUNC_ID)
#undef CGPDFPageGetPageNumber
// extra usings

INTERPOSE(CGPDFPageGetPageNumber)(CGPDFPageRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGPDFPageGetPageNumber(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGColorRelease"
#pragma push_macro(FUNC_ID)
#undef CGColorRelease
// extra usings

INTERPOSE(CGColorRelease)(CGColorRef arg0)
{
    #define RUN_FUNC  real::CGColorRelease(arg0)

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

#define FUNC_ID "CGColorSpaceGetColorTable"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceGetColorTable
// extra usings

INTERPOSE(CGColorSpaceGetColorTable)(CGColorSpaceRef arg0, BytePtr arg1)
{
    #define RUN_FUNC  real::CGColorSpaceGetColorTable(arg0, arg1)

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

#define FUNC_ID "CGColorSpaceCopyICCData"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceCopyICCData
// extra usings

INTERPOSE(CGColorSpaceCopyICCData)(CGColorSpaceRef arg0)
{
    #define RUN_FUNC  CFDataRef ret = real::CGColorSpaceCopyICCData(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayIsAlwaysInMirrorSet"
#pragma push_macro(FUNC_ID)
#undef CGDisplayIsAlwaysInMirrorSet
// extra usings

INTERPOSE(CGDisplayIsAlwaysInMirrorSet)(__uint32_t arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGDisplayIsAlwaysInMirrorSet(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGFontCopyPostScriptName"
#pragma push_macro(FUNC_ID)
#undef CGFontCopyPostScriptName
// extra usings

INTERPOSE(CGFontCopyPostScriptName)(CGFontRef arg0)
{
    #define RUN_FUNC  CFStringRef ret = real::CGFontCopyPostScriptName(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGFontCreateWithDataProvider"
#pragma push_macro(FUNC_ID)
#undef CGFontCreateWithDataProvider
// extra usings

INTERPOSE(CGFontCreateWithDataProvider)(CGDataProviderRef arg0)
{
    #define RUN_FUNC  CGFontRef ret = real::CGFontCreateWithDataProvider(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGRectCreateDictionaryRepresentation"
#pragma push_macro(FUNC_ID)
#undef CGRectCreateDictionaryRepresentation
// extra usings

INTERPOSE(CGRectCreateDictionaryRepresentation)(CGRect arg0)
{
    #define RUN_FUNC  CFDictionaryRef ret = real::CGRectCreateDictionaryRepresentation(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGRectInset"
#pragma push_macro(FUNC_ID)
#undef CGRectInset
// extra usings

INTERPOSE(CGRectInset)(CGRect arg0, CGFloat arg1, CGFloat arg2)
{
    #define RUN_FUNC  CGRect ret = real::CGRectInset(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGRectGetWidth"
#pragma push_macro(FUNC_ID)
#undef CGRectGetWidth
// extra usings

INTERPOSE(CGRectGetWidth)(CGRect arg0)
{
    #define RUN_FUNC  CGFloat ret = real::CGRectGetWidth(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextStrokeRectWithWidth"
#pragma push_macro(FUNC_ID)
#undef CGContextStrokeRectWithWidth
// extra usings

INTERPOSE(CGContextStrokeRectWithWidth)(CGContextRef arg0, CGRect arg1, CGFloat arg2)
{
    #define RUN_FUNC  real::CGContextStrokeRectWithWidth(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGImageMaskCreate"
#pragma push_macro(FUNC_ID)
#undef CGImageMaskCreate
// extra usings

INTERPOSE(CGImageMaskCreate)(__darwin_size_t arg0, __darwin_size_t arg1, __darwin_size_t arg2, __darwin_size_t arg3, __darwin_size_t arg4, CGDataProviderRef arg5, const double * arg6, bool arg7)
{
    #define RUN_FUNC  CGImageRef ret = real::CGImageMaskCreate(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextDrawLayerInRect"
#pragma push_macro(FUNC_ID)
#undef CGContextDrawLayerInRect
// extra usings

INTERPOSE(CGContextDrawLayerInRect)(CGContextRef arg0, CGRect arg1, CGLayerRef arg2)
{
    #define RUN_FUNC  real::CGContextDrawLayerInRect(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGRectUnion"
#pragma push_macro(FUNC_ID)
#undef CGRectUnion
// extra usings

INTERPOSE(CGRectUnion)(CGRect arg0, CGRect arg1)
{
    #define RUN_FUNC  CGRect ret = real::CGRectUnion(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPathAddRects"
#pragma push_macro(FUNC_ID)
#undef CGPathAddRects
// extra usings
using CGPathAddRects_T_arg1 = const CGAffineTransform *;
using CGPathAddRects_T_arg2 = const CGRect *;
using CGPathAddRects_T_arg1 = const CGAffineTransform *;
using CGPathAddRects_T_arg2 = const CGRect *;
INTERPOSE(CGPathAddRects)(CGMutablePathRef arg0, CGPathAddRects_T_arg1 arg1, CGPathAddRects_T_arg2 arg2, __darwin_size_t arg3)
{
    #define RUN_FUNC  real::CGPathAddRects(arg0, arg1, arg2, arg3)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGColorSpaceSupportsOutput"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceSupportsOutput
// extra usings

INTERPOSE(CGColorSpaceSupportsOutput)(CGColorSpaceRef arg0)
{
    #define RUN_FUNC  bool ret = real::CGColorSpaceSupportsOutput(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFContextSetDestinationForRect"
#pragma push_macro(FUNC_ID)
#undef CGPDFContextSetDestinationForRect
// extra usings

INTERPOSE(CGPDFContextSetDestinationForRect)(CGContextRef arg0, CFStringRef arg1, CGRect arg2)
{
    #define RUN_FUNC  real::CGPDFContextSetDestinationForRect(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPDFScannerPopName"
#pragma push_macro(FUNC_ID)
#undef CGPDFScannerPopName
// extra usings

INTERPOSE(CGPDFScannerPopName)(CGPDFScannerRef arg0, const char ** arg1)
{
    #define RUN_FUNC  bool ret = real::CGPDFScannerPopName(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGLayerGetContext"
#pragma push_macro(FUNC_ID)
#undef CGLayerGetContext
// extra usings

INTERPOSE(CGLayerGetContext)(CGLayerRef arg0)
{
    #define RUN_FUNC  CGContextRef ret = real::CGLayerGetContext(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGImageGetBitsPerPixel"
#pragma push_macro(FUNC_ID)
#undef CGImageGetBitsPerPixel
// extra usings

INTERPOSE(CGImageGetBitsPerPixel)(CGImageRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGImageGetBitsPerPixel(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPathAddArc"
#pragma push_macro(FUNC_ID)
#undef CGPathAddArc
// extra usings
using CGPathAddArc_T_arg1 = const CGAffineTransform *;
using CGPathAddArc_T_arg1 = const CGAffineTransform *;
INTERPOSE(CGPathAddArc)(CGMutablePathRef arg0, CGPathAddArc_T_arg1 arg1, CGFloat arg2, CGFloat arg3, CGFloat arg4, CGFloat arg5, CGFloat arg6, bool arg7)
{
    #define RUN_FUNC  real::CGPathAddArc(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGContextDrawLinearGradient"
#pragma push_macro(FUNC_ID)
#undef CGContextDrawLinearGradient
// extra usings

INTERPOSE(CGContextDrawLinearGradient)(CGContextRef arg0, CGGradientRef arg1, CGPoint arg2, CGPoint arg3, __uint32_t arg4)
{
    #define RUN_FUNC  real::CGContextDrawLinearGradient(arg0, arg1, arg2, arg3, arg4)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGDataConsumerGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CGDataConsumerGetTypeID
// extra usings

INTERPOSE(CGDataConsumerGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGDataConsumerGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGDisplayModeIsUsableForDesktopGUI"
#pragma push_macro(FUNC_ID)
#undef CGDisplayModeIsUsableForDesktopGUI
// extra usings

INTERPOSE(CGDisplayModeIsUsableForDesktopGUI)(CGDisplayModeRef arg0)
{
    #define RUN_FUNC  bool ret = real::CGDisplayModeIsUsableForDesktopGUI(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGRectGetHeight"
#pragma push_macro(FUNC_ID)
#undef CGRectGetHeight
// extra usings

INTERPOSE(CGRectGetHeight)(CGRect arg0)
{
    #define RUN_FUNC  CGFloat ret = real::CGRectGetHeight(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGRectIsInfinite"
#pragma push_macro(FUNC_ID)
#undef CGRectIsInfinite
// extra usings

INTERPOSE(CGRectIsInfinite)(CGRect arg0)
{
    #define RUN_FUNC  bool ret = real::CGRectIsInfinite(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFContextAddDocumentMetadata"
#pragma push_macro(FUNC_ID)
#undef CGPDFContextAddDocumentMetadata
// extra usings

INTERPOSE(CGPDFContextAddDocumentMetadata)(CGContextRef arg0, CFDataRef arg1)
{
    #define RUN_FUNC  real::CGPDFContextAddDocumentMetadata(arg0, arg1)

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

#define FUNC_ID "CGColorSpaceCreateWithICCData"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceCreateWithICCData
// extra usings

INTERPOSE(CGColorSpaceCreateWithICCData)(const void * arg0)
{
    #define RUN_FUNC  CGColorSpaceRef ret = real::CGColorSpaceCreateWithICCData(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFContextBeginPage"
#pragma push_macro(FUNC_ID)
#undef CGPDFContextBeginPage
// extra usings

INTERPOSE(CGPDFContextBeginPage)(CGContextRef arg0, CFDictionaryRef arg1)
{
    #define RUN_FUNC  real::CGPDFContextBeginPage(arg0, arg1)

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

#define FUNC_ID "CGPSConverterIsConverting"
#pragma push_macro(FUNC_ID)
#undef CGPSConverterIsConverting
// extra usings

INTERPOSE(CGPSConverterIsConverting)(CGPSConverterRef arg0)
{
    #define RUN_FUNC  bool ret = real::CGPSConverterIsConverting(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPathIsEmpty"
#pragma push_macro(FUNC_ID)
#undef CGPathIsEmpty
// extra usings

INTERPOSE(CGPathIsEmpty)(CGPathRef arg0)
{
    #define RUN_FUNC  bool ret = real::CGPathIsEmpty(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayScreenSize"
#pragma push_macro(FUNC_ID)
#undef CGDisplayScreenSize
// extra usings

INTERPOSE(CGDisplayScreenSize)(__uint32_t arg0)
{
    #define RUN_FUNC  CGSize ret = real::CGDisplayScreenSize(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayIsInMirrorSet"
#pragma push_macro(FUNC_ID)
#undef CGDisplayIsInMirrorSet
// extra usings

INTERPOSE(CGDisplayIsInMirrorSet)(__uint32_t arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGDisplayIsInMirrorSet(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGFontCopyGlyphNameForGlyph"
#pragma push_macro(FUNC_ID)
#undef CGFontCopyGlyphNameForGlyph
// extra usings

INTERPOSE(CGFontCopyGlyphNameForGlyph)(CGFontRef arg0, __uint16_t arg1)
{
    #define RUN_FUNC  CFStringRef ret = real::CGFontCopyGlyphNameForGlyph(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGBitmapContextGetAlphaInfo"
#pragma push_macro(FUNC_ID)
#undef CGBitmapContextGetAlphaInfo
// extra usings

INTERPOSE(CGBitmapContextGetAlphaInfo)(CGContextRef arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGBitmapContextGetAlphaInfo(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFScannerRelease"
#pragma push_macro(FUNC_ID)
#undef CGPDFScannerRelease
// extra usings

INTERPOSE(CGPDFScannerRelease)(CGPDFScannerRef arg0)
{
    #define RUN_FUNC  real::CGPDFScannerRelease(arg0)

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

#define FUNC_ID "CGContextCopyPath"
#pragma push_macro(FUNC_ID)
#undef CGContextCopyPath
// extra usings

INTERPOSE(CGContextCopyPath)(CGContextRef arg0)
{
    #define RUN_FUNC  CGPathRef ret = real::CGContextCopyPath(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGShadingRelease"
#pragma push_macro(FUNC_ID)
#undef CGShadingRelease
// extra usings

INTERPOSE(CGShadingRelease)(CGShadingRef arg0)
{
    #define RUN_FUNC  real::CGShadingRelease(arg0)

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

#define FUNC_ID "CGDisplayFadeOperationInProgress"
#pragma push_macro(FUNC_ID)
#undef CGDisplayFadeOperationInProgress
// extra usings

INTERPOSE(CGDisplayFadeOperationInProgress)()
{
    #define RUN_FUNC  __uint32_t ret = real::CGDisplayFadeOperationInProgress()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPDFContentStreamGetStreams"
#pragma push_macro(FUNC_ID)
#undef CGPDFContentStreamGetStreams
// extra usings

INTERPOSE(CGPDFContentStreamGetStreams)(CGPDFContentStreamRef arg0)
{
    #define RUN_FUNC  CFArrayRef ret = real::CGPDFContentStreamGetStreams(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextSetMiterLimit"
#pragma push_macro(FUNC_ID)
#undef CGContextSetMiterLimit
// extra usings

INTERPOSE(CGContextSetMiterLimit)(CGContextRef arg0, CGFloat arg1)
{
    #define RUN_FUNC  real::CGContextSetMiterLimit(arg0, arg1)

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

#define FUNC_ID "CGPDFOperatorTableSetCallback"
#pragma push_macro(FUNC_ID)
#undef CGPDFOperatorTableSetCallback
// extra usings

INTERPOSE(CGPDFOperatorTableSetCallback)(CGPDFOperatorTableRef arg0, const char * arg1, CGPDFOperatorCallback arg2)
{
    #define RUN_FUNC  real::CGPDFOperatorTableSetCallback(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGContextDrawPath"
#pragma push_macro(FUNC_ID)
#undef CGContextDrawPath
// extra usings

INTERPOSE(CGContextDrawPath)(CGContextRef arg0, __int32_t arg1)
{
    #define RUN_FUNC  real::CGContextDrawPath(arg0, arg1)

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

#define FUNC_ID "CGWindowServerCFMachPort"
#pragma push_macro(FUNC_ID)
#undef CGWindowServerCFMachPort
// extra usings

INTERPOSE(CGWindowServerCFMachPort)()
{
    #define RUN_FUNC  CFMachPortRef ret = real::CGWindowServerCFMachPort()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGColorEqualToColor"
#pragma push_macro(FUNC_ID)
#undef CGColorEqualToColor
// extra usings

INTERPOSE(CGColorEqualToColor)(CGColorRef arg0, CGColorRef arg1)
{
    #define RUN_FUNC  bool ret = real::CGColorEqualToColor(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextSetFontSize"
#pragma push_macro(FUNC_ID)
#undef CGContextSetFontSize
// extra usings

INTERPOSE(CGContextSetFontSize)(CGContextRef arg0, CGFloat arg1)
{
    #define RUN_FUNC  real::CGContextSetFontSize(arg0, arg1)

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

#define FUNC_ID "CGContextShowText"
#pragma push_macro(FUNC_ID)
#undef CGContextShowText
// extra usings

INTERPOSE(CGContextShowText)(CGContextRef arg0, const char * arg1, __darwin_size_t arg2)
{
    #define RUN_FUNC  real::CGContextShowText(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGColorSpaceCreateWithName"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceCreateWithName
// extra usings

INTERPOSE(CGColorSpaceCreateWithName)(CFStringRef arg0)
{
    #define RUN_FUNC  CGColorSpaceRef ret = real::CGColorSpaceCreateWithName(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGRectGetMaxX"
#pragma push_macro(FUNC_ID)
#undef CGRectGetMaxX
// extra usings

INTERPOSE(CGRectGetMaxX)(CGRect arg0)
{
    #define RUN_FUNC  CGFloat ret = real::CGRectGetMaxX(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGImageCreateWithMask"
#pragma push_macro(FUNC_ID)
#undef CGImageCreateWithMask
// extra usings

INTERPOSE(CGImageCreateWithMask)(CGImageRef arg0, CGImageRef arg1)
{
    #define RUN_FUNC  CGImageRef ret = real::CGImageCreateWithMask(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGImageCreateWithPNGDataProvider"
#pragma push_macro(FUNC_ID)
#undef CGImageCreateWithPNGDataProvider
// extra usings

INTERPOSE(CGImageCreateWithPNGDataProvider)(CGDataProviderRef arg0, const double * arg1, bool arg2, __int32_t arg3)
{
    #define RUN_FUNC  CGImageRef ret = real::CGImageCreateWithPNGDataProvider(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextSetTextDrawingMode"
#pragma push_macro(FUNC_ID)
#undef CGContextSetTextDrawingMode
// extra usings

INTERPOSE(CGContextSetTextDrawingMode)(CGContextRef arg0, __int32_t arg1)
{
    #define RUN_FUNC  real::CGContextSetTextDrawingMode(arg0, arg1)

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

#define FUNC_ID "CGContextGetUserSpaceToDeviceSpaceTransform"
#pragma push_macro(FUNC_ID)
#undef CGContextGetUserSpaceToDeviceSpaceTransform
// extra usings

INTERPOSE(CGContextGetUserSpaceToDeviceSpaceTransform)(CGContextRef arg0)
{
    #define RUN_FUNC  CGAffineTransform ret = real::CGContextGetUserSpaceToDeviceSpaceTransform(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDataConsumerCreateWithCFData"
#pragma push_macro(FUNC_ID)
#undef CGDataConsumerCreateWithCFData
// extra usings

INTERPOSE(CGDataConsumerCreateWithCFData)(CFMutableDataRef arg0)
{
    #define RUN_FUNC  CGDataConsumerRef ret = real::CGDataConsumerCreateWithCFData(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGColorSpaceCreateCalibratedRGB"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceCreateCalibratedRGB
// extra usings

INTERPOSE(CGColorSpaceCreateCalibratedRGB)(const double * arg0, const double * arg1, const double * arg2, const double * arg3)
{
    #define RUN_FUNC  CGColorSpaceRef ret = real::CGColorSpaceCreateCalibratedRGB(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextSetLineJoin"
#pragma push_macro(FUNC_ID)
#undef CGContextSetLineJoin
// extra usings

INTERPOSE(CGContextSetLineJoin)(CGContextRef arg0, __int32_t arg1)
{
    #define RUN_FUNC  real::CGContextSetLineJoin(arg0, arg1)

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

#define FUNC_ID "CGDataProviderCreateSequential"
#pragma push_macro(FUNC_ID)
#undef CGDataProviderCreateSequential
// extra usings

INTERPOSE(CGDataProviderCreateSequential)(void * arg0, const CGDataProviderSequentialCallbacks * arg1)
{
    #define RUN_FUNC  CGDataProviderRef ret = real::CGDataProviderCreateSequential(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFArrayGetNull"
#pragma push_macro(FUNC_ID)
#undef CGPDFArrayGetNull
// extra usings

INTERPOSE(CGPDFArrayGetNull)(CGPDFArrayRef arg0, __darwin_size_t arg1)
{
    #define RUN_FUNC  bool ret = real::CGPDFArrayGetNull(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextSetRGBFillColor"
#pragma push_macro(FUNC_ID)
#undef CGContextSetRGBFillColor
// extra usings

INTERPOSE(CGContextSetRGBFillColor)(CGContextRef arg0, CGFloat arg1, CGFloat arg2, CGFloat arg3, CGFloat arg4)
{
    #define RUN_FUNC  real::CGContextSetRGBFillColor(arg0, arg1, arg2, arg3, arg4)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPathAddRect"
#pragma push_macro(FUNC_ID)
#undef CGPathAddRect
// extra usings
using CGPathAddRect_T_arg1 = const CGAffineTransform *;
using CGPathAddRect_T_arg1 = const CGAffineTransform *;
INTERPOSE(CGPathAddRect)(CGMutablePathRef arg0, CGPathAddRect_T_arg1 arg1, CGRect arg2)
{
    #define RUN_FUNC  real::CGPathAddRect(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGGetLastMouseDelta"
#pragma push_macro(FUNC_ID)
#undef CGGetLastMouseDelta
// extra usings

INTERPOSE(CGGetLastMouseDelta)(FixedPtr arg0, FixedPtr arg1)
{
    #define RUN_FUNC  real::CGGetLastMouseDelta(arg0, arg1)

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

#define FUNC_ID "CGPDFArrayGetDictionary"
#pragma push_macro(FUNC_ID)
#undef CGPDFArrayGetDictionary
// extra usings
using CGPDFArrayGetDictionary_T_arg2 = CGPDFDictionary **;
using CGPDFArrayGetDictionary_T_arg2 = CGPDFDictionary **;
INTERPOSE(CGPDFArrayGetDictionary)(CGPDFArrayRef arg0, __darwin_size_t arg1, CGPDFArrayGetDictionary_T_arg2 arg2)
{
    #define RUN_FUNC  bool ret = real::CGPDFArrayGetDictionary(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPathCloseSubpath"
#pragma push_macro(FUNC_ID)
#undef CGPathCloseSubpath
// extra usings

INTERPOSE(CGPathCloseSubpath)(CGMutablePathRef arg0)
{
    #define RUN_FUNC  real::CGPathCloseSubpath(arg0)

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

#define FUNC_ID "CGPDFContentStreamCreateWithStream"
#pragma push_macro(FUNC_ID)
#undef CGPDFContentStreamCreateWithStream
// extra usings

INTERPOSE(CGPDFContentStreamCreateWithStream)(CGPDFStreamRef arg0, CGPDFDictionaryRef arg1, CGPDFContentStreamRef arg2)
{
    #define RUN_FUNC  CGPDFContentStreamRef ret = real::CGPDFContentStreamCreateWithStream(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGDisplaySerialNumber"
#pragma push_macro(FUNC_ID)
#undef CGDisplaySerialNumber
// extra usings

INTERPOSE(CGDisplaySerialNumber)(__uint32_t arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGDisplaySerialNumber(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGGetOnlineDisplayList"
#pragma push_macro(FUNC_ID)
#undef CGGetOnlineDisplayList
// extra usings

INTERPOSE(CGGetOnlineDisplayList)(__uint32_t arg0, UnsignedFixedPtr arg1, UnsignedFixedPtr arg2)
{
    #define RUN_FUNC  __int32_t ret = real::CGGetOnlineDisplayList(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGCancelDisplayConfiguration"
#pragma push_macro(FUNC_ID)
#undef CGCancelDisplayConfiguration
// extra usings

INTERPOSE(CGCancelDisplayConfiguration)(CGDisplayConfigRef arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGCancelDisplayConfiguration(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextSetShouldSubpixelPositionFonts"
#pragma push_macro(FUNC_ID)
#undef CGContextSetShouldSubpixelPositionFonts
// extra usings

INTERPOSE(CGContextSetShouldSubpixelPositionFonts)(CGContextRef arg0, bool arg1)
{
    #define RUN_FUNC  real::CGContextSetShouldSubpixelPositionFonts(arg0, arg1)

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

#define FUNC_ID "CGContextSaveGState"
#pragma push_macro(FUNC_ID)
#undef CGContextSaveGState
// extra usings

INTERPOSE(CGContextSaveGState)(CGContextRef arg0)
{
    #define RUN_FUNC  real::CGContextSaveGState(arg0)

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

#define FUNC_ID "CGReleaseAllDisplays"
#pragma push_macro(FUNC_ID)
#undef CGReleaseAllDisplays
// extra usings

INTERPOSE(CGReleaseAllDisplays)()
{
    #define RUN_FUNC  __int32_t ret = real::CGReleaseAllDisplays()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGDisplayRelease"
#pragma push_macro(FUNC_ID)
#undef CGDisplayRelease
// extra usings

INTERPOSE(CGDisplayRelease)(__uint32_t arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGDisplayRelease(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextConvertSizeToUserSpace"
#pragma push_macro(FUNC_ID)
#undef CGContextConvertSizeToUserSpace
// extra usings

INTERPOSE(CGContextConvertSizeToUserSpace)(CGContextRef arg0, CGSize arg1)
{
    #define RUN_FUNC  CGSize ret = real::CGContextConvertSizeToUserSpace(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGColorCreateCopyWithAlpha"
#pragma push_macro(FUNC_ID)
#undef CGColorCreateCopyWithAlpha
// extra usings

INTERPOSE(CGColorCreateCopyWithAlpha)(CGColorRef arg0, CGFloat arg1)
{
    #define RUN_FUNC  CGColorRef ret = real::CGColorCreateCopyWithAlpha(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFScannerPopNumber"
#pragma push_macro(FUNC_ID)
#undef CGPDFScannerPopNumber
// extra usings
using CGPDFScannerPopNumber_T_arg1 = double *;
using CGPDFScannerPopNumber_T_arg1 = double *;
INTERPOSE(CGPDFScannerPopNumber)(CGPDFScannerRef arg0, CGPDFScannerPopNumber_T_arg1 arg1)
{
    #define RUN_FUNC  bool ret = real::CGPDFScannerPopNumber(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextEOFillPath"
#pragma push_macro(FUNC_ID)
#undef CGContextEOFillPath
// extra usings

INTERPOSE(CGContextEOFillPath)(CGContextRef arg0)
{
    #define RUN_FUNC  real::CGContextEOFillPath(arg0)

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

#define FUNC_ID "CGPathCreateCopy"
#pragma push_macro(FUNC_ID)
#undef CGPathCreateCopy
// extra usings

INTERPOSE(CGPathCreateCopy)(CGPathRef arg0)
{
    #define RUN_FUNC  CGPathRef ret = real::CGPathCreateCopy(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPSConverterAbort"
#pragma push_macro(FUNC_ID)
#undef CGPSConverterAbort
// extra usings

INTERPOSE(CGPSConverterAbort)(CGPSConverterRef arg0)
{
    #define RUN_FUNC  bool ret = real::CGPSConverterAbort(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextFillPath"
#pragma push_macro(FUNC_ID)
#undef CGContextFillPath
// extra usings

INTERPOSE(CGContextFillPath)(CGContextRef arg0)
{
    #define RUN_FUNC  real::CGContextFillPath(arg0)

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

#define FUNC_ID "CGContextFillRects"
#pragma push_macro(FUNC_ID)
#undef CGContextFillRects
// extra usings
using CGContextFillRects_T_arg1 = const CGRect *;
using CGContextFillRects_T_arg1 = const CGRect *;
INTERPOSE(CGContextFillRects)(CGContextRef arg0, CGContextFillRects_T_arg1 arg1, __darwin_size_t arg2)
{
    #define RUN_FUNC  real::CGContextFillRects(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGContextStrokeEllipseInRect"
#pragma push_macro(FUNC_ID)
#undef CGContextStrokeEllipseInRect
// extra usings

INTERPOSE(CGContextStrokeEllipseInRect)(CGContextRef arg0, CGRect arg1)
{
    #define RUN_FUNC  real::CGContextStrokeEllipseInRect(arg0, arg1)

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

#define FUNC_ID "CGPDFContextEndPage"
#pragma push_macro(FUNC_ID)
#undef CGPDFContextEndPage
// extra usings

INTERPOSE(CGPDFContextEndPage)(CGContextRef arg0)
{
    #define RUN_FUNC  real::CGPDFContextEndPage(arg0)

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

#define FUNC_ID "CGContextConvertSizeToDeviceSpace"
#pragma push_macro(FUNC_ID)
#undef CGContextConvertSizeToDeviceSpace
// extra usings

INTERPOSE(CGContextConvertSizeToDeviceSpace)(CGContextRef arg0, CGSize arg1)
{
    #define RUN_FUNC  CGSize ret = real::CGContextConvertSizeToDeviceSpace(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGReleaseScreenRefreshRects"
#pragma push_macro(FUNC_ID)
#undef CGReleaseScreenRefreshRects
// extra usings

INTERPOSE(CGReleaseScreenRefreshRects)(CGRect * arg0)
{
    #define RUN_FUNC  real::CGReleaseScreenRefreshRects(arg0)

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

#define FUNC_ID "CGContextSetFlatness"
#pragma push_macro(FUNC_ID)
#undef CGContextSetFlatness
// extra usings

INTERPOSE(CGContextSetFlatness)(CGContextRef arg0, CGFloat arg1)
{
    #define RUN_FUNC  real::CGContextSetFlatness(arg0, arg1)

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

#define FUNC_ID "CGColorSpaceUsesExtendedRange"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceUsesExtendedRange
// extra usings

INTERPOSE(CGColorSpaceUsesExtendedRange)(CGColorSpaceRef arg0)
{
    #define RUN_FUNC  bool ret = real::CGColorSpaceUsesExtendedRange(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextDrawShading"
#pragma push_macro(FUNC_ID)
#undef CGContextDrawShading
// extra usings

INTERPOSE(CGContextDrawShading)(CGContextRef arg0, CGShadingRef arg1)
{
    #define RUN_FUNC  real::CGContextDrawShading(arg0, arg1)

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

#define FUNC_ID "CGFontCopyVariationAxes"
#pragma push_macro(FUNC_ID)
#undef CGFontCopyVariationAxes
// extra usings

INTERPOSE(CGFontCopyVariationAxes)(CGFontRef arg0)
{
    #define RUN_FUNC  CFArrayRef ret = real::CGFontCopyVariationAxes(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextDrawImage"
#pragma push_macro(FUNC_ID)
#undef CGContextDrawImage
// extra usings

INTERPOSE(CGContextDrawImage)(CGContextRef arg0, CGRect arg1, CGImageRef arg2)
{
    #define RUN_FUNC  real::CGContextDrawImage(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPDFDocumentCreateWithProvider"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentCreateWithProvider
// extra usings

INTERPOSE(CGPDFDocumentCreateWithProvider)(CGDataProviderRef arg0)
{
    #define RUN_FUNC  CGPDFDocumentRef ret = real::CGPDFDocumentCreateWithProvider(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextStrokeRect"
#pragma push_macro(FUNC_ID)
#undef CGContextStrokeRect
// extra usings

INTERPOSE(CGContextStrokeRect)(CGContextRef arg0, CGRect arg1)
{
    #define RUN_FUNC  real::CGContextStrokeRect(arg0, arg1)

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

#define FUNC_ID "CGContextBeginPath"
#pragma push_macro(FUNC_ID)
#undef CGContextBeginPath
// extra usings

INTERPOSE(CGContextBeginPath)(CGContextRef arg0)
{
    #define RUN_FUNC  real::CGContextBeginPath(arg0)

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

#define FUNC_ID "CGFontGetNumberOfGlyphs"
#pragma push_macro(FUNC_ID)
#undef CGFontGetNumberOfGlyphs
// extra usings

INTERPOSE(CGFontGetNumberOfGlyphs)(CGFontRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGFontGetNumberOfGlyphs(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPathCreateCopyByDashingPath"
#pragma push_macro(FUNC_ID)
#undef CGPathCreateCopyByDashingPath
// extra usings
using CGPathCreateCopyByDashingPath_T_arg1 = const CGAffineTransform *;
using CGPathCreateCopyByDashingPath_T_arg1 = const CGAffineTransform *;
INTERPOSE(CGPathCreateCopyByDashingPath)(CGPathRef arg0, CGPathCreateCopyByDashingPath_T_arg1 arg1, CGFloat arg2, const double * arg3, __darwin_size_t arg4)
{
    #define RUN_FUNC  CGPathRef ret = real::CGPathCreateCopyByDashingPath(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGDisplayModeCopyPixelEncoding"
#pragma push_macro(FUNC_ID)
#undef CGDisplayModeCopyPixelEncoding
// extra usings

INTERPOSE(CGDisplayModeCopyPixelEncoding)(CGDisplayModeRef arg0)
{
    #define RUN_FUNC  CFStringRef ret = real::CGDisplayModeCopyPixelEncoding(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPSConverterConvert"
#pragma push_macro(FUNC_ID)
#undef CGPSConverterConvert
// extra usings

INTERPOSE(CGPSConverterConvert)(CGPSConverterRef arg0, CGDataProviderRef arg1, CGDataConsumerRef arg2, CFDictionaryRef arg3)
{
    #define RUN_FUNC  bool ret = real::CGPSConverterConvert(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextConvertPointToDeviceSpace"
#pragma push_macro(FUNC_ID)
#undef CGContextConvertPointToDeviceSpace
// extra usings

INTERPOSE(CGContextConvertPointToDeviceSpace)(CGContextRef arg0, CGPoint arg1)
{
    #define RUN_FUNC  CGPoint ret = real::CGContextConvertPointToDeviceSpace(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGDisplayBounds"
#pragma push_macro(FUNC_ID)
#undef CGDisplayBounds
// extra usings

INTERPOSE(CGDisplayBounds)(__uint32_t arg0)
{
    #define RUN_FUNC  CGRect ret = real::CGDisplayBounds(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGColorGetConstantColor"
#pragma push_macro(FUNC_ID)
#undef CGColorGetConstantColor
// extra usings

INTERPOSE(CGColorGetConstantColor)(CFStringRef arg0)
{
    #define RUN_FUNC  CGColorRef ret = real::CGColorGetConstantColor(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayUnitNumber"
#pragma push_macro(FUNC_ID)
#undef CGDisplayUnitNumber
// extra usings

INTERPOSE(CGDisplayUnitNumber)(__uint32_t arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGDisplayUnitNumber(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextClosePath"
#pragma push_macro(FUNC_ID)
#undef CGContextClosePath
// extra usings

INTERPOSE(CGContextClosePath)(CGContextRef arg0)
{
    #define RUN_FUNC  real::CGContextClosePath(arg0)

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

#define FUNC_ID "CGImageIsMask"
#pragma push_macro(FUNC_ID)
#undef CGImageIsMask
// extra usings

INTERPOSE(CGImageIsMask)(CGImageRef arg0)
{
    #define RUN_FUNC  bool ret = real::CGImageIsMask(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayCopyDisplayMode"
#pragma push_macro(FUNC_ID)
#undef CGDisplayCopyDisplayMode
// extra usings

INTERPOSE(CGDisplayCopyDisplayMode)(__uint32_t arg0)
{
    #define RUN_FUNC  CGDisplayModeRef ret = real::CGDisplayCopyDisplayMode(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFDocumentAllowsCopying"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentAllowsCopying
// extra usings

INTERPOSE(CGPDFDocumentAllowsCopying)(CGPDFDocumentRef arg0)
{
    #define RUN_FUNC  bool ret = real::CGPDFDocumentAllowsCopying(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayCreateImage"
#pragma push_macro(FUNC_ID)
#undef CGDisplayCreateImage
// extra usings

INTERPOSE(CGDisplayCreateImage)(__uint32_t arg0)
{
    #define RUN_FUNC  CGImageRef ret = real::CGDisplayCreateImage(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayRotation"
#pragma push_macro(FUNC_ID)
#undef CGDisplayRotation
// extra usings

INTERPOSE(CGDisplayRotation)(__uint32_t arg0)
{
    #define RUN_FUNC  CGFloat ret = real::CGDisplayRotation(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayIDToOpenGLDisplayMask"
#pragma push_macro(FUNC_ID)
#undef CGDisplayIDToOpenGLDisplayMask
// extra usings

INTERPOSE(CGDisplayIDToOpenGLDisplayMask)(__uint32_t arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGDisplayIDToOpenGLDisplayMask(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGColorCreate"
#pragma push_macro(FUNC_ID)
#undef CGColorCreate
// extra usings

INTERPOSE(CGColorCreate)(CGColorSpaceRef arg0, const double * arg1)
{
    #define RUN_FUNC  CGColorRef ret = real::CGColorCreate(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGImageGetByteOrderInfo"
#pragma push_macro(FUNC_ID)
#undef CGImageGetByteOrderInfo
// extra usings

INTERPOSE(CGImageGetByteOrderInfo)(CGImageRef arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGImageGetByteOrderInfo(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFDocumentGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentGetTypeID
// extra usings

INTERPOSE(CGPDFDocumentGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGPDFDocumentGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGShadingGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CGShadingGetTypeID
// extra usings

INTERPOSE(CGShadingGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGShadingGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGRectEqualToRect"
#pragma push_macro(FUNC_ID)
#undef CGRectEqualToRect
// extra usings

INTERPOSE(CGRectEqualToRect)(CGRect arg0, CGRect arg1)
{
    #define RUN_FUNC  bool ret = real::CGRectEqualToRect(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextBeginTransparencyLayerWithRect"
#pragma push_macro(FUNC_ID)
#undef CGContextBeginTransparencyLayerWithRect
// extra usings

INTERPOSE(CGContextBeginTransparencyLayerWithRect)(CGContextRef arg0, CGRect arg1, CFDictionaryRef arg2)
{
    #define RUN_FUNC  real::CGContextBeginTransparencyLayerWithRect(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPointCreateDictionaryRepresentation"
#pragma push_macro(FUNC_ID)
#undef CGPointCreateDictionaryRepresentation
// extra usings

INTERPOSE(CGPointCreateDictionaryRepresentation)(CGPoint arg0)
{
    #define RUN_FUNC  CFDictionaryRef ret = real::CGPointCreateDictionaryRepresentation(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGColorCreateWithPattern"
#pragma push_macro(FUNC_ID)
#undef CGColorCreateWithPattern
// extra usings

INTERPOSE(CGColorCreateWithPattern)(CGColorSpaceRef arg0, CGPatternRef arg1, const double * arg2)
{
    #define RUN_FUNC  CGColorRef ret = real::CGColorCreateWithPattern(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGDisplayPixelsWide"
#pragma push_macro(FUNC_ID)
#undef CGDisplayPixelsWide
// extra usings

INTERPOSE(CGDisplayPixelsWide)(__uint32_t arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGDisplayPixelsWide(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGLayerRetain"
#pragma push_macro(FUNC_ID)
#undef CGLayerRetain
// extra usings

INTERPOSE(CGLayerRetain)(CGLayerRef arg0)
{
    #define RUN_FUNC  CGLayerRef ret = real::CGLayerRetain(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextFillRect"
#pragma push_macro(FUNC_ID)
#undef CGContextFillRect
// extra usings

INTERPOSE(CGContextFillRect)(CGContextRef arg0, CGRect arg1)
{
    #define RUN_FUNC  real::CGContextFillRect(arg0, arg1)

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

#define FUNC_ID "CGAffineTransformInvert"
#pragma push_macro(FUNC_ID)
#undef CGAffineTransformInvert
// extra usings

INTERPOSE(CGAffineTransformInvert)(CGAffineTransform arg0)
{
    #define RUN_FUNC  CGAffineTransform ret = real::CGAffineTransformInvert(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFDocumentGetCropBox"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentGetCropBox
// extra usings

INTERPOSE(CGPDFDocumentGetCropBox)(CGPDFDocumentRef arg0, __int32_t arg1)
{
    #define RUN_FUNC  CGRect ret = real::CGPDFDocumentGetCropBox(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGShieldingWindowID"
#pragma push_macro(FUNC_ID)
#undef CGShieldingWindowID
// extra usings

INTERPOSE(CGShieldingWindowID)(__uint32_t arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CGShieldingWindowID(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPatternGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CGPatternGetTypeID
// extra usings

INTERPOSE(CGPatternGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGPatternGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGImageGetBytesPerRow"
#pragma push_macro(FUNC_ID)
#undef CGImageGetBytesPerRow
// extra usings

INTERPOSE(CGImageGetBytesPerRow)(CGImageRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGImageGetBytesPerRow(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPathRelease"
#pragma push_macro(FUNC_ID)
#undef CGPathRelease
// extra usings

INTERPOSE(CGPathRelease)(CGPathRef arg0)
{
    #define RUN_FUNC  real::CGPathRelease(arg0)

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

#define FUNC_ID "CGDisplayModeGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CGDisplayModeGetTypeID
// extra usings

INTERPOSE(CGDisplayModeGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGDisplayModeGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGContextSetAllowsFontSubpixelQuantization"
#pragma push_macro(FUNC_ID)
#undef CGContextSetAllowsFontSubpixelQuantization
// extra usings

INTERPOSE(CGContextSetAllowsFontSubpixelQuantization)(CGContextRef arg0, bool arg1)
{
    #define RUN_FUNC  real::CGContextSetAllowsFontSubpixelQuantization(arg0, arg1)

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

#define FUNC_ID "CGPathMoveToPoint"
#pragma push_macro(FUNC_ID)
#undef CGPathMoveToPoint
// extra usings
using CGPathMoveToPoint_T_arg1 = const CGAffineTransform *;
using CGPathMoveToPoint_T_arg1 = const CGAffineTransform *;
INTERPOSE(CGPathMoveToPoint)(CGMutablePathRef arg0, CGPathMoveToPoint_T_arg1 arg1, CGFloat arg2, CGFloat arg3)
{
    #define RUN_FUNC  real::CGPathMoveToPoint(arg0, arg1, arg2, arg3)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGPathCreateCopyByTransformingPath"
#pragma push_macro(FUNC_ID)
#undef CGPathCreateCopyByTransformingPath
// extra usings
using CGPathCreateCopyByTransformingPath_T_arg1 = const CGAffineTransform *;
using CGPathCreateCopyByTransformingPath_T_arg1 = const CGAffineTransform *;
INTERPOSE(CGPathCreateCopyByTransformingPath)(CGPathRef arg0, CGPathCreateCopyByTransformingPath_T_arg1 arg1)
{
    #define RUN_FUNC  CGPathRef ret = real::CGPathCreateCopyByTransformingPath(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFDocumentRelease"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentRelease
// extra usings

INTERPOSE(CGPDFDocumentRelease)(CGPDFDocumentRef arg0)
{
    #define RUN_FUNC  real::CGPDFDocumentRelease(arg0)

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

#define FUNC_ID "CGContextSetLineWidth"
#pragma push_macro(FUNC_ID)
#undef CGContextSetLineWidth
// extra usings

INTERPOSE(CGContextSetLineWidth)(CGContextRef arg0, CGFloat arg1)
{
    #define RUN_FUNC  real::CGContextSetLineWidth(arg0, arg1)

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

#define FUNC_ID "CGDisplayStreamCreateWithDispatchQueue"
#pragma push_macro(FUNC_ID)
#undef CGDisplayStreamCreateWithDispatchQueue
// extra usings

INTERPOSE(CGDisplayStreamCreateWithDispatchQueue)(__uint32_t arg0, __darwin_size_t arg1, __darwin_size_t arg2, __int32_t arg3, CFDictionaryRef arg4, dispatch_queue_t arg5, CGDisplayStreamFrameAvailableHandler arg6)
{
    #define RUN_FUNC  CGDisplayStreamRef ret = real::CGDisplayStreamCreateWithDispatchQueue(arg0, arg1, arg2, arg3, arg4, arg5, arg6)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGColorSpaceCreateWithPropertyList"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceCreateWithPropertyList
// extra usings

INTERPOSE(CGColorSpaceCreateWithPropertyList)(const void * arg0)
{
    #define RUN_FUNC  CGColorSpaceRef ret = real::CGColorSpaceCreateWithPropertyList(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextGetPathCurrentPoint"
#pragma push_macro(FUNC_ID)
#undef CGContextGetPathCurrentPoint
// extra usings

INTERPOSE(CGContextGetPathCurrentPoint)(CGContextRef arg0)
{
    #define RUN_FUNC  CGPoint ret = real::CGContextGetPathCurrentPoint(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextSetPatternPhase"
#pragma push_macro(FUNC_ID)
#undef CGContextSetPatternPhase
// extra usings

INTERPOSE(CGContextSetPatternPhase)(CGContextRef arg0, CGSize arg1)
{
    #define RUN_FUNC  real::CGContextSetPatternPhase(arg0, arg1)

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

#define FUNC_ID "CGFontGetAscent"
#pragma push_macro(FUNC_ID)
#undef CGFontGetAscent
// extra usings

INTERPOSE(CGFontGetAscent)(CGFontRef arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGFontGetAscent(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFDictionaryGetDictionary"
#pragma push_macro(FUNC_ID)
#undef CGPDFDictionaryGetDictionary
// extra usings
using CGPDFDictionaryGetDictionary_T_arg2 = CGPDFDictionary **;
using CGPDFDictionaryGetDictionary_T_arg2 = CGPDFDictionary **;
INTERPOSE(CGPDFDictionaryGetDictionary)(CGPDFDictionaryRef arg0, const char * arg1, CGPDFDictionaryGetDictionary_T_arg2 arg2)
{
    #define RUN_FUNC  bool ret = real::CGPDFDictionaryGetDictionary(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextShowGlyphs"
#pragma push_macro(FUNC_ID)
#undef CGContextShowGlyphs
// extra usings

INTERPOSE(CGContextShowGlyphs)(CGContextRef arg0, const unsigned short * arg1, __darwin_size_t arg2)
{
    #define RUN_FUNC  real::CGContextShowGlyphs(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGFontGetLeading"
#pragma push_macro(FUNC_ID)
#undef CGFontGetLeading
// extra usings

INTERPOSE(CGFontGetLeading)(CGFontRef arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGFontGetLeading(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGGradientCreateWithColorComponents"
#pragma push_macro(FUNC_ID)
#undef CGGradientCreateWithColorComponents
// extra usings

INTERPOSE(CGGradientCreateWithColorComponents)(CGColorSpaceRef arg0, const double * arg1, const double * arg2, __darwin_size_t arg3)
{
    #define RUN_FUNC  CGGradientRef ret = real::CGGradientCreateWithColorComponents(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGDisplayGetDrawingContext"
#pragma push_macro(FUNC_ID)
#undef CGDisplayGetDrawingContext
// extra usings

INTERPOSE(CGDisplayGetDrawingContext)(__uint32_t arg0)
{
    #define RUN_FUNC  CGContextRef ret = real::CGDisplayGetDrawingContext(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextMoveToPoint"
#pragma push_macro(FUNC_ID)
#undef CGContextMoveToPoint
// extra usings

INTERPOSE(CGContextMoveToPoint)(CGContextRef arg0, CGFloat arg1, CGFloat arg2)
{
    #define RUN_FUNC  real::CGContextMoveToPoint(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGDisplayStreamUpdateGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CGDisplayStreamUpdateGetTypeID
// extra usings

INTERPOSE(CGDisplayStreamUpdateGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGDisplayStreamUpdateGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGRectGetMinY"
#pragma push_macro(FUNC_ID)
#undef CGRectGetMinY
// extra usings

INTERPOSE(CGRectGetMinY)(CGRect arg0)
{
    #define RUN_FUNC  CGFloat ret = real::CGRectGetMinY(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGRectGetMinX"
#pragma push_macro(FUNC_ID)
#undef CGRectGetMinX
// extra usings

INTERPOSE(CGRectGetMinX)(CGRect arg0)
{
    #define RUN_FUNC  CGFloat ret = real::CGRectGetMinX(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextSetFont"
#pragma push_macro(FUNC_ID)
#undef CGContextSetFont
// extra usings

INTERPOSE(CGContextSetFont)(CGContextRef arg0, CGFontRef arg1)
{
    #define RUN_FUNC  real::CGContextSetFont(arg0, arg1)

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

#define FUNC_ID "CGPDFObjectGetValue"
#pragma push_macro(FUNC_ID)
#undef CGPDFObjectGetValue
// extra usings

INTERPOSE(CGPDFObjectGetValue)(CGPDFObjectRef arg0, __int32_t arg1, void * arg2)
{
    #define RUN_FUNC  bool ret = real::CGPDFObjectGetValue(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGDisplayShowCursor"
#pragma push_macro(FUNC_ID)
#undef CGDisplayShowCursor
// extra usings

INTERPOSE(CGDisplayShowCursor)(__uint32_t arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGDisplayShowCursor(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextRestoreGState"
#pragma push_macro(FUNC_ID)
#undef CGContextRestoreGState
// extra usings

INTERPOSE(CGContextRestoreGState)(CGContextRef arg0)
{
    #define RUN_FUNC  real::CGContextRestoreGState(arg0)

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

#define FUNC_ID "CGPathRetain"
#pragma push_macro(FUNC_ID)
#undef CGPathRetain
// extra usings

INTERPOSE(CGPathRetain)(CGPathRef arg0)
{
    #define RUN_FUNC  CGPathRef ret = real::CGPathRetain(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPDFDocumentGetNumberOfPages"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentGetNumberOfPages
// extra usings

INTERPOSE(CGPDFDocumentGetNumberOfPages)(CGPDFDocumentRef arg0)
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGPDFDocumentGetNumberOfPages(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGAffineTransformMakeScale"
#pragma push_macro(FUNC_ID)
#undef CGAffineTransformMakeScale
// extra usings

INTERPOSE(CGAffineTransformMakeScale)(CGFloat arg0, CGFloat arg1)
{
    #define RUN_FUNC  CGAffineTransform ret = real::CGAffineTransformMakeScale(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPathAddCurveToPoint"
#pragma push_macro(FUNC_ID)
#undef CGPathAddCurveToPoint
// extra usings
using CGPathAddCurveToPoint_T_arg1 = const CGAffineTransform *;
using CGPathAddCurveToPoint_T_arg1 = const CGAffineTransform *;
INTERPOSE(CGPathAddCurveToPoint)(CGMutablePathRef arg0, CGPathAddCurveToPoint_T_arg1 arg1, CGFloat arg2, CGFloat arg3, CGFloat arg4, CGFloat arg5, CGFloat arg6, CGFloat arg7)
{
    #define RUN_FUNC  real::CGPathAddCurveToPoint(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)

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
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGImageCreate"
#pragma push_macro(FUNC_ID)
#undef CGImageCreate
// extra usings

INTERPOSE(CGImageCreate)(__darwin_size_t arg0, __darwin_size_t arg1, __darwin_size_t arg2, __darwin_size_t arg3, __darwin_size_t arg4, CGColorSpaceRef arg5, __uint32_t arg6, CGDataProviderRef arg7, const double * arg8, bool arg9, __int32_t arg10)
{
    #define RUN_FUNC  CGImageRef ret = real::CGImageCreate(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg10);
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
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg10);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGContextSetShouldSmoothFonts"
#pragma push_macro(FUNC_ID)
#undef CGContextSetShouldSmoothFonts
// extra usings

INTERPOSE(CGContextSetShouldSmoothFonts)(CGContextRef arg0, bool arg1)
{
    #define RUN_FUNC  real::CGContextSetShouldSmoothFonts(arg0, arg1)

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

#define FUNC_ID "CGPDFDictionaryGetBoolean"
#pragma push_macro(FUNC_ID)
#undef CGPDFDictionaryGetBoolean
// extra usings

INTERPOSE(CGPDFDictionaryGetBoolean)(CGPDFDictionaryRef arg0, const char * arg1, BytePtr arg2)
{
    #define RUN_FUNC  bool ret = real::CGPDFDictionaryGetBoolean(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFStringGetBytePtr"
#pragma push_macro(FUNC_ID)
#undef CGPDFStringGetBytePtr
// extra usings

INTERPOSE(CGPDFStringGetBytePtr)(CGPDFStringRef arg0)
{
    #define RUN_FUNC  ConstStringPtr ret = real::CGPDFStringGetBytePtr(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGColorGetColorSpace"
#pragma push_macro(FUNC_ID)
#undef CGColorGetColorSpace
// extra usings

INTERPOSE(CGColorGetColorSpace)(CGColorRef arg0)
{
    #define RUN_FUNC  CGColorSpaceRef ret = real::CGColorGetColorSpace(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGDisplayAvailableModes"
#pragma push_macro(FUNC_ID)
#undef CGDisplayAvailableModes
// extra usings

INTERPOSE(CGDisplayAvailableModes)(__uint32_t arg0)
{
    #define RUN_FUNC  CFArrayRef ret = real::CGDisplayAvailableModes(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGColorCreateGenericGrayGamma2_2"
#pragma push_macro(FUNC_ID)
#undef CGColorCreateGenericGrayGamma2_2
// extra usings

INTERPOSE(CGColorCreateGenericGrayGamma2_2)(CGFloat arg0, CGFloat arg1)
{
    #define RUN_FUNC  CGColorRef ret = real::CGColorCreateGenericGrayGamma2_2(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGBitmapContextCreateWithData"
#pragma push_macro(FUNC_ID)
#undef CGBitmapContextCreateWithData
// extra usings

INTERPOSE(CGBitmapContextCreateWithData)(void * arg0, __darwin_size_t arg1, __darwin_size_t arg2, __darwin_size_t arg3, __darwin_size_t arg4, CGColorSpaceRef arg5, __uint32_t arg6, CFAllocatorDeallocateCallBack arg7, void * arg8)
{
    #define RUN_FUNC  CGContextRef ret = real::CGBitmapContextCreateWithData(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPostKeyboardEvent"
#pragma push_macro(FUNC_ID)
#undef CGPostKeyboardEvent
// extra usings

INTERPOSE(CGPostKeyboardEvent)(__uint16_t arg0, __uint16_t arg1, __uint32_t arg2)
{
    #define RUN_FUNC  __int32_t ret = real::CGPostKeyboardEvent(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPathCreateMutableCopy"
#pragma push_macro(FUNC_ID)
#undef CGPathCreateMutableCopy
// extra usings

INTERPOSE(CGPathCreateMutableCopy)(CGPathRef arg0)
{
    #define RUN_FUNC  CGMutablePathRef ret = real::CGPathCreateMutableCopy(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGPathGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CGPathGetTypeID
// extra usings

INTERPOSE(CGPathGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CGPathGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGColorSpaceCreateIndexed"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceCreateIndexed
// extra usings

INTERPOSE(CGColorSpaceCreateIndexed)(CGColorSpaceRef arg0, __darwin_size_t arg1, ConstStringPtr arg2)
{
    #define RUN_FUNC  CGColorSpaceRef ret = real::CGColorSpaceCreateIndexed(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGColorSpaceCreateLab"
#pragma push_macro(FUNC_ID)
#undef CGColorSpaceCreateLab
// extra usings

INTERPOSE(CGColorSpaceCreateLab)(const double * arg0, const double * arg1, const double * arg2)
{
    #define RUN_FUNC  CGColorSpaceRef ret = real::CGColorSpaceCreateLab(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGDisplayIOServicePort"
#pragma push_macro(FUNC_ID)
#undef CGDisplayIOServicePort
// extra usings

INTERPOSE(CGDisplayIOServicePort)(__uint32_t arg0)
{
    #define RUN_FUNC  __int32_t ret = real::CGDisplayIOServicePort(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

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

#define FUNC_ID "CGContextSetFillPattern"
#pragma push_macro(FUNC_ID)
#undef CGContextSetFillPattern
// extra usings

INTERPOSE(CGContextSetFillPattern)(CGContextRef arg0, CGPatternRef arg1, const double * arg2)
{
    #define RUN_FUNC  real::CGContextSetFillPattern(arg0, arg1, arg2)

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
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg2);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg1);
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg2);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CGSizeMakeWithDictionaryRepresentation"
#pragma push_macro(FUNC_ID)
#undef CGSizeMakeWithDictionaryRepresentation
// extra usings

INTERPOSE(CGSizeMakeWithDictionaryRepresentation)(CFDictionaryRef arg0, CGSize * arg1)
{
    #define RUN_FUNC  bool ret = real::CGSizeMakeWithDictionaryRepresentation(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGPDFDocumentUnlockWithPassword"
#pragma push_macro(FUNC_ID)
#undef CGPDFDocumentUnlockWithPassword
// extra usings

INTERPOSE(CGPDFDocumentUnlockWithPassword)(CGPDFDocumentRef arg0, const char * arg1)
{
    #define RUN_FUNC  bool ret = real::CGPDFDocumentUnlockWithPassword(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CGContextSetTextMatrix"
#pragma push_macro(FUNC_ID)
#undef CGContextSetTextMatrix
// extra usings

INTERPOSE(CGContextSetTextMatrix)(CGContextRef arg0, CGAffineTransform arg1)
{
    #define RUN_FUNC  real::CGContextSetTextMatrix(arg0, arg1)

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

#define FUNC_ID "CGContextSetFillColorWithColor"
#pragma push_macro(FUNC_ID)
#undef CGContextSetFillColorWithColor
// extra usings

INTERPOSE(CGContextSetFillColorWithColor)(CGContextRef arg0, CGColorRef arg1)
{
    #define RUN_FUNC  real::CGContextSetFillColorWithColor(arg0, arg1)

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

#define FUNC_ID "CGPDFDictionaryGetName"
#pragma push_macro(FUNC_ID)
#undef CGPDFDictionaryGetName
// extra usings

INTERPOSE(CGPDFDictionaryGetName)(CGPDFDictionaryRef arg0, const char * arg1, const char ** arg2)
{
    #define RUN_FUNC  bool ret = real::CGPDFDictionaryGetName(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

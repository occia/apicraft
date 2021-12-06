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

#define FUNC_ID "CTFontManagerCreateFontDescriptorsFromURL"
#pragma push_macro(FUNC_ID)
#undef CTFontManagerCreateFontDescriptorsFromURL
// extra usings

INTERPOSE(CTFontManagerCreateFontDescriptorsFromURL)(CFURLRef arg0)
{
    #define RUN_FUNC  CFArrayRef ret = real::CTFontManagerCreateFontDescriptorsFromURL(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTLineCreateTruncatedLine"
#pragma push_macro(FUNC_ID)
#undef CTLineCreateTruncatedLine
// extra usings

INTERPOSE(CTLineCreateTruncatedLine)(CTLineRef arg0, double arg1, __uint32_t arg2, CTLineRef arg3)
{
    #define RUN_FUNC  CTLineRef ret = real::CTLineCreateTruncatedLine(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFramesetterCreateFrame"
#pragma push_macro(FUNC_ID)
#undef CTFramesetterCreateFrame
// extra usings

INTERPOSE(CTFramesetterCreateFrame)(CTFramesetterRef arg0, CFRange arg1, CGPathRef arg2, CFDictionaryRef arg3)
{
    #define RUN_FUNC  CTFrameRef ret = real::CTFramesetterCreateFrame(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTTypesetterSuggestClusterBreak"
#pragma push_macro(FUNC_ID)
#undef CTTypesetterSuggestClusterBreak
// extra usings

INTERPOSE(CTTypesetterSuggestClusterBreak)(CTTypesetterRef arg0, __darwin_intptr_t arg1, double arg2)
{
    #define RUN_FUNC  __darwin_intptr_t ret = real::CTTypesetterSuggestClusterBreak(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontCreateCopyWithFamily"
#pragma push_macro(FUNC_ID)
#undef CTFontCreateCopyWithFamily
// extra usings
using CTFontCreateCopyWithFamily_T_arg2 = const CGAffineTransform *;
using CTFontCreateCopyWithFamily_T_arg2 = const CGAffineTransform *;
INTERPOSE(CTFontCreateCopyWithFamily)(CTFontRef arg0, double arg1, CTFontCreateCopyWithFamily_T_arg2 arg2, CFStringRef arg3)
{
    #define RUN_FUNC  CTFontRef ret = real::CTFontCreateCopyWithFamily(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontGetGlyphsForCharacters"
#pragma push_macro(FUNC_ID)
#undef CTFontGetGlyphsForCharacters
// extra usings
using CTFontGetGlyphsForCharacters_T_arg2 = unsigned short *;
using CTFontGetGlyphsForCharacters_T_arg2 = unsigned short *;
INTERPOSE(CTFontGetGlyphsForCharacters)(CTFontRef arg0, const unsigned short * arg1, CTFontGetGlyphsForCharacters_T_arg2 arg2, __darwin_intptr_t arg3)
{
    #define RUN_FUNC  bool ret = real::CTFontGetGlyphsForCharacters(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTLineGetPenOffsetForFlush"
#pragma push_macro(FUNC_ID)
#undef CTLineGetPenOffsetForFlush
// extra usings

INTERPOSE(CTLineGetPenOffsetForFlush)(CTLineRef arg0, double arg1, double arg2)
{
    #define RUN_FUNC  double ret = real::CTLineGetPenOffsetForFlush(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTTypesetterSuggestLineBreak"
#pragma push_macro(FUNC_ID)
#undef CTTypesetterSuggestLineBreak
// extra usings

INTERPOSE(CTTypesetterSuggestLineBreak)(CTTypesetterRef arg0, __darwin_intptr_t arg1, double arg2)
{
    #define RUN_FUNC  __darwin_intptr_t ret = real::CTTypesetterSuggestLineBreak(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontCreateWithGraphicsFont"
#pragma push_macro(FUNC_ID)
#undef CTFontCreateWithGraphicsFont
// extra usings
using CTFontCreateWithGraphicsFont_T_arg2 = const CGAffineTransform *;
using CTFontCreateWithGraphicsFont_T_arg2 = const CGAffineTransform *;
INTERPOSE(CTFontCreateWithGraphicsFont)(CGFontRef arg0, double arg1, CTFontCreateWithGraphicsFont_T_arg2 arg2, CTFontDescriptorRef arg3)
{
    #define RUN_FUNC  CTFontRef ret = real::CTFontCreateWithGraphicsFont(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontDescriptorCreateCopyWithFamily"
#pragma push_macro(FUNC_ID)
#undef CTFontDescriptorCreateCopyWithFamily
// extra usings

INTERPOSE(CTFontDescriptorCreateCopyWithFamily)(CTFontDescriptorRef arg0, CFStringRef arg1)
{
    #define RUN_FUNC  CTFontDescriptorRef ret = real::CTFontDescriptorCreateCopyWithFamily(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTRunGetStringRange"
#pragma push_macro(FUNC_ID)
#undef CTRunGetStringRange
// extra usings

INTERPOSE(CTRunGetStringRange)(CTRunRef arg0)
{
    #define RUN_FUNC  CFRange ret = real::CTRunGetStringRange(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontCreateWithQuickdrawInstance"
#pragma push_macro(FUNC_ID)
#undef CTFontCreateWithQuickdrawInstance
// extra usings

INTERPOSE(CTFontCreateWithQuickdrawInstance)(const unsigned char * arg0, __int16_t arg1, __uint8_t arg2, double arg3)
{
    #define RUN_FUNC  CTFontRef ret = real::CTFontCreateWithQuickdrawInstance(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontManagerUnregisterFontsForURL"
#pragma push_macro(FUNC_ID)
#undef CTFontManagerUnregisterFontsForURL
// extra usings
using CTFontManagerUnregisterFontsForURL_T_arg2 = __CFError **;
using CTFontManagerUnregisterFontsForURL_T_arg2 = __CFError **;
INTERPOSE(CTFontManagerUnregisterFontsForURL)(CFURLRef arg0, __uint32_t arg1, CTFontManagerUnregisterFontsForURL_T_arg2 arg2)
{
    #define RUN_FUNC  bool ret = real::CTFontManagerUnregisterFontsForURL(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTRubyAnnotationCreateWithAttributes"
#pragma push_macro(FUNC_ID)
#undef CTRubyAnnotationCreateWithAttributes
// extra usings

INTERPOSE(CTRubyAnnotationCreateWithAttributes)(__uint8_t arg0, __uint8_t arg1, __uint8_t arg2, CFStringRef arg3, CFDictionaryRef arg4)
{
    #define RUN_FUNC  CTRubyAnnotationRef ret = real::CTRubyAnnotationCreateWithAttributes(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontDescriptorMatchFontDescriptorsWithProgressHandler"
#pragma push_macro(FUNC_ID)
#undef CTFontDescriptorMatchFontDescriptorsWithProgressHandler
// extra usings

INTERPOSE(CTFontDescriptorMatchFontDescriptorsWithProgressHandler)(CFArrayRef arg0, CFSetRef arg1, CTFontDescriptorProgressHandler arg2)
{
    #define RUN_FUNC  bool ret = real::CTFontDescriptorMatchFontDescriptorsWithProgressHandler(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTGlyphInfoGetGlyph"
#pragma push_macro(FUNC_ID)
#undef CTGlyphInfoGetGlyph
// extra usings

INTERPOSE(CTGlyphInfoGetGlyph)(CTGlyphInfoRef arg0)
{
    #define RUN_FUNC  __uint16_t ret = real::CTGlyphInfoGetGlyph(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontManagerCreateFontDescriptorsFromData"
#pragma push_macro(FUNC_ID)
#undef CTFontManagerCreateFontDescriptorsFromData
// extra usings

INTERPOSE(CTFontManagerCreateFontDescriptorsFromData)(CFDataRef arg0)
{
    #define RUN_FUNC  CFArrayRef ret = real::CTFontManagerCreateFontDescriptorsFromData(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTRunDelegateGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CTRunDelegateGetTypeID
// extra usings

INTERPOSE(CTRunDelegateGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CTRunDelegateGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

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

#define FUNC_ID "CTFontCopyAvailableTables"
#pragma push_macro(FUNC_ID)
#undef CTFontCopyAvailableTables
// extra usings

INTERPOSE(CTFontCopyAvailableTables)(CTFontRef arg0, __uint32_t arg1)
{
    #define RUN_FUNC  CFArrayRef ret = real::CTFontCopyAvailableTables(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTFontManagerCopyAvailableFontURLs"
#pragma push_macro(FUNC_ID)
#undef CTFontManagerCopyAvailableFontURLs
// extra usings

INTERPOSE(CTFontManagerCopyAvailableFontURLs)()
{
    #define RUN_FUNC  CFArrayRef ret = real::CTFontManagerCopyAvailableFontURLs()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

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

#define FUNC_ID "CTRubyAnnotationCreate"
#pragma push_macro(FUNC_ID)
#undef CTRubyAnnotationCreate
// extra usings
using CTRubyAnnotationCreate_T_arg3 = const __CFString **;
using CTRubyAnnotationCreate_T_arg3 = const __CFString **;
INTERPOSE(CTRubyAnnotationCreate)(__uint8_t arg0, __uint8_t arg1, double arg2, CTRubyAnnotationCreate_T_arg3 arg3)
{
    #define RUN_FUNC  CTRubyAnnotationRef ret = real::CTRubyAnnotationCreate(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontGetAscent"
#pragma push_macro(FUNC_ID)
#undef CTFontGetAscent
// extra usings

INTERPOSE(CTFontGetAscent)(CTFontRef arg0)
{
    #define RUN_FUNC  double ret = real::CTFontGetAscent(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontManagerRegisterGraphicsFont"
#pragma push_macro(FUNC_ID)
#undef CTFontManagerRegisterGraphicsFont
// extra usings
using CTFontManagerRegisterGraphicsFont_T_arg1 = __CFError **;
using CTFontManagerRegisterGraphicsFont_T_arg1 = __CFError **;
INTERPOSE(CTFontManagerRegisterGraphicsFont)(CGFontRef arg0, CTFontManagerRegisterGraphicsFont_T_arg1 arg1)
{
    #define RUN_FUNC  bool ret = real::CTFontManagerRegisterGraphicsFont(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTFontCollectionCopyQueryDescriptors"
#pragma push_macro(FUNC_ID)
#undef CTFontCollectionCopyQueryDescriptors
// extra usings

INTERPOSE(CTFontCollectionCopyQueryDescriptors)(CTFontCollectionRef arg0)
{
    #define RUN_FUNC  CFArrayRef ret = real::CTFontCollectionCopyQueryDescriptors(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTTypesetterCreateLine"
#pragma push_macro(FUNC_ID)
#undef CTTypesetterCreateLine
// extra usings

INTERPOSE(CTTypesetterCreateLine)(CTTypesetterRef arg0, CFRange arg1)
{
    #define RUN_FUNC  CTLineRef ret = real::CTTypesetterCreateLine(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTFontGetDescent"
#pragma push_macro(FUNC_ID)
#undef CTFontGetDescent
// extra usings

INTERPOSE(CTFontGetDescent)(CTFontRef arg0)
{
    #define RUN_FUNC  double ret = real::CTFontGetDescent(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontCreateWithFontDescriptor"
#pragma push_macro(FUNC_ID)
#undef CTFontCreateWithFontDescriptor
// extra usings
using CTFontCreateWithFontDescriptor_T_arg2 = const CGAffineTransform *;
using CTFontCreateWithFontDescriptor_T_arg2 = const CGAffineTransform *;
INTERPOSE(CTFontCreateWithFontDescriptor)(CTFontDescriptorRef arg0, double arg1, CTFontCreateWithFontDescriptor_T_arg2 arg2)
{
    #define RUN_FUNC  CTFontRef ret = real::CTFontCreateWithFontDescriptor(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTRunGetAttributes"
#pragma push_macro(FUNC_ID)
#undef CTRunGetAttributes
// extra usings

INTERPOSE(CTRunGetAttributes)(CTRunRef arg0)
{
    #define RUN_FUNC  CFDictionaryRef ret = real::CTRunGetAttributes(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontCopySupportedLanguages"
#pragma push_macro(FUNC_ID)
#undef CTFontCopySupportedLanguages
// extra usings

INTERPOSE(CTFontCopySupportedLanguages)(CTFontRef arg0)
{
    #define RUN_FUNC  CFArrayRef ret = real::CTFontCopySupportedLanguages(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontCopyVariationAxes"
#pragma push_macro(FUNC_ID)
#undef CTFontCopyVariationAxes
// extra usings

INTERPOSE(CTFontCopyVariationAxes)(CTFontRef arg0)
{
    #define RUN_FUNC  CFArrayRef ret = real::CTFontCopyVariationAxes(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTTextTabGetLocation"
#pragma push_macro(FUNC_ID)
#undef CTTextTabGetLocation
// extra usings

INTERPOSE(CTTextTabGetLocation)(CTTextTabRef arg0)
{
    #define RUN_FUNC  double ret = real::CTTextTabGetLocation(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontCopyPostScriptName"
#pragma push_macro(FUNC_ID)
#undef CTFontCopyPostScriptName
// extra usings

INTERPOSE(CTFontCopyPostScriptName)(CTFontRef arg0)
{
    #define RUN_FUNC  CFStringRef ret = real::CTFontCopyPostScriptName(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontCopyDefaultCascadeListForLanguages"
#pragma push_macro(FUNC_ID)
#undef CTFontCopyDefaultCascadeListForLanguages
// extra usings

INTERPOSE(CTFontCopyDefaultCascadeListForLanguages)(CTFontRef arg0, CFArrayRef arg1)
{
    #define RUN_FUNC  CFArrayRef ret = real::CTFontCopyDefaultCascadeListForLanguages(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTRunGetBaseAdvancesAndOrigins"
#pragma push_macro(FUNC_ID)
#undef CTRunGetBaseAdvancesAndOrigins
// extra usings

INTERPOSE(CTRunGetBaseAdvancesAndOrigins)(CTRunRef arg0, CFRange arg1, CGSize * arg2, CGPoint * arg3)
{
    #define RUN_FUNC  real::CTRunGetBaseAdvancesAndOrigins(arg0, arg1, arg2, arg3)

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

#define FUNC_ID "CTFontGetVerticalTranslationsForGlyphs"
#pragma push_macro(FUNC_ID)
#undef CTFontGetVerticalTranslationsForGlyphs
// extra usings

INTERPOSE(CTFontGetVerticalTranslationsForGlyphs)(CTFontRef arg0, const unsigned short * arg1, CGSize * arg2, __darwin_intptr_t arg3)
{
    #define RUN_FUNC  real::CTFontGetVerticalTranslationsForGlyphs(arg0, arg1, arg2, arg3)

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

#define FUNC_ID "CTFontCollectionCreateMatchingFontDescriptorsWithOptions"
#pragma push_macro(FUNC_ID)
#undef CTFontCollectionCreateMatchingFontDescriptorsWithOptions
// extra usings

INTERPOSE(CTFontCollectionCreateMatchingFontDescriptorsWithOptions)(CTFontCollectionRef arg0, CFDictionaryRef arg1)
{
    #define RUN_FUNC  CFArrayRef ret = real::CTFontCollectionCreateMatchingFontDescriptorsWithOptions(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTFramesetterCreateWithAttributedString"
#pragma push_macro(FUNC_ID)
#undef CTFramesetterCreateWithAttributedString
// extra usings

INTERPOSE(CTFramesetterCreateWithAttributedString)(CFAttributedStringRef arg0)
{
    #define RUN_FUNC  CTFramesetterRef ret = real::CTFramesetterCreateWithAttributedString(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontCreatePathForGlyph"
#pragma push_macro(FUNC_ID)
#undef CTFontCreatePathForGlyph
// extra usings
using CTFontCreatePathForGlyph_T_arg2 = const CGAffineTransform *;
using CTFontCreatePathForGlyph_T_arg2 = const CGAffineTransform *;
INTERPOSE(CTFontCreatePathForGlyph)(CTFontRef arg0, __uint16_t arg1, CTFontCreatePathForGlyph_T_arg2 arg2)
{
    #define RUN_FUNC  CGPathRef ret = real::CTFontCreatePathForGlyph(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFrameDraw"
#pragma push_macro(FUNC_ID)
#undef CTFrameDraw
// extra usings

INTERPOSE(CTFrameDraw)(CTFrameRef arg0, CGContextRef arg1)
{
    #define RUN_FUNC  real::CTFrameDraw(arg0, arg1)

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

#define FUNC_ID "CTFontCollectionCopyExclusionDescriptors"
#pragma push_macro(FUNC_ID)
#undef CTFontCollectionCopyExclusionDescriptors
// extra usings

INTERPOSE(CTFontCollectionCopyExclusionDescriptors)(CTFontCollectionRef arg0)
{
    #define RUN_FUNC  CFArrayRef ret = real::CTFontCollectionCopyExclusionDescriptors(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTLineGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CTLineGetTypeID
// extra usings

INTERPOSE(CTLineGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CTLineGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

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

#define FUNC_ID "CTFontManagerGetAutoActivationSetting"
#pragma push_macro(FUNC_ID)
#undef CTFontManagerGetAutoActivationSetting
// extra usings

INTERPOSE(CTFontManagerGetAutoActivationSetting)(CFStringRef arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CTFontManagerGetAutoActivationSetting(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontGetOpticalBoundsForGlyphs"
#pragma push_macro(FUNC_ID)
#undef CTFontGetOpticalBoundsForGlyphs
// extra usings

INTERPOSE(CTFontGetOpticalBoundsForGlyphs)(CTFontRef arg0, const unsigned short * arg1, CGRect * arg2, __darwin_intptr_t arg3, __darwin_size_t arg4)
{
    #define RUN_FUNC  CGRect ret = real::CTFontGetOpticalBoundsForGlyphs(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontDescriptorCopyAttribute"
#pragma push_macro(FUNC_ID)
#undef CTFontDescriptorCopyAttribute
// extra usings

INTERPOSE(CTFontDescriptorCopyAttribute)(CTFontDescriptorRef arg0, CFStringRef arg1)
{
    #define RUN_FUNC  const void * ret = real::CTFontDescriptorCopyAttribute(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTFontCreateWithFontDescriptorAndOptions"
#pragma push_macro(FUNC_ID)
#undef CTFontCreateWithFontDescriptorAndOptions
// extra usings
using CTFontCreateWithFontDescriptorAndOptions_T_arg2 = const CGAffineTransform *;
using CTFontCreateWithFontDescriptorAndOptions_T_arg2 = const CGAffineTransform *;
INTERPOSE(CTFontCreateWithFontDescriptorAndOptions)(CTFontDescriptorRef arg0, double arg1, CTFontCreateWithFontDescriptorAndOptions_T_arg2 arg2, __darwin_size_t arg3)
{
    #define RUN_FUNC  CTFontRef ret = real::CTFontCreateWithFontDescriptorAndOptions(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontGetMatrix"
#pragma push_macro(FUNC_ID)
#undef CTFontGetMatrix
// extra usings

INTERPOSE(CTFontGetMatrix)(CTFontRef arg0)
{
    #define RUN_FUNC  CGAffineTransform ret = real::CTFontGetMatrix(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontGetSymbolicTraits"
#pragma push_macro(FUNC_ID)
#undef CTFontGetSymbolicTraits
// extra usings

INTERPOSE(CTFontGetSymbolicTraits)(CTFontRef arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CTFontGetSymbolicTraits(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontCreateCopyWithAttributes"
#pragma push_macro(FUNC_ID)
#undef CTFontCreateCopyWithAttributes
// extra usings
using CTFontCreateCopyWithAttributes_T_arg2 = const CGAffineTransform *;
using CTFontCreateCopyWithAttributes_T_arg2 = const CGAffineTransform *;
INTERPOSE(CTFontCreateCopyWithAttributes)(CTFontRef arg0, double arg1, CTFontCreateCopyWithAttributes_T_arg2 arg2, CTFontDescriptorRef arg3)
{
    #define RUN_FUNC  CTFontRef ret = real::CTFontCreateCopyWithAttributes(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTRubyAnnotationGetSizeFactor"
#pragma push_macro(FUNC_ID)
#undef CTRubyAnnotationGetSizeFactor
// extra usings

INTERPOSE(CTRubyAnnotationGetSizeFactor)(CTRubyAnnotationRef arg0)
{
    #define RUN_FUNC  double ret = real::CTRubyAnnotationGetSizeFactor(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontCollectionCopyFontAttribute"
#pragma push_macro(FUNC_ID)
#undef CTFontCollectionCopyFontAttribute
// extra usings

INTERPOSE(CTFontCollectionCopyFontAttribute)(CTFontCollectionRef arg0, CFStringRef arg1, __uint32_t arg2)
{
    #define RUN_FUNC  CFArrayRef ret = real::CTFontCollectionCopyFontAttribute(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontCopyFamilyName"
#pragma push_macro(FUNC_ID)
#undef CTFontCopyFamilyName
// extra usings

INTERPOSE(CTFontCopyFamilyName)(CTFontRef arg0)
{
    #define RUN_FUNC  CFStringRef ret = real::CTFontCopyFamilyName(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTGlyphInfoGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CTGlyphInfoGetTypeID
// extra usings

INTERPOSE(CTGlyphInfoGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CTGlyphInfoGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

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

#define FUNC_ID "CTParagraphStyleCreate"
#pragma push_macro(FUNC_ID)
#undef CTParagraphStyleCreate
// extra usings

INTERPOSE(CTParagraphStyleCreate)(const CTParagraphStyleSetting * arg0, __darwin_size_t arg1)
{
    #define RUN_FUNC  CTParagraphStyleRef ret = real::CTParagraphStyleCreate(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTRunGetImageBounds"
#pragma push_macro(FUNC_ID)
#undef CTRunGetImageBounds
// extra usings

INTERPOSE(CTRunGetImageBounds)(CTRunRef arg0, CGContextRef arg1, CFRange arg2)
{
    #define RUN_FUNC  CGRect ret = real::CTRunGetImageBounds(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontManagerIsSupportedFont"
#pragma push_macro(FUNC_ID)
#undef CTFontManagerIsSupportedFont
// extra usings

INTERPOSE(CTFontManagerIsSupportedFont)(CFURLRef arg0)
{
    #define RUN_FUNC  bool ret = real::CTFontManagerIsSupportedFont(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTRunGetAdvancesPtr"
#pragma push_macro(FUNC_ID)
#undef CTRunGetAdvancesPtr
// extra usings
using CTRunGetAdvancesPtr_T_ret = const CGSize *;
using CTRunGetAdvancesPtr_T_ret = const CGSize *;
INTERPOSE(CTRunGetAdvancesPtr)(CTRunRef arg0)
{
    #define RUN_FUNC  CTRunGetAdvancesPtr_T_ret ret = real::CTRunGetAdvancesPtr(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTRunGetStatus"
#pragma push_macro(FUNC_ID)
#undef CTRunGetStatus
// extra usings

INTERPOSE(CTRunGetStatus)(CTRunRef arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CTRunGetStatus(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTGlyphInfoGetCharacterIdentifier"
#pragma push_macro(FUNC_ID)
#undef CTGlyphInfoGetCharacterIdentifier
// extra usings

INTERPOSE(CTGlyphInfoGetCharacterIdentifier)(CTGlyphInfoRef arg0)
{
    #define RUN_FUNC  __uint16_t ret = real::CTGlyphInfoGetCharacterIdentifier(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontGetUnitsPerEm"
#pragma push_macro(FUNC_ID)
#undef CTFontGetUnitsPerEm
// extra usings

INTERPOSE(CTFontGetUnitsPerEm)(CTFontRef arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CTFontGetUnitsPerEm(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontCopyVariation"
#pragma push_macro(FUNC_ID)
#undef CTFontCopyVariation
// extra usings

INTERPOSE(CTFontCopyVariation)(CTFontRef arg0)
{
    #define RUN_FUNC  CFDictionaryRef ret = real::CTFontCopyVariation(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFrameGetFrameAttributes"
#pragma push_macro(FUNC_ID)
#undef CTFrameGetFrameAttributes
// extra usings

INTERPOSE(CTFrameGetFrameAttributes)(CTFrameRef arg0)
{
    #define RUN_FUNC  CFDictionaryRef ret = real::CTFrameGetFrameAttributes(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFramesetterCreateWithTypesetter"
#pragma push_macro(FUNC_ID)
#undef CTFramesetterCreateWithTypesetter
// extra usings

INTERPOSE(CTFramesetterCreateWithTypesetter)(CTTypesetterRef arg0)
{
    #define RUN_FUNC  CTFramesetterRef ret = real::CTFramesetterCreateWithTypesetter(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTTextTabCreate"
#pragma push_macro(FUNC_ID)
#undef CTTextTabCreate
// extra usings

INTERPOSE(CTTextTabCreate)(__uint8_t arg0, double arg1, CFDictionaryRef arg2)
{
    #define RUN_FUNC  CTTextTabRef ret = real::CTTextTabCreate(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontCollectionSetExclusionDescriptors"
#pragma push_macro(FUNC_ID)
#undef CTFontCollectionSetExclusionDescriptors
// extra usings

INTERPOSE(CTFontCollectionSetExclusionDescriptors)(CTMutableFontCollectionRef arg0, CFArrayRef arg1)
{
    #define RUN_FUNC  real::CTFontCollectionSetExclusionDescriptors(arg0, arg1)

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

#define FUNC_ID "CTFrameGetPath"
#pragma push_macro(FUNC_ID)
#undef CTFrameGetPath
// extra usings

INTERPOSE(CTFrameGetPath)(CTFrameRef arg0)
{
    #define RUN_FUNC  CGPathRef ret = real::CTFrameGetPath(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFrameGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CTFrameGetTypeID
// extra usings

INTERPOSE(CTFrameGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CTFrameGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

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

#define FUNC_ID "CTFramesetterGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CTFramesetterGetTypeID
// extra usings

INTERPOSE(CTFramesetterGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CTFramesetterGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

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

#define FUNC_ID "CTFontCollectionCreateFromAvailableFonts"
#pragma push_macro(FUNC_ID)
#undef CTFontCollectionCreateFromAvailableFonts
// extra usings

INTERPOSE(CTFontCollectionCreateFromAvailableFonts)(CFDictionaryRef arg0)
{
    #define RUN_FUNC  CTFontCollectionRef ret = real::CTFontCollectionCreateFromAvailableFonts(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTRunGetGlyphsPtr"
#pragma push_macro(FUNC_ID)
#undef CTRunGetGlyphsPtr
// extra usings

INTERPOSE(CTRunGetGlyphsPtr)(CTRunRef arg0)
{
    #define RUN_FUNC  const unsigned short * ret = real::CTRunGetGlyphsPtr(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontDrawGlyphs"
#pragma push_macro(FUNC_ID)
#undef CTFontDrawGlyphs
// extra usings
using CTFontDrawGlyphs_T_arg2 = const CGPoint *;
using CTFontDrawGlyphs_T_arg2 = const CGPoint *;
INTERPOSE(CTFontDrawGlyphs)(CTFontRef arg0, const unsigned short * arg1, CTFontDrawGlyphs_T_arg2 arg2, __darwin_size_t arg3, CGContextRef arg4)
{
    #define RUN_FUNC  real::CTFontDrawGlyphs(arg0, arg1, arg2, arg3, arg4)

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

#define FUNC_ID "CTFontGetGlyphCount"
#pragma push_macro(FUNC_ID)
#undef CTFontGetGlyphCount
// extra usings

INTERPOSE(CTFontGetGlyphCount)(CTFontRef arg0)
{
    #define RUN_FUNC  __darwin_intptr_t ret = real::CTFontGetGlyphCount(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontManagerCreateFontDescriptorFromData"
#pragma push_macro(FUNC_ID)
#undef CTFontManagerCreateFontDescriptorFromData
// extra usings

INTERPOSE(CTFontManagerCreateFontDescriptorFromData)(CFDataRef arg0)
{
    #define RUN_FUNC  CTFontDescriptorRef ret = real::CTFontManagerCreateFontDescriptorFromData(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTGlyphInfoGetCharacterCollection"
#pragma push_macro(FUNC_ID)
#undef CTGlyphInfoGetCharacterCollection
// extra usings

INTERPOSE(CTGlyphInfoGetCharacterCollection)(CTGlyphInfoRef arg0)
{
    #define RUN_FUNC  __uint16_t ret = real::CTGlyphInfoGetCharacterCollection(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontCopyAttribute"
#pragma push_macro(FUNC_ID)
#undef CTFontCopyAttribute
// extra usings

INTERPOSE(CTFontCopyAttribute)(CTFontRef arg0, CFStringRef arg1)
{
    #define RUN_FUNC  const void * ret = real::CTFontCopyAttribute(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTFontGetBoundingRectsForGlyphs"
#pragma push_macro(FUNC_ID)
#undef CTFontGetBoundingRectsForGlyphs
// extra usings

INTERPOSE(CTFontGetBoundingRectsForGlyphs)(CTFontRef arg0, __uint32_t arg1, const unsigned short * arg2, CGRect * arg3, __darwin_intptr_t arg4)
{
    #define RUN_FUNC  CGRect ret = real::CTFontGetBoundingRectsForGlyphs(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontGetBoundingBox"
#pragma push_macro(FUNC_ID)
#undef CTFontGetBoundingBox
// extra usings

INTERPOSE(CTFontGetBoundingBox)(CTFontRef arg0)
{
    #define RUN_FUNC  CGRect ret = real::CTFontGetBoundingBox(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontManagerSetAutoActivationSetting"
#pragma push_macro(FUNC_ID)
#undef CTFontManagerSetAutoActivationSetting
// extra usings

INTERPOSE(CTFontManagerSetAutoActivationSetting)(CFStringRef arg0, __uint32_t arg1)
{
    #define RUN_FUNC  real::CTFontManagerSetAutoActivationSetting(arg0, arg1)

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

#define FUNC_ID "CTTypesetterCreateWithAttributedStringAndOptions"
#pragma push_macro(FUNC_ID)
#undef CTTypesetterCreateWithAttributedStringAndOptions
// extra usings

INTERPOSE(CTTypesetterCreateWithAttributedStringAndOptions)(CFAttributedStringRef arg0, CFDictionaryRef arg1)
{
    #define RUN_FUNC  CTTypesetterRef ret = real::CTTypesetterCreateWithAttributedStringAndOptions(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTLineGetImageBounds"
#pragma push_macro(FUNC_ID)
#undef CTLineGetImageBounds
// extra usings

INTERPOSE(CTLineGetImageBounds)(CTLineRef arg0, CGContextRef arg1)
{
    #define RUN_FUNC  CGRect ret = real::CTLineGetImageBounds(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTFontCopyDisplayName"
#pragma push_macro(FUNC_ID)
#undef CTFontCopyDisplayName
// extra usings

INTERPOSE(CTFontCopyDisplayName)(CTFontRef arg0)
{
    #define RUN_FUNC  CFStringRef ret = real::CTFontCopyDisplayName(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTGetCoreTextVersion"
#pragma push_macro(FUNC_ID)
#undef CTGetCoreTextVersion
// extra usings

INTERPOSE(CTGetCoreTextVersion)()
{
    #define RUN_FUNC  __uint32_t ret = real::CTGetCoreTextVersion()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

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

#define FUNC_ID "CTParagraphStyleCreateCopy"
#pragma push_macro(FUNC_ID)
#undef CTParagraphStyleCreateCopy
// extra usings

INTERPOSE(CTParagraphStyleCreateCopy)(CTParagraphStyleRef arg0)
{
    #define RUN_FUNC  CTParagraphStyleRef ret = real::CTParagraphStyleCreateCopy(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontGetAdvancesForGlyphs"
#pragma push_macro(FUNC_ID)
#undef CTFontGetAdvancesForGlyphs
// extra usings

INTERPOSE(CTFontGetAdvancesForGlyphs)(CTFontRef arg0, __uint32_t arg1, const unsigned short * arg2, CGSize * arg3, __darwin_intptr_t arg4)
{
    #define RUN_FUNC  double ret = real::CTFontGetAdvancesForGlyphs(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTTextTabGetOptions"
#pragma push_macro(FUNC_ID)
#undef CTTextTabGetOptions
// extra usings

INTERPOSE(CTTextTabGetOptions)(CTTextTabRef arg0)
{
    #define RUN_FUNC  CFDictionaryRef ret = real::CTTextTabGetOptions(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTGlyphInfoCreateWithGlyph"
#pragma push_macro(FUNC_ID)
#undef CTGlyphInfoCreateWithGlyph
// extra usings

INTERPOSE(CTGlyphInfoCreateWithGlyph)(__uint16_t arg0, CTFontRef arg1, CFStringRef arg2)
{
    #define RUN_FUNC  CTGlyphInfoRef ret = real::CTGlyphInfoCreateWithGlyph(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontCreateWithPlatformFont"
#pragma push_macro(FUNC_ID)
#undef CTFontCreateWithPlatformFont
// extra usings
using CTFontCreateWithPlatformFont_T_arg2 = const CGAffineTransform *;
using CTFontCreateWithPlatformFont_T_arg2 = const CGAffineTransform *;
INTERPOSE(CTFontCreateWithPlatformFont)(__uint32_t arg0, double arg1, CTFontCreateWithPlatformFont_T_arg2 arg2, CTFontDescriptorRef arg3)
{
    #define RUN_FUNC  CTFontRef ret = real::CTFontCreateWithPlatformFont(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontCreateForStringWithLanguage"
#pragma push_macro(FUNC_ID)
#undef CTFontCreateForStringWithLanguage
// extra usings

INTERPOSE(CTFontCreateForStringWithLanguage)(CTFontRef arg0, CFStringRef arg1, CFRange arg2, CFStringRef arg3)
{
    #define RUN_FUNC  CTFontRef ret = real::CTFontCreateForStringWithLanguage(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontManagerUnregisterGraphicsFont"
#pragma push_macro(FUNC_ID)
#undef CTFontManagerUnregisterGraphicsFont
// extra usings
using CTFontManagerUnregisterGraphicsFont_T_arg1 = __CFError **;
using CTFontManagerUnregisterGraphicsFont_T_arg1 = __CFError **;
INTERPOSE(CTFontManagerUnregisterGraphicsFont)(CGFontRef arg0, CTFontManagerUnregisterGraphicsFont_T_arg1 arg1)
{
    #define RUN_FUNC  bool ret = real::CTFontManagerUnregisterGraphicsFont(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTRubyAnnotationCreateCopy"
#pragma push_macro(FUNC_ID)
#undef CTRubyAnnotationCreateCopy
// extra usings

INTERPOSE(CTRubyAnnotationCreateCopy)(CTRubyAnnotationRef arg0)
{
    #define RUN_FUNC  CTRubyAnnotationRef ret = real::CTRubyAnnotationCreateCopy(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTTypesetterSuggestClusterBreakWithOffset"
#pragma push_macro(FUNC_ID)
#undef CTTypesetterSuggestClusterBreakWithOffset
// extra usings

INTERPOSE(CTTypesetterSuggestClusterBreakWithOffset)(CTTypesetterRef arg0, __darwin_intptr_t arg1, double arg2, double arg3)
{
    #define RUN_FUNC  __darwin_intptr_t ret = real::CTTypesetterSuggestClusterBreakWithOffset(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTRunGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CTRunGetTypeID
// extra usings

INTERPOSE(CTRunGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CTRunGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

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

#define FUNC_ID "CTRubyAnnotationGetTextForPosition"
#pragma push_macro(FUNC_ID)
#undef CTRubyAnnotationGetTextForPosition
// extra usings

INTERPOSE(CTRubyAnnotationGetTextForPosition)(CTRubyAnnotationRef arg0, __uint8_t arg1)
{
    #define RUN_FUNC  CFStringRef ret = real::CTRubyAnnotationGetTextForPosition(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTLineGetTypographicBounds"
#pragma push_macro(FUNC_ID)
#undef CTLineGetTypographicBounds
// extra usings

INTERPOSE(CTLineGetTypographicBounds)(CTLineRef arg0, double * arg1, double * arg2, double * arg3)
{
    #define RUN_FUNC  double ret = real::CTLineGetTypographicBounds(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontGetPlatformFont"
#pragma push_macro(FUNC_ID)
#undef CTFontGetPlatformFont
// extra usings
using CTFontGetPlatformFont_T_arg1 = const __CTFontDescriptor **;
using CTFontGetPlatformFont_T_arg1 = const __CTFontDescriptor **;
INTERPOSE(CTFontGetPlatformFont)(CTFontRef arg0, CTFontGetPlatformFont_T_arg1 arg1)
{
    #define RUN_FUNC  __uint32_t ret = real::CTFontGetPlatformFont(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTLineGetTrailingWhitespaceWidth"
#pragma push_macro(FUNC_ID)
#undef CTLineGetTrailingWhitespaceWidth
// extra usings

INTERPOSE(CTLineGetTrailingWhitespaceWidth)(CTLineRef arg0)
{
    #define RUN_FUNC  double ret = real::CTLineGetTrailingWhitespaceWidth(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontManagerRegisterFontsForURL"
#pragma push_macro(FUNC_ID)
#undef CTFontManagerRegisterFontsForURL
// extra usings
using CTFontManagerRegisterFontsForURL_T_arg2 = __CFError **;
using CTFontManagerRegisterFontsForURL_T_arg2 = __CFError **;
INTERPOSE(CTFontManagerRegisterFontsForURL)(CFURLRef arg0, __uint32_t arg1, CTFontManagerRegisterFontsForURL_T_arg2 arg2)
{
    #define RUN_FUNC  bool ret = real::CTFontManagerRegisterFontsForURL(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontCopyTable"
#pragma push_macro(FUNC_ID)
#undef CTFontCopyTable
// extra usings

INTERPOSE(CTFontCopyTable)(CTFontRef arg0, __uint32_t arg1, __uint32_t arg2)
{
    #define RUN_FUNC  CFDataRef ret = real::CTFontCopyTable(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTTypesetterSuggestLineBreakWithOffset"
#pragma push_macro(FUNC_ID)
#undef CTTypesetterSuggestLineBreakWithOffset
// extra usings

INTERPOSE(CTTypesetterSuggestLineBreakWithOffset)(CTTypesetterRef arg0, __darwin_intptr_t arg1, double arg2, double arg3)
{
    #define RUN_FUNC  __darwin_intptr_t ret = real::CTTypesetterSuggestLineBreakWithOffset(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTGlyphInfoCreateWithCharacterIdentifier"
#pragma push_macro(FUNC_ID)
#undef CTGlyphInfoCreateWithCharacterIdentifier
// extra usings

INTERPOSE(CTGlyphInfoCreateWithCharacterIdentifier)(__uint16_t arg0, __uint16_t arg1, CFStringRef arg2)
{
    #define RUN_FUNC  CTGlyphInfoRef ret = real::CTGlyphInfoCreateWithCharacterIdentifier(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontCopyCharacterSet"
#pragma push_macro(FUNC_ID)
#undef CTFontCopyCharacterSet
// extra usings

INTERPOSE(CTFontCopyCharacterSet)(CTFontRef arg0)
{
    #define RUN_FUNC  CFCharacterSetRef ret = real::CTFontCopyCharacterSet(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontGetStringEncoding"
#pragma push_macro(FUNC_ID)
#undef CTFontGetStringEncoding
// extra usings

INTERPOSE(CTFontGetStringEncoding)(CTFontRef arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CTFontGetStringEncoding(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTRunGetStringIndices"
#pragma push_macro(FUNC_ID)
#undef CTRunGetStringIndices
// extra usings
using CTRunGetStringIndices_T_arg2 = long *;
using CTRunGetStringIndices_T_arg2 = long *;
INTERPOSE(CTRunGetStringIndices)(CTRunRef arg0, CFRange arg1, CTRunGetStringIndices_T_arg2 arg2)
{
    #define RUN_FUNC  real::CTRunGetStringIndices(arg0, arg1, arg2)

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

#define FUNC_ID "CTRunGetAdvances"
#pragma push_macro(FUNC_ID)
#undef CTRunGetAdvances
// extra usings

INTERPOSE(CTRunGetAdvances)(CTRunRef arg0, CFRange arg1, CGSize * arg2)
{
    #define RUN_FUNC  real::CTRunGetAdvances(arg0, arg1, arg2)

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

#define FUNC_ID "CTFontCollectionCreateMatchingFontDescriptorsSortedWithCallback"
#pragma push_macro(FUNC_ID)
#undef CTFontCollectionCreateMatchingFontDescriptorsSortedWithCallback
// extra usings

INTERPOSE(CTFontCollectionCreateMatchingFontDescriptorsSortedWithCallback)(CTFontCollectionRef arg0, CTFontCollectionSortDescriptorsCallback arg1, void * arg2)
{
    #define RUN_FUNC  CFArrayRef ret = real::CTFontCollectionCreateMatchingFontDescriptorsSortedWithCallback(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontCopyFullName"
#pragma push_macro(FUNC_ID)
#undef CTFontCopyFullName
// extra usings

INTERPOSE(CTFontCopyFullName)(CTFontRef arg0)
{
    #define RUN_FUNC  CFStringRef ret = real::CTFontCopyFullName(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTParagraphStyleGetValueForSpecifier"
#pragma push_macro(FUNC_ID)
#undef CTParagraphStyleGetValueForSpecifier
// extra usings

INTERPOSE(CTParagraphStyleGetValueForSpecifier)(CTParagraphStyleRef arg0, __uint32_t arg1, __darwin_size_t arg2, void * arg3)
{
    #define RUN_FUNC  bool ret = real::CTParagraphStyleGetValueForSpecifier(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTLineGetOffsetForStringIndex"
#pragma push_macro(FUNC_ID)
#undef CTLineGetOffsetForStringIndex
// extra usings

INTERPOSE(CTLineGetOffsetForStringIndex)(CTLineRef arg0, __darwin_intptr_t arg1, double * arg2)
{
    #define RUN_FUNC  double ret = real::CTLineGetOffsetForStringIndex(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTRunDraw"
#pragma push_macro(FUNC_ID)
#undef CTRunDraw
// extra usings

INTERPOSE(CTRunDraw)(CTRunRef arg0, CGContextRef arg1, CFRange arg2)
{
    #define RUN_FUNC  real::CTRunDraw(arg0, arg1, arg2)

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

#define FUNC_ID "CTFontManagerEnableFontDescriptors"
#pragma push_macro(FUNC_ID)
#undef CTFontManagerEnableFontDescriptors
// extra usings

INTERPOSE(CTFontManagerEnableFontDescriptors)(CFArrayRef arg0, bool arg1)
{
    #define RUN_FUNC  real::CTFontManagerEnableFontDescriptors(arg0, arg1)

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

#define FUNC_ID "CTRubyAnnotationGetAlignment"
#pragma push_macro(FUNC_ID)
#undef CTRubyAnnotationGetAlignment
// extra usings

INTERPOSE(CTRubyAnnotationGetAlignment)(CTRubyAnnotationRef arg0)
{
    #define RUN_FUNC  __uint8_t ret = real::CTRubyAnnotationGetAlignment(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontCopyLocalizedName"
#pragma push_macro(FUNC_ID)
#undef CTFontCopyLocalizedName
// extra usings
using CTFontCopyLocalizedName_T_arg2 = const __CFString **;
using CTFontCopyLocalizedName_T_arg2 = const __CFString **;
INTERPOSE(CTFontCopyLocalizedName)(CTFontRef arg0, CFStringRef arg1, CTFontCopyLocalizedName_T_arg2 arg2)
{
    #define RUN_FUNC  CFStringRef ret = real::CTFontCopyLocalizedName(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CTFontGetTypeID
// extra usings

INTERPOSE(CTFontGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CTFontGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

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

#define FUNC_ID "CTFontManagerGetScopeForURL"
#pragma push_macro(FUNC_ID)
#undef CTFontManagerGetScopeForURL
// extra usings

INTERPOSE(CTFontManagerGetScopeForURL)(CFURLRef arg0)
{
    #define RUN_FUNC  __uint32_t ret = real::CTFontManagerGetScopeForURL(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontGetSize"
#pragma push_macro(FUNC_ID)
#undef CTFontGetSize
// extra usings

INTERPOSE(CTFontGetSize)(CTFontRef arg0)
{
    #define RUN_FUNC  double ret = real::CTFontGetSize(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontCollectionGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CTFontCollectionGetTypeID
// extra usings

INTERPOSE(CTFontCollectionGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CTFontCollectionGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

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

#define FUNC_ID "CTFontGetGlyphWithName"
#pragma push_macro(FUNC_ID)
#undef CTFontGetGlyphWithName
// extra usings

INTERPOSE(CTFontGetGlyphWithName)(CTFontRef arg0, CFStringRef arg1)
{
    #define RUN_FUNC  __uint16_t ret = real::CTFontGetGlyphWithName(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTLineGetGlyphRuns"
#pragma push_macro(FUNC_ID)
#undef CTLineGetGlyphRuns
// extra usings

INTERPOSE(CTLineGetGlyphRuns)(CTLineRef arg0)
{
    #define RUN_FUNC  CFArrayRef ret = real::CTLineGetGlyphRuns(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontCreateWithNameAndOptions"
#pragma push_macro(FUNC_ID)
#undef CTFontCreateWithNameAndOptions
// extra usings
using CTFontCreateWithNameAndOptions_T_arg2 = const CGAffineTransform *;
using CTFontCreateWithNameAndOptions_T_arg2 = const CGAffineTransform *;
INTERPOSE(CTFontCreateWithNameAndOptions)(CFStringRef arg0, double arg1, CTFontCreateWithNameAndOptions_T_arg2 arg2, __darwin_size_t arg3)
{
    #define RUN_FUNC  CTFontRef ret = real::CTFontCreateWithNameAndOptions(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontDescriptorCreateCopyWithAttributes"
#pragma push_macro(FUNC_ID)
#undef CTFontDescriptorCreateCopyWithAttributes
// extra usings

INTERPOSE(CTFontDescriptorCreateCopyWithAttributes)(CTFontDescriptorRef arg0, CFDictionaryRef arg1)
{
    #define RUN_FUNC  CTFontDescriptorRef ret = real::CTFontDescriptorCreateCopyWithAttributes(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTFontCopyFontDescriptor"
#pragma push_macro(FUNC_ID)
#undef CTFontCopyFontDescriptor
// extra usings

INTERPOSE(CTFontCopyFontDescriptor)(CTFontRef arg0)
{
    #define RUN_FUNC  CTFontDescriptorRef ret = real::CTFontCopyFontDescriptor(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontGetCapHeight"
#pragma push_macro(FUNC_ID)
#undef CTFontGetCapHeight
// extra usings

INTERPOSE(CTFontGetCapHeight)(CTFontRef arg0)
{
    #define RUN_FUNC  double ret = real::CTFontGetCapHeight(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontGetUnderlineThickness"
#pragma push_macro(FUNC_ID)
#undef CTFontGetUnderlineThickness
// extra usings

INTERPOSE(CTFontGetUnderlineThickness)(CTFontRef arg0)
{
    #define RUN_FUNC  double ret = real::CTFontGetUnderlineThickness(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontManagerCompareFontFamilyNames"
#pragma push_macro(FUNC_ID)
#undef CTFontManagerCompareFontFamilyNames
// extra usings

INTERPOSE(CTFontManagerCompareFontFamilyNames)(const void * arg0, const void * arg1, void * arg2)
{
    #define RUN_FUNC  __darwin_intptr_t ret = real::CTFontManagerCompareFontFamilyNames(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontCopyFeatureSettings"
#pragma push_macro(FUNC_ID)
#undef CTFontCopyFeatureSettings
// extra usings

INTERPOSE(CTFontCopyFeatureSettings)(CTFontRef arg0)
{
    #define RUN_FUNC  CFArrayRef ret = real::CTFontCopyFeatureSettings(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontCreateCopyWithSymbolicTraits"
#pragma push_macro(FUNC_ID)
#undef CTFontCreateCopyWithSymbolicTraits
// extra usings
using CTFontCreateCopyWithSymbolicTraits_T_arg2 = const CGAffineTransform *;
using CTFontCreateCopyWithSymbolicTraits_T_arg2 = const CGAffineTransform *;
INTERPOSE(CTFontCreateCopyWithSymbolicTraits)(CTFontRef arg0, double arg1, CTFontCreateCopyWithSymbolicTraits_T_arg2 arg2, __uint32_t arg3, __uint32_t arg4)
{
    #define RUN_FUNC  CTFontRef ret = real::CTFontCreateCopyWithSymbolicTraits(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTLineGetGlyphCount"
#pragma push_macro(FUNC_ID)
#undef CTLineGetGlyphCount
// extra usings

INTERPOSE(CTLineGetGlyphCount)(CTLineRef arg0)
{
    #define RUN_FUNC  __darwin_intptr_t ret = real::CTLineGetGlyphCount(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTLineDraw"
#pragma push_macro(FUNC_ID)
#undef CTLineDraw
// extra usings

INTERPOSE(CTLineDraw)(CTLineRef arg0, CGContextRef arg1)
{
    #define RUN_FUNC  real::CTLineDraw(arg0, arg1)

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

#define FUNC_ID "CTFontDescriptorCreateCopyWithFeature"
#pragma push_macro(FUNC_ID)
#undef CTFontDescriptorCreateCopyWithFeature
// extra usings

INTERPOSE(CTFontDescriptorCreateCopyWithFeature)(CTFontDescriptorRef arg0, CFNumberRef arg1, CFNumberRef arg2)
{
    #define RUN_FUNC  CTFontDescriptorRef ret = real::CTFontDescriptorCreateCopyWithFeature(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTRubyAnnotationGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CTRubyAnnotationGetTypeID
// extra usings

INTERPOSE(CTRubyAnnotationGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CTRubyAnnotationGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

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

#define FUNC_ID "CTTypesetterGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CTTypesetterGetTypeID
// extra usings

INTERPOSE(CTTypesetterGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CTTypesetterGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

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

#define FUNC_ID "CTRunGetTextMatrix"
#pragma push_macro(FUNC_ID)
#undef CTRunGetTextMatrix
// extra usings

INTERPOSE(CTRunGetTextMatrix)(CTRunRef arg0)
{
    #define RUN_FUNC  CGAffineTransform ret = real::CTRunGetTextMatrix(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontGetLigatureCaretPositions"
#pragma push_macro(FUNC_ID)
#undef CTFontGetLigatureCaretPositions
// extra usings

INTERPOSE(CTFontGetLigatureCaretPositions)(CTFontRef arg0, __uint16_t arg1, double * arg2, __darwin_intptr_t arg3)
{
    #define RUN_FUNC  __darwin_intptr_t ret = real::CTFontGetLigatureCaretPositions(arg0, arg1, arg2, arg3)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontCollectionCreateMutableCopy"
#pragma push_macro(FUNC_ID)
#undef CTFontCollectionCreateMutableCopy
// extra usings

INTERPOSE(CTFontCollectionCreateMutableCopy)(CTFontCollectionRef arg0)
{
    #define RUN_FUNC  CTMutableFontCollectionRef ret = real::CTFontCollectionCreateMutableCopy(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontDescriptorCreateWithNameAndSize"
#pragma push_macro(FUNC_ID)
#undef CTFontDescriptorCreateWithNameAndSize
// extra usings

INTERPOSE(CTFontDescriptorCreateWithNameAndSize)(CFStringRef arg0, double arg1)
{
    #define RUN_FUNC  CTFontDescriptorRef ret = real::CTFontDescriptorCreateWithNameAndSize(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTLineGetStringRange"
#pragma push_macro(FUNC_ID)
#undef CTLineGetStringRange
// extra usings

INTERPOSE(CTLineGetStringRange)(CTLineRef arg0)
{
    #define RUN_FUNC  CFRange ret = real::CTLineGetStringRange(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontManagerCopyAvailablePostScriptNames"
#pragma push_macro(FUNC_ID)
#undef CTFontManagerCopyAvailablePostScriptNames
// extra usings

INTERPOSE(CTFontManagerCopyAvailablePostScriptNames)()
{
    #define RUN_FUNC  CFArrayRef ret = real::CTFontManagerCopyAvailablePostScriptNames()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

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

#define FUNC_ID "CTRunDelegateGetRefCon"
#pragma push_macro(FUNC_ID)
#undef CTRunDelegateGetRefCon
// extra usings

INTERPOSE(CTRunDelegateGetRefCon)(CTRunDelegateRef arg0)
{
    #define RUN_FUNC  void * ret = real::CTRunDelegateGetRefCon(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTLineCreateJustifiedLine"
#pragma push_macro(FUNC_ID)
#undef CTLineCreateJustifiedLine
// extra usings

INTERPOSE(CTLineCreateJustifiedLine)(CTLineRef arg0, double arg1, double arg2)
{
    #define RUN_FUNC  CTLineRef ret = real::CTLineCreateJustifiedLine(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFrameGetLines"
#pragma push_macro(FUNC_ID)
#undef CTFrameGetLines
// extra usings

INTERPOSE(CTFrameGetLines)(CTFrameRef arg0)
{
    #define RUN_FUNC  CFArrayRef ret = real::CTFrameGetLines(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontCollectionCreateCopyWithFontDescriptors"
#pragma push_macro(FUNC_ID)
#undef CTFontCollectionCreateCopyWithFontDescriptors
// extra usings

INTERPOSE(CTFontCollectionCreateCopyWithFontDescriptors)(CTFontCollectionRef arg0, CFArrayRef arg1, CFDictionaryRef arg2)
{
    #define RUN_FUNC  CTFontCollectionRef ret = real::CTFontCollectionCreateCopyWithFontDescriptors(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTRunGetGlyphCount"
#pragma push_macro(FUNC_ID)
#undef CTRunGetGlyphCount
// extra usings

INTERPOSE(CTRunGetGlyphCount)(CTRunRef arg0)
{
    #define RUN_FUNC  __darwin_intptr_t ret = real::CTRunGetGlyphCount(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontDescriptorCreateMatchingFontDescriptors"
#pragma push_macro(FUNC_ID)
#undef CTFontDescriptorCreateMatchingFontDescriptors
// extra usings

INTERPOSE(CTFontDescriptorCreateMatchingFontDescriptors)(CTFontDescriptorRef arg0, CFSetRef arg1)
{
    #define RUN_FUNC  CFArrayRef ret = real::CTFontDescriptorCreateMatchingFontDescriptors(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTFontCollectionSetQueryDescriptors"
#pragma push_macro(FUNC_ID)
#undef CTFontCollectionSetQueryDescriptors
// extra usings

INTERPOSE(CTFontCollectionSetQueryDescriptors)(CTMutableFontCollectionRef arg0, CFArrayRef arg1)
{
    #define RUN_FUNC  real::CTFontCollectionSetQueryDescriptors(arg0, arg1)

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

#define FUNC_ID "CTFontDescriptorCopyLocalizedAttribute"
#pragma push_macro(FUNC_ID)
#undef CTFontDescriptorCopyLocalizedAttribute
// extra usings
using CTFontDescriptorCopyLocalizedAttribute_T_arg2 = const __CFString **;
using CTFontDescriptorCopyLocalizedAttribute_T_arg2 = const __CFString **;
INTERPOSE(CTFontDescriptorCopyLocalizedAttribute)(CTFontDescriptorRef arg0, CFStringRef arg1, CTFontDescriptorCopyLocalizedAttribute_T_arg2 arg2)
{
    #define RUN_FUNC  const void * ret = real::CTFontDescriptorCopyLocalizedAttribute(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFrameGetStringRange"
#pragma push_macro(FUNC_ID)
#undef CTFrameGetStringRange
// extra usings

INTERPOSE(CTFrameGetStringRange)(CTFrameRef arg0)
{
    #define RUN_FUNC  CFRange ret = real::CTFrameGetStringRange(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFrameGetLineOrigins"
#pragma push_macro(FUNC_ID)
#undef CTFrameGetLineOrigins
// extra usings

INTERPOSE(CTFrameGetLineOrigins)(CTFrameRef arg0, CFRange arg1, CGPoint * arg2)
{
    #define RUN_FUNC  real::CTFrameGetLineOrigins(arg0, arg1, arg2)

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

#define FUNC_ID "CTFontCreateWithName"
#pragma push_macro(FUNC_ID)
#undef CTFontCreateWithName
// extra usings
using CTFontCreateWithName_T_arg2 = const CGAffineTransform *;
using CTFontCreateWithName_T_arg2 = const CGAffineTransform *;
INTERPOSE(CTFontCreateWithName)(CFStringRef arg0, double arg1, CTFontCreateWithName_T_arg2 arg2)
{
    #define RUN_FUNC  CTFontRef ret = real::CTFontCreateWithName(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFramesetterGetTypesetter"
#pragma push_macro(FUNC_ID)
#undef CTFramesetterGetTypesetter
// extra usings

INTERPOSE(CTFramesetterGetTypesetter)(CTFramesetterRef arg0)
{
    #define RUN_FUNC  CTTypesetterRef ret = real::CTFramesetterGetTypesetter(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTGlyphInfoCreateWithGlyphName"
#pragma push_macro(FUNC_ID)
#undef CTGlyphInfoCreateWithGlyphName
// extra usings

INTERPOSE(CTGlyphInfoCreateWithGlyphName)(CFStringRef arg0, CTFontRef arg1, CFStringRef arg2)
{
    #define RUN_FUNC  CTGlyphInfoRef ret = real::CTGlyphInfoCreateWithGlyphName(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontDescriptorCreateCopyWithSymbolicTraits"
#pragma push_macro(FUNC_ID)
#undef CTFontDescriptorCreateCopyWithSymbolicTraits
// extra usings

INTERPOSE(CTFontDescriptorCreateCopyWithSymbolicTraits)(CTFontDescriptorRef arg0, __uint32_t arg1, __uint32_t arg2)
{
    #define RUN_FUNC  CTFontDescriptorRef ret = real::CTFontDescriptorCreateCopyWithSymbolicTraits(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTLineGetBoundsWithOptions"
#pragma push_macro(FUNC_ID)
#undef CTLineGetBoundsWithOptions
// extra usings

INTERPOSE(CTLineGetBoundsWithOptions)(CTLineRef arg0, __darwin_size_t arg1)
{
    #define RUN_FUNC  CGRect ret = real::CTLineGetBoundsWithOptions(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTFontCopyGraphicsFont"
#pragma push_macro(FUNC_ID)
#undef CTFontCopyGraphicsFont
// extra usings
using CTFontCopyGraphicsFont_T_arg1 = const __CTFontDescriptor **;
using CTFontCopyGraphicsFont_T_arg1 = const __CTFontDescriptor **;
INTERPOSE(CTFontCopyGraphicsFont)(CTFontRef arg0, CTFontCopyGraphicsFont_T_arg1 arg1)
{
    #define RUN_FUNC  CGFontRef ret = real::CTFontCopyGraphicsFont(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTFontCollectionCreateMatchingFontDescriptorsForFamily"
#pragma push_macro(FUNC_ID)
#undef CTFontCollectionCreateMatchingFontDescriptorsForFamily
// extra usings

INTERPOSE(CTFontCollectionCreateMatchingFontDescriptorsForFamily)(CTFontCollectionRef arg0, CFStringRef arg1, CFDictionaryRef arg2)
{
    #define RUN_FUNC  CFArrayRef ret = real::CTFontCollectionCreateMatchingFontDescriptorsForFamily(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontGetXHeight"
#pragma push_macro(FUNC_ID)
#undef CTFontGetXHeight
// extra usings

INTERPOSE(CTFontGetXHeight)(CTFontRef arg0)
{
    #define RUN_FUNC  double ret = real::CTFontGetXHeight(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTRunGetPositions"
#pragma push_macro(FUNC_ID)
#undef CTRunGetPositions
// extra usings

INTERPOSE(CTRunGetPositions)(CTRunRef arg0, CFRange arg1, CGPoint * arg2)
{
    #define RUN_FUNC  real::CTRunGetPositions(arg0, arg1, arg2)

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

#define FUNC_ID "CTFontDescriptorCreateCopyWithVariation"
#pragma push_macro(FUNC_ID)
#undef CTFontDescriptorCreateCopyWithVariation
// extra usings

INTERPOSE(CTFontDescriptorCreateCopyWithVariation)(CTFontDescriptorRef arg0, CFNumberRef arg1, double arg2)
{
    #define RUN_FUNC  CTFontDescriptorRef ret = real::CTFontDescriptorCreateCopyWithVariation(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontDescriptorCreateWithAttributes"
#pragma push_macro(FUNC_ID)
#undef CTFontDescriptorCreateWithAttributes
// extra usings

INTERPOSE(CTFontDescriptorCreateWithAttributes)(CFDictionaryRef arg0)
{
    #define RUN_FUNC  CTFontDescriptorRef ret = real::CTFontDescriptorCreateWithAttributes(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontDescriptorGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CTFontDescriptorGetTypeID
// extra usings

INTERPOSE(CTFontDescriptorGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CTFontDescriptorGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

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

#define FUNC_ID "CTFontCreateUIFontForLanguage"
#pragma push_macro(FUNC_ID)
#undef CTFontCreateUIFontForLanguage
// extra usings

INTERPOSE(CTFontCreateUIFontForLanguage)(__uint32_t arg0, double arg1, CFStringRef arg2)
{
    #define RUN_FUNC  CTFontRef ret = real::CTFontCreateUIFontForLanguage(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTTextTabGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CTTextTabGetTypeID
// extra usings

INTERPOSE(CTTextTabGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CTTextTabGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

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

#define FUNC_ID "CTFontManagerUnregisterFontsForURLs"
#pragma push_macro(FUNC_ID)
#undef CTFontManagerUnregisterFontsForURLs
// extra usings
using CTFontManagerUnregisterFontsForURLs_T_arg2 = const __CFArray **;
using CTFontManagerUnregisterFontsForURLs_T_arg2 = const __CFArray **;
INTERPOSE(CTFontManagerUnregisterFontsForURLs)(CFArrayRef arg0, __uint32_t arg1, CTFontManagerUnregisterFontsForURLs_T_arg2 arg2)
{
    #define RUN_FUNC  bool ret = real::CTFontManagerUnregisterFontsForURLs(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontDescriptorCreateMatchingFontDescriptor"
#pragma push_macro(FUNC_ID)
#undef CTFontDescriptorCreateMatchingFontDescriptor
// extra usings

INTERPOSE(CTFontDescriptorCreateMatchingFontDescriptor)(CTFontDescriptorRef arg0, CFSetRef arg1)
{
    #define RUN_FUNC  CTFontDescriptorRef ret = real::CTFontDescriptorCreateMatchingFontDescriptor(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTFontCopyTraits"
#pragma push_macro(FUNC_ID)
#undef CTFontCopyTraits
// extra usings

INTERPOSE(CTFontCopyTraits)(CTFontRef arg0)
{
    #define RUN_FUNC  CFDictionaryRef ret = real::CTFontCopyTraits(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTRunGetStringIndicesPtr"
#pragma push_macro(FUNC_ID)
#undef CTRunGetStringIndicesPtr
// extra usings

INTERPOSE(CTRunGetStringIndicesPtr)(CTRunRef arg0)
{
    #define RUN_FUNC  const long * ret = real::CTRunGetStringIndicesPtr(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTLineGetStringIndexForPosition"
#pragma push_macro(FUNC_ID)
#undef CTLineGetStringIndexForPosition
// extra usings

INTERPOSE(CTLineGetStringIndexForPosition)(CTLineRef arg0, CGPoint arg1)
{
    #define RUN_FUNC  __darwin_intptr_t ret = real::CTLineGetStringIndexForPosition(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTFontDescriptorCopyAttributes"
#pragma push_macro(FUNC_ID)
#undef CTFontDescriptorCopyAttributes
// extra usings

INTERPOSE(CTFontDescriptorCopyAttributes)(CTFontDescriptorRef arg0)
{
    #define RUN_FUNC  CFDictionaryRef ret = real::CTFontDescriptorCopyAttributes(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontGetLeading"
#pragma push_macro(FUNC_ID)
#undef CTFontGetLeading
// extra usings

INTERPOSE(CTFontGetLeading)(CTFontRef arg0)
{
    #define RUN_FUNC  double ret = real::CTFontGetLeading(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTRunGetGlyphs"
#pragma push_macro(FUNC_ID)
#undef CTRunGetGlyphs
// extra usings
using CTRunGetGlyphs_T_arg2 = unsigned short *;
using CTRunGetGlyphs_T_arg2 = unsigned short *;
INTERPOSE(CTRunGetGlyphs)(CTRunRef arg0, CFRange arg1, CTRunGetGlyphs_T_arg2 arg2)
{
    #define RUN_FUNC  real::CTRunGetGlyphs(arg0, arg1, arg2)

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

#define FUNC_ID "CTFontCollectionCreateWithFontDescriptors"
#pragma push_macro(FUNC_ID)
#undef CTFontCollectionCreateWithFontDescriptors
// extra usings

INTERPOSE(CTFontCollectionCreateWithFontDescriptors)(CFArrayRef arg0, CFDictionaryRef arg1)
{
    #define RUN_FUNC  CTFontCollectionRef ret = real::CTFontCollectionCreateWithFontDescriptors(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTRunDelegateCreate"
#pragma push_macro(FUNC_ID)
#undef CTRunDelegateCreate
// extra usings

INTERPOSE(CTRunDelegateCreate)(const CTRunDelegateCallbacks * arg0, void * arg1)
{
    #define RUN_FUNC  CTRunDelegateRef ret = real::CTRunDelegateCreate(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTTypesetterCreateLineWithOffset"
#pragma push_macro(FUNC_ID)
#undef CTTypesetterCreateLineWithOffset
// extra usings

INTERPOSE(CTTypesetterCreateLineWithOffset)(CTTypesetterRef arg0, CFRange arg1, double arg2)
{
    #define RUN_FUNC  CTLineRef ret = real::CTTypesetterCreateLineWithOffset(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontGetUnderlinePosition"
#pragma push_macro(FUNC_ID)
#undef CTFontGetUnderlinePosition
// extra usings

INTERPOSE(CTFontGetUnderlinePosition)(CTFontRef arg0)
{
    #define RUN_FUNC  double ret = real::CTFontGetUnderlinePosition(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTRunGetTypographicBounds"
#pragma push_macro(FUNC_ID)
#undef CTRunGetTypographicBounds
// extra usings

INTERPOSE(CTRunGetTypographicBounds)(CTRunRef arg0, CFRange arg1, double * arg2, double * arg3, double * arg4)
{
    #define RUN_FUNC  double ret = real::CTRunGetTypographicBounds(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTTypesetterCreateWithAttributedString"
#pragma push_macro(FUNC_ID)
#undef CTTypesetterCreateWithAttributedString
// extra usings

INTERPOSE(CTTypesetterCreateWithAttributedString)(CFAttributedStringRef arg0)
{
    #define RUN_FUNC  CTTypesetterRef ret = real::CTTypesetterCreateWithAttributedString(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTLineCreateWithAttributedString"
#pragma push_macro(FUNC_ID)
#undef CTLineCreateWithAttributedString
// extra usings

INTERPOSE(CTLineCreateWithAttributedString)(CFAttributedStringRef arg0)
{
    #define RUN_FUNC  CTLineRef ret = real::CTLineCreateWithAttributedString(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTTextTabGetAlignment"
#pragma push_macro(FUNC_ID)
#undef CTTextTabGetAlignment
// extra usings

INTERPOSE(CTTextTabGetAlignment)(CTTextTabRef arg0)
{
    #define RUN_FUNC  __uint8_t ret = real::CTTextTabGetAlignment(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontCopyName"
#pragma push_macro(FUNC_ID)
#undef CTFontCopyName
// extra usings

INTERPOSE(CTFontCopyName)(CTFontRef arg0, CFStringRef arg1)
{
    #define RUN_FUNC  CFStringRef ret = real::CTFontCopyName(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTFontGetSlantAngle"
#pragma push_macro(FUNC_ID)
#undef CTFontGetSlantAngle
// extra usings

INTERPOSE(CTFontGetSlantAngle)(CTFontRef arg0)
{
    #define RUN_FUNC  double ret = real::CTFontGetSlantAngle(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFramesetterSuggestFrameSizeWithConstraints"
#pragma push_macro(FUNC_ID)
#undef CTFramesetterSuggestFrameSizeWithConstraints
// extra usings

INTERPOSE(CTFramesetterSuggestFrameSizeWithConstraints)(CTFramesetterRef arg0, CFRange arg1, CFDictionaryRef arg2, CGSize arg3, CFRange * arg4)
{
    #define RUN_FUNC  CGSize ret = real::CTFramesetterSuggestFrameSizeWithConstraints(arg0, arg1, arg2, arg3, arg4)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontCollectionCopyFontAttributes"
#pragma push_macro(FUNC_ID)
#undef CTFontCollectionCopyFontAttributes
// extra usings

INTERPOSE(CTFontCollectionCopyFontAttributes)(CTFontCollectionRef arg0, CFSetRef arg1, __uint32_t arg2)
{
    #define RUN_FUNC  CFArrayRef ret = real::CTFontCollectionCopyFontAttributes(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTFontManagerRegisterFontsForURLs"
#pragma push_macro(FUNC_ID)
#undef CTFontManagerRegisterFontsForURLs
// extra usings
using CTFontManagerRegisterFontsForURLs_T_arg2 = const __CFArray **;
using CTFontManagerRegisterFontsForURLs_T_arg2 = const __CFArray **;
INTERPOSE(CTFontManagerRegisterFontsForURLs)(CFArrayRef arg0, __uint32_t arg1, CTFontManagerRegisterFontsForURLs_T_arg2 arg2)
{
    #define RUN_FUNC  bool ret = real::CTFontManagerRegisterFontsForURLs(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTRubyAnnotationGetOverhang"
#pragma push_macro(FUNC_ID)
#undef CTRubyAnnotationGetOverhang
// extra usings

INTERPOSE(CTRubyAnnotationGetOverhang)(CTRubyAnnotationRef arg0)
{
    #define RUN_FUNC  __uint8_t ret = real::CTRubyAnnotationGetOverhang(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontCopyFeatures"
#pragma push_macro(FUNC_ID)
#undef CTFontCopyFeatures
// extra usings

INTERPOSE(CTFontCopyFeatures)(CTFontRef arg0)
{
    #define RUN_FUNC  CFArrayRef ret = real::CTFontCopyFeatures(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontCreateForString"
#pragma push_macro(FUNC_ID)
#undef CTFontCreateForString
// extra usings

INTERPOSE(CTFontCreateForString)(CTFontRef arg0, CFStringRef arg1, CFRange arg2)
{
    #define RUN_FUNC  CTFontRef ret = real::CTFontCreateForString(arg0, arg1, arg2)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
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

#define FUNC_ID "CTGlyphInfoGetGlyphName"
#pragma push_macro(FUNC_ID)
#undef CTGlyphInfoGetGlyphName
// extra usings

INTERPOSE(CTGlyphInfoGetGlyphName)(CTGlyphInfoRef arg0)
{
    #define RUN_FUNC  CFStringRef ret = real::CTGlyphInfoGetGlyphName(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTParagraphStyleGetTypeID"
#pragma push_macro(FUNC_ID)
#undef CTParagraphStyleGetTypeID
// extra usings

INTERPOSE(CTParagraphStyleGetTypeID)()
{
    #define RUN_FUNC  __darwin_size_t ret = real::CTParagraphStyleGetTypeID()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

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

#define FUNC_ID "CTFontCollectionCreateMatchingFontDescriptors"
#pragma push_macro(FUNC_ID)
#undef CTFontCollectionCreateMatchingFontDescriptors
// extra usings

INTERPOSE(CTFontCollectionCreateMatchingFontDescriptors)(CTFontCollectionRef arg0)
{
    #define RUN_FUNC  CFArrayRef ret = real::CTFontCollectionCreateMatchingFontDescriptors(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontManagerCopyAvailableFontFamilyNames"
#pragma push_macro(FUNC_ID)
#undef CTFontManagerCopyAvailableFontFamilyNames
// extra usings

INTERPOSE(CTFontManagerCopyAvailableFontFamilyNames)()
{
    #define RUN_FUNC  CFArrayRef ret = real::CTFontManagerCopyAvailableFontFamilyNames()

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

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

#define FUNC_ID "CTFrameGetVisibleStringRange"
#pragma push_macro(FUNC_ID)
#undef CTFrameGetVisibleStringRange
// extra usings

INTERPOSE(CTFrameGetVisibleStringRange)(CTFrameRef arg0)
{
    #define RUN_FUNC  CFRange ret = real::CTFrameGetVisibleStringRange(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

/////////////////////

#define FUNC_ID "CTFontCopyNameForGlyph"
#pragma push_macro(FUNC_ID)
#undef CTFontCopyNameForGlyph
// extra usings

INTERPOSE(CTFontCopyNameForGlyph)(CTFontRef arg0, __uint16_t arg1)
{
    #define RUN_FUNC  CFStringRef ret = real::CTFontCopyNameForGlyph(arg0, arg1)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

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

#define FUNC_ID "CTRunGetPositionsPtr"
#pragma push_macro(FUNC_ID)
#undef CTRunGetPositionsPtr
// extra usings
using CTRunGetPositionsPtr_T_ret = const CGPoint *;
using CTRunGetPositionsPtr_T_ret = const CGPoint *;
INTERPOSE(CTRunGetPositionsPtr)(CTRunRef arg0)
{
    #define RUN_FUNC  CTRunGetPositionsPtr_T_ret ret = real::CTRunGetPositionsPtr(arg0)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, true, arg0);
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            DUMP_ARG(&funcArgs, FUNC_ID, false, arg0);
            DUMP_ARG(&funcArgs, FUNC_ID, false, ret);
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID

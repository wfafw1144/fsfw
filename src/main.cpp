// MemCLI — universal Windows process memory tool
// Commands: attach, read, write, scan, modules, help
// Build: cl main.cpp /EHsc /O2 /Fe:memcli.exe

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cstdint>
#pragma comment(lib, "psapi.lib")

// ── state ─────────────────────────────────────────────────────────────────
static HANDLE g_proc   = nullptr;
static DWORD  g_pid    = 0;
static std::string g_procName;

// ── helpers ───────────────────────────────────────────────────────────────
static void setColor(WORD attr) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), attr);
}
static void ok (const std::string& s) { setColor(0x0A); std::cout << "[+] " << s << "\n"; setColor(0x07); }
static void err(const std::string& s) { setColor(0x0C); std::cout << "[-] " << s << "\n"; setColor(0x07); }
static void inf(const std::string& s) { setColor(0x0B); std::cout << "[*] " << s << "\n"; setColor(0x07); }

static std::string hexStr(uintptr_t v) {
    std::ostringstream ss;
    ss << "0x" << std::uppercase << std::hex << v;
    return ss.str();
}

static bool parseAddr(const std::string& s, uintptr_t& out) {
    try {
        out = (uintptr_t)std::stoull(s, nullptr, 0);
        return true;
    } catch (...) { return false; }
}

static std::vector<std::string> split(const std::string& line) {
    std::istringstream ss(line);
    std::string tok;
    std::vector<std::string> v;
    while (ss >> tok) v.push_back(tok);
    return v;
}

// ── process ───────────────────────────────────────────────────────────────
static DWORD findPid(const std::string& name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe{ sizeof(pe) };
    DWORD pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name.c_str()) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static void cmdAttach(const std::vector<std::string>& args) {
    if (args.size() < 2) { err("usage: attach <process.exe | PID>"); return; }
    if (g_proc) { CloseHandle(g_proc); g_proc = nullptr; g_pid = 0; }

    DWORD pid = 0;
    try { pid = (DWORD)std::stoul(args[1]); }
    catch (...) { pid = findPid(args[1]); }

    if (!pid) { err("process not found: " + args[1]); return; }

    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
                          | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) { err("OpenProcess failed: " + std::to_string(GetLastError())); return; }

    g_proc = h; g_pid = pid;
    char name[MAX_PATH]{};
    GetProcessImageFileNameA(h, name, MAX_PATH);
    g_procName = strrchr(name, '\\') ? strrchr(name, '\\') + 1 : name;
    ok("attached to " + g_procName + " (PID " + std::to_string(pid) + ")");
}

// ── read ──────────────────────────────────────────────────────────────────
// read <addr> <type>  — types: i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 ptr str bytes:<n>
static void cmdRead(const std::vector<std::string>& args) {
    if (!g_proc) { err("not attached"); return; }
    if (args.size() < 3) { err("usage: read <addr> <type>"); return; }

    uintptr_t addr = 0;
    if (!parseAddr(args[1], addr)) { err("bad address"); return; }

    std::string type = args[2];

    auto doRead = [&](void* buf, size_t sz) -> bool {
        SIZE_T rd = 0;
        return ReadProcessMemory(g_proc, (LPCVOID)addr, buf, sz, &rd) && rd == sz;
    };

    if (type == "i8")  { int8_t  v{}; if (doRead(&v,1))  ok(hexStr(addr)+" = "+std::to_string(v)); else err("read failed"); }
    else if (type=="i16"){ int16_t v{}; if (doRead(&v,2)) ok(hexStr(addr)+" = "+std::to_string(v)); else err("read failed"); }
    else if (type=="i32"){ int32_t v{}; if (doRead(&v,4)) ok(hexStr(addr)+" = "+std::to_string(v)); else err("read failed"); }
    else if (type=="i64"){ int64_t v{}; if (doRead(&v,8)) ok(hexStr(addr)+" = "+std::to_string(v)); else err("read failed"); }
    else if (type=="u8") { uint8_t  v{}; if (doRead(&v,1)) ok(hexStr(addr)+" = "+std::to_string(v)); else err("read failed"); }
    else if (type=="u16"){ uint16_t v{}; if (doRead(&v,2)) ok(hexStr(addr)+" = "+std::to_string(v)); else err("read failed"); }
    else if (type=="u32"){ uint32_t v{}; if (doRead(&v,4)) ok(hexStr(addr)+" = "+std::to_string(v)); else err("read failed"); }
    else if (type=="u64"){ uint64_t v{}; if (doRead(&v,8)) ok(hexStr(addr)+" = "+std::to_string(v)); else err("read failed"); }
    else if (type=="f32"){ float    v{}; if (doRead(&v,4)) ok(hexStr(addr)+" = "+std::to_string(v)); else err("read failed"); }
    else if (type=="f64"){ double   v{}; if (doRead(&v,8)) ok(hexStr(addr)+" = "+std::to_string(v)); else err("read failed"); }
    else if (type=="ptr"){ uintptr_t v{}; if (doRead(&v,sizeof(v))) ok(hexStr(addr)+" -> "+hexStr(v)); else err("read failed"); }
    else if (type=="str"){
        char buf[512]{}; SIZE_T rd=0;
        ReadProcessMemory(g_proc,(LPCVOID)addr,buf,511,&rd);
        ok(hexStr(addr)+" = \""+std::string(buf)+"\"");
    }
    else if (type.rfind("bytes:",0)==0){
        size_t n = std::stoul(type.substr(6));
        n = std::min(n,(size_t)256);
        std::vector<uint8_t> buf(n);
        SIZE_T rd=0;
        ReadProcessMemory(g_proc,(LPCVOID)addr,buf.data(),n,&rd);
        std::cout << hexStr(addr) << ":";
        for (size_t i=0;i<rd;i++) {
            if(i%16==0) std::cout<<"\n  "<<hexStr(addr+i)<<"  ";
            std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)buf[i]<<" ";
        }
        std::cout<<"\n"; setColor(0x07);
    }
    else err("unknown type: " + type);
}

// ── write ─────────────────────────────────────────────────────────────────
// write <addr> <type> <value>
static void cmdWrite(const std::vector<std::string>& args) {
    if (!g_proc) { err("not attached"); return; }
    if (args.size() < 4) { err("usage: write <addr> <type> <value>"); return; }

    uintptr_t addr = 0;
    if (!parseAddr(args[1], addr)) { err("bad address"); return; }

    std::string type = args[2];
    std::string val  = args[3];

    DWORD old = 0;
    VirtualProtectEx(g_proc, (LPVOID)addr, 8, PAGE_EXECUTE_READWRITE, &old);

    auto doWrite = [&](const void* buf, size_t sz) -> bool {
        SIZE_T wr = 0;
        bool r = WriteProcessMemory(g_proc, (LPVOID)addr, buf, sz, &wr) && wr == sz;
        VirtualProtectEx(g_proc, (LPVOID)addr, sz, old, &old);
        return r;
    };

    bool res = false;
    if      (type=="i8")  { int8_t   v=(int8_t)std::stoi(val);   res=doWrite(&v,1); }
    else if (type=="i16") { int16_t  v=(int16_t)std::stoi(val);  res=doWrite(&v,2); }
    else if (type=="i32") { int32_t  v=std::stoi(val);            res=doWrite(&v,4); }
    else if (type=="i64") { int64_t  v=std::stoll(val);           res=doWrite(&v,8); }
    else if (type=="u32") { uint32_t v=(uint32_t)std::stoul(val); res=doWrite(&v,4); }
    else if (type=="u64") { uint64_t v=std::stoull(val);          res=doWrite(&v,8); }
    else if (type=="f32") { float    v=std::stof(val);             res=doWrite(&v,4); }
    else if (type=="f64") { double   v=std::stod(val);             res=doWrite(&v,8); }
    else { err("unsupported write type: " + type); return; }

    if (res) ok("wrote " + val + " -> " + hexStr(addr));
    else     err("write failed: " + std::to_string(GetLastError()));
}

// ── scan (AOB) ────────────────────────────────────────────────────────────
// scan "48 8B 05 ? ? ? ?" [--first]
static std::vector<uint8_t> parsePattern(const std::string& pat, std::vector<bool>& mask) {
    std::istringstream ss(pat);
    std::string tok;
    std::vector<uint8_t> bytes;
    while (ss >> tok) {
        if (tok == "?" || tok == "??") { bytes.push_back(0); mask.push_back(false); }
        else { bytes.push_back((uint8_t)std::stoul(tok,nullptr,16)); mask.push_back(true); }
    }
    return bytes;
}

static void cmdScan(const std::vector<std::string>& args) {
    if (!g_proc) { err("not attached"); return; }
    if (args.size() < 2) { err("usage: scan \"AA BB ? DD\" [--first]"); return; }

    bool firstOnly = false;
    std::string pat = args[1];
    for (size_t i=2;i<args.size();i++) if (args[i]=="--first") firstOnly=true;

    std::vector<bool> mask;
    auto bytes = parsePattern(pat, mask);
    if (bytes.empty()) { err("empty pattern"); return; }

    inf("scanning " + g_procName + " for pattern [" + pat + "] ...");

    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t end  = (uintptr_t)si.lpMaximumApplicationAddress;

    std::vector<uintptr_t> results;
    const size_t CHUNK = 0x10000;
    std::vector<uint8_t> buf(CHUNK + bytes.size());

    while (addr < end && (!firstOnly || results.empty())) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQueryEx(g_proc,(LPCVOID)addr,&mbi,sizeof(mbi))) { addr += 0x1000; continue; }
        if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS|PAGE_GUARD))) {
            addr += mbi.RegionSize; continue;
        }

        size_t regionSz = mbi.RegionSize;
        uintptr_t rBase = (uintptr_t)mbi.BaseAddress;

        for (size_t off=0; off < regionSz; off += CHUNK) {
            size_t toRead = std::min(CHUNK, regionSz - off);
            SIZE_T rd=0;
            if (!ReadProcessMemory(g_proc,(LPCVOID)(rBase+off),buf.data(),toRead,&rd)) continue;
            for (size_t i=0; i+bytes.size() <= rd; i++) {
                bool match = true;
                for (size_t j=0;j<bytes.size();j++)
                    if (mask[j] && buf[i+j]!=bytes[j]) { match=false; break; }
                if (match) {
                    results.push_back(rBase+off+i);
                    if (firstOnly) break;
                    if (results.size() >= 128) { inf("truncated at 128 results"); goto done; }
                }
            }
        }
        addr += mbi.RegionSize;
    }
done:
    if (results.empty()) { err("pattern not found"); return; }
    ok("found " + std::to_string(results.size()) + " match(es):");
    for (auto a : results) std::cout << "  " << hexStr(a) << "\n";
}

// ── modules ───────────────────────────────────────────────────────────────
static void cmdModules(const std::vector<std::string>&) {
    if (!g_proc) { err("not attached"); return; }
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32, g_pid);
    if (snap==INVALID_HANDLE_VALUE) { err("snapshot failed"); return; }
    MODULEENTRY32 me{ sizeof(me) };
    std::cout << std::left << std::setw(40) << "Module"
              << std::setw(18) << "Base"
              << "Size\n";
    std::cout << std::string(70,'-') << "\n";
    if (Module32First(snap,&me)) do {
        std::cout << std::left << std::setw(40) << me.szModule
                  << std::setw(18) << hexStr((uintptr_t)me.modBaseAddr)
                  << hexStr(me.modBaseSize) << "\n";
    } while (Module32Next(snap,&me));
    CloseHandle(snap);
}

// ── help ──────────────────────────────────────────────────────────────────
static void cmdHelp() {
    setColor(0x0E);
    std::cout << R"(
  MemCLI commands:
  ─────────────────────────────────────────────────────────────
  attach <name.exe | PID>          attach to process
  detach                           release handle
  read   <addr> <type>             read memory
  write  <addr> <type> <value>     write memory
  scan   "<AA BB ? CC>" [--first]  AOB pattern scan
  modules                          list loaded modules
  help                             this message
  exit / quit                      exit

  types: i8 i16 i32 i64  u8 u16 u32 u64  f32 f64  ptr  str  bytes:<n>
  addr:  hex (0x...) or decimal
)";
    setColor(0x07);
}

// ── REPL ──────────────────────────────────────────────────────────────────
int main() {
    SetConsoleTitleA("MemCLI");
    setColor(0x0E);
    std::cout << "  MemCLI — universal process memory tool\n";
    setColor(0x08);
    std::cout << "  type 'help' for commands\n\n";
    setColor(0x07);

    std::string line;
    while (true) {
        setColor(0x0B);
        if (g_proc) std::cout << "[" << g_procName << "] ";
        else        std::cout << "[no proc] ";
        setColor(0x07);
        std::cout << "> ";

        if (!std::getline(std::cin, line)) break;

        auto args = split(line);
        if (args.empty()) continue;
        std::string cmd = args[0];
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);

        if      (cmd=="attach")  cmdAttach(args);
        else if (cmd=="detach")  { if (g_proc) CloseHandle(g_proc); g_proc=nullptr; g_pid=0; g_procName.clear(); ok("detached"); }
        else if (cmd=="read")    cmdRead(args);
        else if (cmd=="write")   cmdWrite(args);
        else if (cmd=="scan")    cmdScan(args);
        else if (cmd=="modules") cmdModules(args);
        else if (cmd=="help")    cmdHelp();
        else if (cmd=="exit"||cmd=="quit") break;
        else err("unknown command: " + cmd + " (type 'help')");
    }
    if (g_proc) CloseHandle(g_proc);
    return 0;
}

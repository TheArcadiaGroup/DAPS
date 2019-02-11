// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2018-2019 The DAPScoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/dapscoin-config.h"
#endif

#include "util.h"

#include "allocators.h"
#include "chainparamsbase.h"
#include "random.h"
#include "serialize.h"
#include "sync.h"
#include "utilstrencodings.h"
#include "utiltime.h"

#include <stdarg.h>

#include <boost/date_time/posix_time/posix_time.hpp>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h> // for OPENSSL_cleanse()
#include <openssl/evp.h>


#ifndef WIN32
// for posix_fallocate
#ifdef __linux__

#ifdef _POSIX_C_SOURCE
#undef _POSIX_C_SOURCE
#endif

#define _POSIX_C_SOURCE 200112L

#endif // __linux__

#include <algorithm>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>

#else

#ifdef _MSC_VER
#pragma warning(disable : 4786)
#pragma warning(disable : 4804)
#pragma warning(disable : 4805)
#pragma warning(disable : 4717)
#endif

#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0501

#ifdef _WIN32_IE
#undef _WIN32_IE
#endif
#define _WIN32_IE 0x0501

#define WIN32_LEAN_AND_MEAN 1
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <io.h> /* for _commit */
#include <shlobj.h>
#endif

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/foreach.hpp>
#include <boost/program_options/detail/config_file.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/thread.hpp>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#ifndef WIN32
#include <cpprest/http_client.h>
#include <cpprest/filestream.h>

#else
#include <chilkat-9.5.0/CkJsonObject.h>
#include <chilkat-9.5.0/CkRest.h>
#include <chilkat-9.5.0/CkStringBuilder.h>
#include <chilkat-9.5.0/CkGlobal.h>
#endif
 
#include <stdio.h>

#if defined(WIN32) || defined(UNDER_CE)
#   include <windows.h>
#   if defined(UNDER_CE)
#       include <Iphlpapi.h>
#   endif
#elif defined(__APPLE__)
#   include <CoreFoundation/CoreFoundation.h>
#   include <IOKit/IOKitLib.h>
#   include <IOKit/network/IOEthernetInterface.h>
#   include <IOKit/network/IONetworkInterface.h>
#   include <IOKit/network/IOEthernetController.h>
#elif defined(LINUX) || defined(linux)
#   include <string.h>
#   include <net/if.h>
#   include <sys/ioctl.h>
#   include <sys/socket.h>
#   include <arpa/inet.h>
#endif

// Work around clang compilation problem in Boost 1.46:
// /usr/include/boost/program_options/detail/config_file.hpp:163:17: error: call to function 'to_internal' that is neither visible in the template definition nor found by argument-dependent lookup
// See also: http://stackoverflow.com/questions/10020179/compilation-fail-in-boost-librairies-program-options
//           http://clang.debian.net/status.php?version=3.0&key=CANNOT_FIND_FUNCTION
namespace boost
{
namespace program_options
{
std::string to_internal(const std::string&);
}

} // namespace boost

using namespace std;

// DAPScoin only features
// Masternode
bool fMasterNode = false;
string strMasterNodePrivKey = "";
string strMasterNodeAddr = "";
bool fLiteMode = false;
// SwiftX
bool fEnableSwiftTX = true;
int nSwiftTXDepth = 5;

/**
* @author Wang
* @type zerocoin
*/
// Automatic Zerocoin minting
bool fEnableZeromint = true;
int nZeromintPercentage = 10;
int nPreferredDenom = 0;
const int64_t AUTOMINT_DELAY = (60 * 5); // Wait at least 5 minutes until Automint starts

int nAnonymizeDapscoinAmount = 1000;
int nLiquidityProvider = 0;
/** Spork enforcement enabled time */
int64_t enforceMasternodePaymentsTime = 4085657524;
bool fSucessfullyLoaded = false;
/** All denominations used by obfuscation */
std::vector<int64_t> obfuScationDenominations;
string strBudgetMode = "";

map<string, string> mapArgs;
map<string, vector<string> > mapMultiArgs;
bool fDebug = false;
bool fPrintToConsole = false;
bool fPrintToDebugLog = true;
bool fDaemon = false;
bool fServer = false;
string strMiscWarning;
bool fLogTimestamps = false;
bool fLogIPs = false;
volatile bool fReopenDebugLog = false;

/** Init OpenSSL library multithreading support */
static CCriticalSection** ppmutexOpenSSL;
void locking_callback(int mode, int i, const char* file, int line)
{
    if (mode & CRYPTO_LOCK) {
        ENTER_CRITICAL_SECTION(*ppmutexOpenSSL[i]);
    } else {
        LEAVE_CRITICAL_SECTION(*ppmutexOpenSSL[i]);
    }
}

// Init
class CInit
{
public:
    CInit()
    {
        // Init OpenSSL library multithreading support
        ppmutexOpenSSL = (CCriticalSection**)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(CCriticalSection*));
        for (int i = 0; i < CRYPTO_num_locks(); i++)
            ppmutexOpenSSL[i] = new CCriticalSection();
        CRYPTO_set_locking_callback(locking_callback);

        // OpenSSL can optionally load a config file which lists optional loadable modules and engines.
        // We don't use them so we don't require the config. However some of our libs may call functions
        // which attempt to load the config file, possibly resulting in an exit() or crash if it is missing
        // or corrupt. Explicitly tell OpenSSL not to try to load the file. The result for our libs will be
        // that the config appears to have been loaded and there are no modules/engines available.
        OPENSSL_no_config();

#ifdef WIN32
        // Seed OpenSSL PRNG with current contents of the screen
        RAND_screen();
#endif

        // Seed OpenSSL PRNG with performance counter
        RandAddSeed();
    }
    ~CInit()
    {
        // Securely erase the memory used by the PRNG
        RAND_cleanup();
        // Shutdown OpenSSL library multithreading support
        CRYPTO_set_locking_callback(NULL);
        for (int i = 0; i < CRYPTO_num_locks(); i++)
            delete ppmutexOpenSSL[i];
        OPENSSL_free(ppmutexOpenSSL);
    }
} instance_of_cinit;

/**
 * LogPrintf() has been broken a couple of times now
 * by well-meaning people adding mutexes in the most straightforward way.
 * It breaks because it may be called by global destructors during shutdown.
 * Since the order of destruction of static/global objects is undefined,
 * defining a mutex as a global object doesn't work (the mutex gets
 * destroyed, and then some later destructor calls OutputDebugStringF,
 * maybe indirectly, and you get a core dump at shutdown trying to lock
 * the mutex).
 */

static boost::once_flag debugPrintInitFlag = BOOST_ONCE_INIT;
/**
 * We use boost::call_once() to make sure these are initialized
 * in a thread-safe manner the first time called:
 */
static FILE* fileout = NULL;
static boost::mutex* mutexDebugLog = NULL;

static void DebugPrintInit()
{
    assert(fileout == NULL);
    assert(mutexDebugLog == NULL);

    boost::filesystem::path pathDebug = GetDataDir() / "debug.log";
    fileout = fopen(pathDebug.string().c_str(), "a");
    if (fileout) setbuf(fileout, NULL); // unbuffered

    mutexDebugLog = new boost::mutex();
}

bool LogAcceptCategory(const char* category)
{
    if (category != NULL) {
        if (!fDebug)
            return false;

        // Give each thread quick access to -debug settings.
        // This helps prevent issues debugging global destructors,
        // where mapMultiArgs might be deleted before another
        // global destructor calls LogPrint()
        static boost::thread_specific_ptr<set<string> > ptrCategory;
        if (ptrCategory.get() == NULL) {
            const vector<string>& categories = mapMultiArgs["-debug"];
            ptrCategory.reset(new set<string>(categories.begin(), categories.end()));
            // thread_specific_ptr automatically deletes the set when the thread ends.
            // "dapscoin" is a composite category enabling all DAPScoin-related debug output
            if (ptrCategory->count(string("dapscoin"))) {
                ptrCategory->insert(string("obfuscation"));
                ptrCategory->insert(string("swiftx"));
                ptrCategory->insert(string("masternode"));
                ptrCategory->insert(string("mnpayments"));
                ptrCategory->insert(string("zero"));
                ptrCategory->insert(string("mnbudget"));
            }
        }
        const set<string>& setCategories = *ptrCategory.get();

        // if not debugging everything and not debugging specific category, LogPrint does nothing.
        if (setCategories.count(string("")) == 0 &&
            setCategories.count(string(category)) == 0)
            return false;
    }
    return true;
}

int LogPrintStr(const std::string& str)
{
    int ret = 0; // Returns total number of characters written
    if (fPrintToConsole) {
        // print to console
        ret = fwrite(str.data(), 1, str.size(), stdout);
        fflush(stdout);
    } else if (fPrintToDebugLog && AreBaseParamsConfigured()) {
        static bool fStartedNewLine = true;
        boost::call_once(&DebugPrintInit, debugPrintInitFlag);

        if (fileout == NULL)
            return ret;

        boost::mutex::scoped_lock scoped_lock(*mutexDebugLog);

        // reopen the log file, if requested
        if (fReopenDebugLog) {
            fReopenDebugLog = false;
            boost::filesystem::path pathDebug = GetDataDir() / "debug.log";
            if (freopen(pathDebug.string().c_str(), "a", fileout) != NULL)
                setbuf(fileout, NULL); // unbuffered
        }

        // Debug print useful for profiling
        if (fLogTimestamps && fStartedNewLine)
            ret += fprintf(fileout, "%s ", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTime()).c_str());
        if (!str.empty() && str[str.size() - 1] == '\n')
            fStartedNewLine = true;
        else
            fStartedNewLine = false;

        ret = fwrite(str.data(), 1, str.size(), fileout);
    }

    return ret;
}

/** Interpret string as boolean, for argument parsing */
static bool InterpretBool(const std::string& strValue)
{
    if (strValue.empty())
        return true;
    return (atoi(strValue) != 0);
}

/** Turn -noX into -X=0 */
static void InterpretNegativeSetting(std::string& strKey, std::string& strValue)
{
    if (strKey.length()>3 && strKey[0]=='-' && strKey[1]=='n' && strKey[2]=='o') {
        strKey = "-" + strKey.substr(3);
        strValue = InterpretBool(strValue) ? "0" : "1";
    }
}

void ParseParameters(int argc, const char* const argv[])
{
    mapArgs.clear();
    mapMultiArgs.clear();

    for (int i = 1; i < argc; i++) {
        std::string str(argv[i]);
        std::string strValue;
        size_t is_index = str.find('=');
        if (is_index != std::string::npos) {
            strValue = str.substr(is_index + 1);
            str = str.substr(0, is_index);
        }
#ifdef WIN32
        boost::to_lower(str);
        if (boost::algorithm::starts_with(str, "/"))
            str = "-" + str.substr(1);
#endif

        if (str[0] != '-')
            break;

        // Interpret --foo as -foo.
        // If both --foo and -foo are set, the last takes effect.
        if (str.length() > 1 && str[1] == '-')
            str = str.substr(1);
        InterpretNegativeSetting(str, strValue);

        mapArgs[str] = strValue;
        mapMultiArgs[str].push_back(strValue);
    }
}

std::string GetArg(const std::string& strArg, const std::string& strDefault)
{
    if (mapArgs.count(strArg))
        return mapArgs[strArg];
    return strDefault;
}

int64_t GetArg(const std::string& strArg, int64_t nDefault)
{
    if (mapArgs.count(strArg))
        return atoi64(mapArgs[strArg]);
    return nDefault;
}

bool GetBoolArg(const std::string& strArg, bool fDefault)
{
    if (mapArgs.count(strArg))
        return InterpretBool(mapArgs[strArg]);
    return fDefault;
}

bool SoftSetArg(const std::string& strArg, const std::string& strValue)
{
    if (mapArgs.count(strArg))
        return false;
    mapArgs[strArg] = strValue;
    return true;
}

bool SoftSetBoolArg(const std::string& strArg, bool fValue)
{
    if (fValue)
        return SoftSetArg(strArg, std::string("1"));
    else
        return SoftSetArg(strArg, std::string("0"));
}

static const int screenWidth = 79;
static const int optIndent = 2;
static const int msgIndent = 7;

std::string HelpMessageGroup(const std::string &message) {
    return std::string(message) + std::string("\n\n");
}

std::string HelpMessageOpt(const std::string &option, const std::string &message) {
    return std::string(optIndent,' ') + std::string(option) +
           std::string("\n") + std::string(msgIndent,' ') +
           FormatParagraph(message, screenWidth - msgIndent, msgIndent) +
           std::string("\n\n");
}

static std::string FormatException(std::exception* pex, const char* pszThread)
{
#ifdef WIN32
    char pszModule[MAX_PATH] = "";
    GetModuleFileNameA(NULL, pszModule, sizeof(pszModule));
#else
    const char* pszModule = "dapscoin";
#endif
    if (pex)
        return strprintf(
            "EXCEPTION: %s       \n%s       \n%s in %s       \n", typeid(*pex).name(), pex->what(), pszModule, pszThread);
    else
        return strprintf(
            "UNKNOWN EXCEPTION       \n%s in %s       \n", pszModule, pszThread);
}

void PrintExceptionContinue(std::exception* pex, const char* pszThread)
{
    std::string message = FormatException(pex, pszThread);
    LogPrintf("\n\n************************\n%s\n", message);
    fprintf(stderr, "\n\n************************\n%s\n", message.c_str());
    strMiscWarning = message;
}

boost::filesystem::path GetDefaultDataDir()
{
    namespace fs = boost::filesystem;
// Windows < Vista: C:\Documents and Settings\Username\Application Data\DAPScoin
// Windows >= Vista: C:\Users\Username\AppData\Roaming\DAPScoin
// Mac: ~/Library/Application Support/DAPScoin
// Unix: ~/.dapscoin
#ifdef WIN32
    // Windows
    return GetSpecialFolderPath(CSIDL_APPDATA) / "DAPScoin";
#else
    fs::path pathRet;
    char* pszHome = getenv("HOME");
    if (pszHome == NULL || strlen(pszHome) == 0)
        pathRet = fs::path("/");
    else
        pathRet = fs::path(pszHome);
#ifdef MAC_OSX
    // Mac
    pathRet /= "Library/Application Support";
    TryCreateDirectory(pathRet);
    return pathRet / "DAPScoin";
#else
    // Unix
    return pathRet / ".dapscoin";
#endif
#endif
}

static boost::filesystem::path pathCached;
static boost::filesystem::path pathCachedNetSpecific;
static CCriticalSection csPathCached;

const boost::filesystem::path& GetDataDir(bool fNetSpecific)
{
    namespace fs = boost::filesystem;

    LOCK(csPathCached);

    fs::path& path = fNetSpecific ? pathCachedNetSpecific : pathCached;

    // This can be called during exceptions by LogPrintf(), so we cache the
    // value so we don't have to do memory allocations after that.
    if (!path.empty())
        return path;

    if (mapArgs.count("-datadir")) {
        path = fs::system_complete(mapArgs["-datadir"]);
        if (!fs::is_directory(path)) {
            path = "";
            return path;
        }
    } else {
        path = GetDefaultDataDir();
    }
    if (fNetSpecific)
        path /= BaseParams().DataDir();

    fs::create_directories(path);

    return path;
}

void ClearDatadirCache()
{
    pathCached = boost::filesystem::path();
    pathCachedNetSpecific = boost::filesystem::path();
}

boost::filesystem::path GetConfigFile()
{
    boost::filesystem::path pathConfigFile(GetArg("-conf", "dapscoin.conf"));
    if (!pathConfigFile.is_complete())
        pathConfigFile = GetDataDir(false) / pathConfigFile;

    return pathConfigFile;
}

boost::filesystem::path GetMasternodeConfigFile()
{
    boost::filesystem::path pathConfigFile(GetArg("-mnconf", "masternode.conf"));
    if (!pathConfigFile.is_complete()) pathConfigFile = GetDataDir() / pathConfigFile;
    return pathConfigFile;
}

void ReadConfigFile(map<string, string>& mapSettingsRet,
    map<string, vector<string> >& mapMultiSettingsRet)
{
    boost::filesystem::ifstream streamConfig(GetConfigFile());
    if (!streamConfig.good()) {
        // Create empty dapscoin.conf if it does not exist
        FILE* configFile = fopen(GetConfigFile().string().c_str(), "a");
        if (configFile != NULL)
            fclose(configFile);
        return; // Nothing to read, so just return
    }

    set<string> setOptions;
    setOptions.insert("*");

    for (boost::program_options::detail::config_file_iterator it(streamConfig, setOptions), end; it != end; ++it) {
        // Don't overwrite existing settings so command line settings override dapscoin.conf
        string strKey = string("-") + it->string_key;
        string strValue = it->value[0];
        InterpretNegativeSetting(strKey, strValue);
        if (mapSettingsRet.count(strKey) == 0)
            mapSettingsRet[strKey] = strValue;
        mapMultiSettingsRet[strKey].push_back(strValue);
    }
    // If datadir is changed in .conf file:
    ClearDatadirCache();
}

#ifndef WIN32
boost::filesystem::path GetPidFile()
{
    boost::filesystem::path pathPidFile(GetArg("-pid", "dapscoind.pid"));
    if (!pathPidFile.is_complete()) pathPidFile = GetDataDir() / pathPidFile;
    return pathPidFile;
}

void CreatePidFile(const boost::filesystem::path& path, pid_t pid)
{
    FILE* file = fopen(path.string().c_str(), "w");
    if (file) {
        fprintf(file, "%d\n", pid);
        fclose(file);
    }
}
#endif

bool RenameOver(boost::filesystem::path src, boost::filesystem::path dest)
{
#ifdef WIN32
    return MoveFileExA(src.string().c_str(), dest.string().c_str(),
               MOVEFILE_REPLACE_EXISTING) != 0;
#else
    int rc = std::rename(src.string().c_str(), dest.string().c_str());
    return (rc == 0);
#endif /* WIN32 */
}

/**
 * Ignores exceptions thrown by Boost's create_directory if the requested directory exists.
 * Specifically handles case where path p exists, but it wasn't possible for the user to
 * write to the parent directory.
 */
bool TryCreateDirectory(const boost::filesystem::path& p)
{
    try {
        return boost::filesystem::create_directory(p);
    } catch (boost::filesystem::filesystem_error) {
        if (!boost::filesystem::exists(p) || !boost::filesystem::is_directory(p))
            throw;
    }

    // create_directory didn't create the directory, it had to have existed already
    return false;
}

void FileCommit(FILE* fileout)
{
    fflush(fileout); // harmless if redundantly called
#ifdef WIN32
    HANDLE hFile = (HANDLE)_get_osfhandle(_fileno(fileout));
    FlushFileBuffers(hFile);
#else
#if defined(__linux__) || defined(__NetBSD__)
    fdatasync(fileno(fileout));
#elif defined(__APPLE__) && defined(F_FULLFSYNC)
    fcntl(fileno(fileout), F_FULLFSYNC, 0);
#else
    fsync(fileno(fileout));
#endif
#endif
}

bool TruncateFile(FILE* file, unsigned int length)
{
#if defined(WIN32)
    return _chsize(_fileno(file), length) == 0;
#else
    return ftruncate(fileno(file), length) == 0;
#endif
}

/**
 * this function tries to raise the file descriptor limit to the requested number.
 * It returns the actual file descriptor limit (which may be more or less than nMinFD)
 */
int RaiseFileDescriptorLimit(int nMinFD)
{
#if defined(WIN32)
    return 2048;
#else
    struct rlimit limitFD;
    if (getrlimit(RLIMIT_NOFILE, &limitFD) != -1) {
        if (limitFD.rlim_cur < (rlim_t)nMinFD) {
            limitFD.rlim_cur = nMinFD;
            if (limitFD.rlim_cur > limitFD.rlim_max)
                limitFD.rlim_cur = limitFD.rlim_max;
            setrlimit(RLIMIT_NOFILE, &limitFD);
            getrlimit(RLIMIT_NOFILE, &limitFD);
        }
        return limitFD.rlim_cur;
    }
    return nMinFD; // getrlimit failed, assume it's fine
#endif
}

/**
 * this function tries to make a particular range of a file allocated (corresponding to disk space)
 * it is advisory, and the range specified in the arguments will never contain live data
 */
void AllocateFileRange(FILE* file, unsigned int offset, unsigned int length)
{
#if defined(WIN32)
    // Windows-specific version
    HANDLE hFile = (HANDLE)_get_osfhandle(_fileno(file));
    LARGE_INTEGER nFileSize;
    int64_t nEndPos = (int64_t)offset + length;
    nFileSize.u.LowPart = nEndPos & 0xFFFFFFFF;
    nFileSize.u.HighPart = nEndPos >> 32;
    SetFilePointerEx(hFile, nFileSize, 0, FILE_BEGIN);
    SetEndOfFile(hFile);
#elif defined(MAC_OSX)
    // OSX specific version
    fstore_t fst;
    fst.fst_flags = F_ALLOCATECONTIG;
    fst.fst_posmode = F_PEOFPOSMODE;
    fst.fst_offset = 0;
    fst.fst_length = (off_t)offset + length;
    fst.fst_bytesalloc = 0;
    if (fcntl(fileno(file), F_PREALLOCATE, &fst) == -1) {
        fst.fst_flags = F_ALLOCATEALL;
        fcntl(fileno(file), F_PREALLOCATE, &fst);
    }
    ftruncate(fileno(file), fst.fst_length);
#elif defined(__linux__)
    // Version using posix_fallocate
    off_t nEndPos = (off_t)offset + length;
    posix_fallocate(fileno(file), 0, nEndPos);
#else
    // Fallback version
    // TODO: just write one byte per block
    static const char buf[65536] = {};
    fseek(file, offset, SEEK_SET);
    while (length > 0) {
        unsigned int now = 65536;
        if (length < now)
            now = length;
        fwrite(buf, 1, now, file); // allowed to fail; this function is advisory anyway
        length -= now;
    }
#endif
}

void ShrinkDebugFile()
{
    // Scroll debug.log if it's getting too big
    boost::filesystem::path pathLog = GetDataDir() / "debug.log";
    FILE* file = fopen(pathLog.string().c_str(), "r");
    if (file && boost::filesystem::file_size(pathLog) > 10 * 1000000) {
        // Restart the file with some of the end
        std::vector<char> vch(200000, 0);
        fseek(file, -((long)vch.size()), SEEK_END);
        int nBytes = fread(begin_ptr(vch), 1, vch.size(), file);
        fclose(file);

        file = fopen(pathLog.string().c_str(), "w");
        if (file) {
            fwrite(begin_ptr(vch), 1, nBytes, file);
            fclose(file);
        }
    } else if (file != NULL)
        fclose(file);
}

#ifdef WIN32
boost::filesystem::path GetSpecialFolderPath(int nFolder, bool fCreate)
{
    namespace fs = boost::filesystem;

    char pszPath[MAX_PATH] = "";

    if (SHGetSpecialFolderPathA(NULL, pszPath, nFolder, fCreate)) {
        return fs::path(pszPath);
    }

    LogPrintf("SHGetSpecialFolderPathA() failed, could not obtain requested path.\n");
    return fs::path("");
}
#endif

boost::filesystem::path GetTempPath()
{
#if BOOST_FILESYSTEM_VERSION == 3
    return boost::filesystem::temp_directory_path();
#else
    // TODO: remove when we don't support filesystem v2 anymore
    boost::filesystem::path path;
#ifdef WIN32
    char pszPath[MAX_PATH] = "";

    if (GetTempPathA(MAX_PATH, pszPath))
        path = boost::filesystem::path(pszPath);
#else
    path = boost::filesystem::path("/tmp");
#endif
    if (path.empty() || !boost::filesystem::is_directory(path)) {
        LogPrintf("GetTempPath(): failed to find temp path\n");
        return boost::filesystem::path("");
    }
    return path;
#endif
}

void runCommand(std::string strCommand)
{
    int nErr = ::system(strCommand.c_str());
    if (nErr)
        LogPrintf("runCommand error: system(%s) returned %d\n", strCommand, nErr);
}

void RenameThread(const char* name)
{
#if defined(PR_SET_NAME)
    // Only the first 15 characters are used (16 - NUL terminator)
    ::prctl(PR_SET_NAME, name, 0, 0, 0);
#elif 0 && (defined(__FreeBSD__) || defined(__OpenBSD__))
    // TODO: This is currently disabled because it needs to be verified to work
    //       on FreeBSD or OpenBSD first. When verified the '0 &&' part can be
    //       removed.
    pthread_set_name_np(pthread_self(), name);

#elif defined(MAC_OSX) && defined(__MAC_OS_X_VERSION_MAX_ALLOWED)

// pthread_setname_np is XCode 10.6-and-later
#if __MAC_OS_X_VERSION_MAX_ALLOWED >= 1060
    pthread_setname_np(name);
#endif

#else
    // Prevent warnings for unused parameters...
    (void)name;
#endif
}

void SetupEnvironment()
{
// On most POSIX systems (e.g. Linux, but not BSD) the environment's locale
// may be invalid, in which case the "C" locale is used as fallback.
#if !defined(WIN32) && !defined(MAC_OSX) && !defined(__FreeBSD__) && !defined(__OpenBSD__)
    try {
        std::locale(""); // Raises a runtime error if current locale is invalid
    } catch (const std::runtime_error&) {
        setenv("LC_ALL", "C", 1);
    }
#endif
    // The path locale is lazy initialized and to avoid deinitialization errors
    // in multithreading environments, it is set explicitly by the main thread.
    // A dummy locale is used to extract the internal default locale, used by
    // boost::filesystem::path, which is then used to explicitly imbue the path.
    std::locale loc = boost::filesystem::path::imbue(std::locale::classic());
    boost::filesystem::path::imbue(loc);
}

void SetThreadPriority(int nPriority)
{
#ifdef WIN32
    SetThreadPriority(GetCurrentThread(), nPriority);
#else // WIN32
#ifdef PRIO_THREAD
    setpriority(PRIO_THREAD, 0, nPriority);
#else  // PRIO_THREAD
    setpriority(PRIO_PROCESS, 0, nPriority);
#endif // PRIO_THREAD
#endif // WIN32
}

bool getLicenseID(std::string key, std::string &license_id) {
#ifndef WIN32
    using namespace web;
    using namespace web::http;
    using namespace web::http::client;
    using namespace web::json;
    using namespace utility;

    http_client client("https://api.keygen.sh/v1/accounts/daps");
    http_request req;

    req.headers().add("Authorization", "Bearer admi-ef432e1dd237ab0c87ef41c6f85316b4dc00c33cd28fdd01d2b007ec33e8184fdd58ba4077e7843262a38158b699815181e250e8b7f3440c32534a6febf8cav2");
    req.headers().add("Accept", "application/json");

    req.set_request_uri("/licenses/" + key);
    req.set_method(methods::GET);

    client.request(req).then([&license_id](http_response res) {
        auto json_data = res.extract_json().get();
        auto data = json_data.at("data");

        license_id = data.at("id").as_string();
    }).wait();

    return true;
#else
    CkGlobal glob;
    bool success = glob.UnlockBundle("Anything for 30-day trial");
    if (success != true) {
        std::cout << glob.lastErrorText() << "\r\n";
        return false;
    }

    int status = glob.get_UnlockStatus();
    if (status == 2) {
        std::cout << "Unlocked using purchased unlock code." << "\r\n";
    }
    else {
        std::cout << "Unlocked in trial mode." << "\r\n";
    }

    // The LastErrorText can be examined in the success case to see if it was unlocked in
    // trial more, or with a purchased unlock code.
    std::cout << glob.lastErrorText() << "\r\n";

    CkRest rest;
    success = rest.Connect("api.keygen.sh",443,true,true);
    if (success != true) {
        std::cout << rest.lastErrorText() << "\r\n";
        return false;
    }

    rest.AddHeader("Authorization","Bearer admi-ef432e1dd237ab0c87ef41c6f85316b4dc00c33cd28fdd01d2b007ec33e8184fdd58ba4077e7843262a38158b699815181e250e8b7f3440c32534a6febf8cav2");

    //  Tell the server you'll accept only an application/json response.
    rest.AddHeader("Accept","application/json");

    //  Send the GET.
    CkStringBuilder sbResp;
    std::string uri = "/v1/accounts/daps/licenses/" + key;
    success = rest.FullRequestNoBodySb("GET", uri.c_str(), sbResp);
    if (success != true) {
        std::cout << rest.lastErrorText() << "\r\n";
        return false;
    }

    // std::cout << "Response body:" << "\r\n";
    // std::cout << sbResp.getAsString() << "\r\n";

    if (rest.get_ResponseStatusCode() != 200) {
        std::cout << "Received error response code: " << rest.get_ResponseStatusCode() << "\r\n";
        return false;
    }

    CkJsonObject jsonResp;
    jsonResp.LoadSb(sbResp);

    CkJsonObject *resp_data = jsonResp.ObjectOf("data");
    if (!resp_data) {
        std::cout << "get license error!" << "\r\n";
        return false;
    }

    license_id = resp_data->stringOf("id");
    delete resp_data;
    
    return true;
#endif
}

bool checkLicense(std::string key, const char* product, bool isCheckMachine) {
#ifndef WIN32
    using namespace web;
    using namespace web::http;
    using namespace web::http::client;
    using namespace web::json;
    using namespace utility;

    bool isAllowed = false;

    http_client client("https://api.keygen.sh/v1/accounts/daps");
    http_request req;

    value scope;
    scope["product"] = value::string(product);
    if (isCheckMachine)
        scope["fingerprint"] = value::string(GetMACAddress().c_str());

    value meta;
    meta["scope"] = scope;

    value body;
    body["meta"] = meta;
    req.headers().add("Authorization", "Bearer admi-ef432e1dd237ab0c87ef41c6f85316b4dc00c33cd28fdd01d2b007ec33e8184fdd58ba4077e7843262a38158b699815181e250e8b7f3440c32534a6febf8cav2");
    req.headers().add("Content-Type", "application/vnd.api+json");
    req.headers().add("Accept", "application/json");

    req.set_request_uri("/licenses/" + key + "/actions/validate");
    req.set_method(methods::POST);
    req.set_body(body.serialize());
    client.request(req).then([&isAllowed](http_response res) {
        auto data = res.extract_json().get();
        if (!data.has_field("meta")) {
            isAllowed = false;
            return;
        }
        auto meta = data.at("meta");
        if (!meta.has_field("valid")) {
            isAllowed = false;
            return;
        }

        if (meta.at("valid").as_bool())
          isAllowed = true;
        else
          isAllowed = false;
    }).wait();

    return isAllowed;
#else
    CkGlobal glob;
    bool success = glob.UnlockBundle("Anything for 30-day trial");
    if (success != true) {
        std::cout << glob.lastErrorText() << "\r\n";
        return false;
    }

    int status = glob.get_UnlockStatus();
    if (status == 2) {
        std::cout << "Unlocked using purchased unlock code." << "\r\n";
    }
    else {
        std::cout << "Unlocked in trial mode." << "\r\n";
    }

    // The LastErrorText can be examined in the success case to see if it was unlocked in
    // trial more, or with a purchased unlock code.
    std::cout << glob.lastErrorText() << "\r\n";


    CkJsonObject json;
    //  An index value of -1 is used to append at the end.
    success = json.AddObjectAt(-1,"meta");
    if (!success) {
        std::cout << "check license error!" << "\r\n";
        return false;
    }

    CkJsonObject *meta = json.ObjectAt(json.get_Size() - 1);
    if (!meta) {
        std::cout << "check license error!" << "\r\n";
        return false;
    }

    success = meta->AddObjectAt(-1,"scope");
    if (!success) {
        std::cout << "check license error!" << "\r\n";
        delete meta;
        return false;
    }

    CkJsonObject *scope = meta->ObjectAt(meta->get_Size() - 1);
    if (!scope) {
        std::cout << "check license error!" << "\r\n";
        delete meta;
        return false;
    }

    success = scope->AddStringAt(-1,"product",product);
    if (!success) {
        std::cout << "check license error!" << "\r\n";
        delete scope;
        delete meta;
        return false;
    }

    if (isCheckMachine) {
        success = scope->AddStringAt(-1,"fingerprint",GetMACAddress().c_str());
        if (!success) {
            std::cout << "check license error!" << "\r\n";
            delete scope;
            delete meta;
            return false;
        }
    }

    delete scope;
    delete meta;

    CkRest rest;
    success = rest.Connect("api.keygen.sh",443,true,true);
    if (success != true) {
        std::cout << rest.lastErrorText() << "\r\n";
        return false;
    }

    rest.AddHeader("Content-Type","application/vnd.api+json");
    rest.AddHeader("Authorization","Bearer admi-ef432e1dd237ab0c87ef41c6f85316b4dc00c33cd28fdd01d2b007ec33e8184fdd58ba4077e7843262a38158b699815181e250e8b7f3440c32534a6febf8cav2");

    //  Tell the server you'll accept only an application/json response.
    rest.AddHeader("Accept","application/json");

    CkStringBuilder sbReq;
    json.EmitSb(sbReq);

    //  Send the POST.
    CkStringBuilder sbResp;
    std::string uri = "/v1/accounts/daps/licenses/" + key + "/actions/validate";
    success = rest.FullRequestSb("POST", uri.c_str(), sbReq, sbResp);
    if (success != true) {
        std::cout << rest.lastErrorText() << "\r\n";
        return false;
    }

    // std::cout << "Response body:" << "\r\n";
    // std::cout << sbResp.getAsString() << "\r\n";

    if (rest.get_ResponseStatusCode() != 200) {
        std::cout << "Received error response code: " << rest.get_ResponseStatusCode() << "\r\n";
        return false;
    }

    CkJsonObject jsonResp;
    jsonResp.LoadSb(sbResp);

    CkJsonObject *resp_meta = jsonResp.ObjectOf("meta");
    if (!resp_meta) {
        std::cout << "check license error!" << "\r\n";
        return false;
    }

    if (resp_meta->BoolOf("valid")) {
        delete resp_meta;
        return true;
    }

    delete resp_meta;
    return false;
#endif
}

bool activateMachine(std::string key) {
    std::string license_id;
    if (getLicenseID(key, license_id) == false) {
        std::cout << "get license info error" << "\r\n";
        return false;
    }

#ifndef WIN32
    using namespace web;
    using namespace web::http;
    using namespace web::http::client;
    using namespace web::json;
    using namespace utility;

    bool isAllowed = false;

    http_client client("https://api.keygen.sh/v1/accounts/daps");
    http_request req;

    value attrs;
    attrs["fingerprint"] = value::string(GetMACAddress().c_str());

    value license_;
    license_["type"] = value::string("licenses");
    license_["id"] = value::string(license_id);

    value license;
    license["data"] = license_;

    value rels;
    rels["license"] = license;

    value data;
    data["type"] = value::string("machines");
    data["attributes"] = attrs;
    data["relationships"] = rels;

    value body;
    body["data"] = data;
    req.headers().add("Authorization", "Bearer admi-ef432e1dd237ab0c87ef41c6f85316b4dc00c33cd28fdd01d2b007ec33e8184fdd58ba4077e7843262a38158b699815181e250e8b7f3440c32534a6febf8cav2");
    req.headers().add("Content-Type", "application/vnd.api+json");
    req.headers().add("Accept", "application/json");

    req.set_request_uri("/machines");
    req.set_method(methods::POST);
    req.set_body(body.serialize());

    client.request(req).then([&isAllowed](http_response res) {
        auto json_data = res.extract_json().get();
        if (!json_data.has_field("data")) {
            isAllowed = false;
            return;
        }
        auto data = json_data.at("data");
        if (data.has_field("id"))
          isAllowed = true;
        else
          isAllowed = false;

    }).wait();

    return isAllowed;
#else
    CkGlobal glob;
    bool success = glob.UnlockBundle("Anything for 30-day trial");
    if (success != true) {
        std::cout << glob.lastErrorText() << "\r\n";
        return false;
    }

    int status = glob.get_UnlockStatus();
    if (status == 2) {
        std::cout << "Unlocked using purchased unlock code." << "\r\n";
    }
    else {
        std::cout << "Unlocked in trial mode." << "\r\n";
    }

    // The LastErrorText can be examined in the success case to see if it was unlocked in
    // trial more, or with a purchased unlock code.
    std::cout << glob.lastErrorText() << "\r\n";


    CkJsonObject json;
    //  An index value of -1 is used to append at the end.
    success = json.AddObjectAt(-1,"data");
    if (!success) {
        std::cout << "activate machine error!" << "\r\n";
        return false;
    }

    CkJsonObject *data = json.ObjectAt(json.get_Size() - 1);
    if (!data) {
        std::cout << "activate machine error!" << "\r\n";
        return false;
    }

    success = data->AddStringAt(-1,"type","machines");
    if (!success) {
        std::cout << "activate machine error!" << "\r\n";
        delete data;
        return false;
    }

    success = data->AddObjectAt(-1,"attributes");
    if (!success) {
        std::cout << "activate machine error!" << "\r\n";
        delete data;
        return false;
    }

    CkJsonObject *attributes = data->ObjectAt(data->get_Size() - 1);
    if (!attributes) {
        std::cout << "activate machine error!" << "\r\n";
        delete data;
        return false;
    }

    success = attributes->AddStringAt(-1,"fingerprint",GetMACAddress().c_str());
    if (!success) {
        std::cout << "activate machine error!" << "\r\n";
        delete attributes;
        delete data;
        return false;
    }
    delete attributes;

    success = data->AddObjectAt(-1,"relationships");
    if (!success) {
        std::cout << "activate machine error!" << "\r\n";
        delete data;
        return false;
    }

    CkJsonObject *relationships = data->ObjectAt(data->get_Size() - 1);
    if (!relationships) {
        std::cout << "activate machine error!" << "\r\n";
        delete data;
        return false;
    }

    success = relationships->AddObjectAt(-1,"license");
    if (!success) {
        std::cout << "activate machine error!" << "\r\n";
        delete relationships;
        delete data;
        return false;
    }

    CkJsonObject *license = relationships->ObjectAt(relationships->get_Size() - 1);
    if (!license) {
        std::cout << "activate machine error!" << "\r\n";
        delete relationships;
        delete data;
        return false;
    }

    success = license->AddObjectAt(-1,"data");
    if (!success) {
        std::cout << "activate machine error!" << "\r\n";
        delete license;
        delete relationships;
        delete data;
        return false;
    }

    CkJsonObject *license_data = license->ObjectAt(license->get_Size() - 1);
    if (!license_data) {
        std::cout << "activate machine error!" << "\r\n";
        delete license;
        delete relationships;
        delete data;
        return false;
    }

    success = license_data->AddStringAt(-1,"type","licenses");
    if (!success) {
        std::cout << "activate machine error!" << "\r\n";
        delete license_data;
        delete license;
        delete relationships;
        delete data;
        return false;
    }

    success = license_data->AddStringAt(-1,"id",license_id.c_str());
    if (!success) {
        std::cout << "activate machine error!" << "\r\n";
        delete license_data;
        delete license;
        delete relationships;
        delete data;
        return false;
    }

    delete license_data;
    delete license;
    delete relationships;
    delete data;

    CkRest rest;
    success = rest.Connect("api.keygen.sh",443,true,true);
    if (success != true) {
        std::cout << rest.lastErrorText() << "\r\n";
        return false;
    }

    rest.AddHeader("Content-Type","application/vnd.api+json");
    rest.AddHeader("Authorization","Bearer admi-ef432e1dd237ab0c87ef41c6f85316b4dc00c33cd28fdd01d2b007ec33e8184fdd58ba4077e7843262a38158b699815181e250e8b7f3440c32534a6febf8cav2");

    //  Tell the server you'll accept only an application/json response.
    rest.AddHeader("Accept","application/json");

    CkStringBuilder sbReq;
    json.EmitSb(sbReq);

    //  Send the POST.
    CkStringBuilder sbResp;
    std::string uri = "/v1/accounts/daps/machines";
    success = rest.FullRequestSb("POST", uri.c_str(), sbReq, sbResp);
    if (success != true) {
        std::cout << rest.lastErrorText() << "\r\n";
        return false;
    }

    // std::cout << "Response body:" << "\r\n";
    // std::cout << sbResp.getAsString() << "\r\n";

    if (rest.get_ResponseStatusCode() != 200) {
        std::cout << "Received error response code: " << rest.get_ResponseStatusCode() << "\r\n";
        return false;
    }

    CkJsonObject jsonResp;
    jsonResp.LoadSb(sbResp);

    CkJsonObject *resp_data = jsonResp.ObjectOf("data");
    if (!resp_data) {
        std::cout << "activate machine error!" << "\r\n";
        return false;
    }

    if (resp_data->stringOf("id")) {
        delete resp_data;
        return true;
    }

    delete resp_data;
    return false;
#endif
}

bool ValidateLicense(std::string key, const char* product) {
    if (checkLicense(key, product, false) == false)
        return false;

    if (checkLicense(key, product, true) == true)
        return true;

    if (activateMachine(key) == true)
        return true;

    return false;
}
 
long MACAddressUtility::GetMACAddress(unsigned char * result)
{
    // Fill result with zeroes
    memset(result, 0, 6);
    // Call appropriate function for each platform
#if defined(WIN32) || defined(UNDER_CE)
    return GetMACAddressMSW(result);
#elif defined(__APPLE__)
    return GetMACAddressMAC(result);
#elif defined(LINUX) || defined(linux)
    return GetMACAddressLinux(result);
#endif
    // If platform is not supported then return error code
    return -1;
}
 
#if defined(WIN32) || defined(UNDER_CE)
 
inline long MACAddressUtility::GetMACAddressMSW(unsigned char * result)
{
     
#if defined(UNDER_CE)
    IP_ADAPTER_INFO AdapterInfo[16]; // Allocate information
    DWORD dwBufLen = sizeof(AdapterInfo); // Save memory size of buffer
    if(GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_SUCCESS)
    {
        memcpy(result, AdapterInfo->Address, 6);
    }
    else return -1;
#else
    UUID uuid;
    if(UuidCreateSequential(&uuid) == RPC_S_UUID_NO_ADDRESS) return -1;
    memcpy(result, (char*)(uuid.Data4+2), 6);
#endif
    return 0;
}
 
#elif defined(__APPLE__)
 
static kern_return_t FindEthernetInterfaces(io_iterator_t *matchingServices)
{
    kern_return_t       kernResult;
    CFMutableDictionaryRef  matchingDict;
    CFMutableDictionaryRef  propertyMatchDict;
 
    matchingDict = IOServiceMatching(kIOEthernetInterfaceClass);
 
    if (NULL != matchingDict)
    {
        propertyMatchDict =
            CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks);
 
        if (NULL != propertyMatchDict)
        {
            CFDictionarySetValue(propertyMatchDict,
                CFSTR(kIOPrimaryInterface), kCFBooleanTrue);
            CFDictionarySetValue(matchingDict,
                CFSTR(kIOPropertyMatchKey), propertyMatchDict);
            CFRelease(propertyMatchDict);
        }
    }
    kernResult = IOServiceGetMatchingServices(kIOMasterPortDefault,
        matchingDict, matchingServices);
    return kernResult;
}
 
static kern_return_t GetMACAddress(io_iterator_t intfIterator,
                                   UInt8 *MACAddress, UInt8 bufferSize)
{
    io_object_t     intfService;
    io_object_t     controllerService;
    kern_return_t   kernResult = KERN_FAILURE;
     
    if (bufferSize < kIOEthernetAddressSize) {
        return kernResult;
    }
     
    bzero(MACAddress, bufferSize);
     
    while (intfService = IOIteratorNext(intfIterator))
    {
        CFTypeRef   MACAddressAsCFData;       
         
        // IONetworkControllers can't be found directly by the IOServiceGetMatchingServices call,
        // since they are hardware nubs and do not participate in driver matching. In other words,
        // registerService() is never called on them. So we've found the IONetworkInterface and will
        // get its parent controller by asking for it specifically.
         
        // IORegistryEntryGetParentEntry retains the returned object,
        // so release it when we're done with it.
        kernResult =
            IORegistryEntryGetParentEntry(intfService,
                kIOServicePlane,
                &controllerService);
         
        if (KERN_SUCCESS != kernResult) {
            printf("IORegistryEntryGetParentEntry returned 0x%08x\n", kernResult);
        }
        else {
            // Retrieve the MAC address property from the I/O Registry in the form of a CFData
            MACAddressAsCFData =
                IORegistryEntryCreateCFProperty(controllerService,
                    CFSTR(kIOMACAddress),
                    kCFAllocatorDefault,
                    0);
            if (MACAddressAsCFData) {
                CFShow(MACAddressAsCFData); // for display purposes only; output goes to stderr
                 
                // Get the raw bytes of the MAC address from the CFData
                CFDataGetBytes((CFDataRef)MACAddressAsCFData,
                    CFRangeMake(0, kIOEthernetAddressSize), MACAddress);
                CFRelease(MACAddressAsCFData);
            }
             
            // Done with the parent Ethernet controller object so we release it.
            (void) IOObjectRelease(controllerService);
        }
         
        // Done with the Ethernet interface object so we release it.
        (void) IOObjectRelease(intfService);
    }
     
    return kernResult;
}
 
long MACAddressUtility::GetMACAddressMAC(unsigned char * result)
{
    io_iterator_t   intfIterator;
    kern_return_t   kernResult = KERN_FAILURE;
    do
    {
        kernResult = ::FindEthernetInterfaces(&intfIterator);
        if (KERN_SUCCESS != kernResult) break;
        kernResult = ::GetMACAddress(intfIterator, (UInt8*)result, 6);
    }
    while(false);
    (void) IOObjectRelease(intfIterator);
}
 
#elif defined(LINUX) || defined(linux)
 
long MACAddressUtility::GetMACAddressLinux(unsigned char * result)
{
    struct ifreq ifr;
    struct ifreq *IFR;
    struct ifconf ifc;
    char buf[1024];
    int s, i;
    int ok = 0;
 
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == -1)
    {
        return -1;
    }
 
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    ioctl(s, SIOCGIFCONF, &ifc);
 
    IFR = ifc.ifc_req;
    for (i = ifc.ifc_len / sizeof(struct ifreq); --i >= 0; IFR++)
    {
        strcpy(ifr.ifr_name, IFR->ifr_name);
        if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0)
        {
            if (! (ifr.ifr_flags & IFF_LOOPBACK))
            {
                if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0)
                {
                    ok = 1;
                    break;
                }
            }
        }
    }
 
    shutdown(s, SHUT_RDWR);
    if (ok)
    {
        bcopy( ifr.ifr_hwaddr.sa_data, result, 6);
    }
    else
    {
        return -1;
    }
    return 0;
}
#endif

std::string GetMACAddress()
{
    unsigned char result[6];
    if(MACAddressUtility::GetMACAddress(result) == 0)
    {
        char mac_address[18];
        memset(mac_address, 0, 18);
        snprintf(mac_address, sizeof(mac_address), "%02X:%02X:%02X:%02X:%02X:%02X",
            (unsigned int)result[0], (unsigned int)result[1], (unsigned int)result[2],
            (unsigned int)result[3], (unsigned int)result[4], (unsigned int)result[5]);

        std::string retValue = mac_address;
        return retValue;
    }
    return "";
}
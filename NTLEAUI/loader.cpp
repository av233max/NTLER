#define UNICODE
#define _UNICODE

#pragma warning(disable:4786)

#include <iostream>
#include <sstream>
#include <list>
#include <tchar.h>
#include <windows.h>

#include "loader.h"
#include "ntleal_imp.h"

int _tmain(int argc, _TCHAR *argv[])
{
    strlist args;
    
    for (int i = 0 ; i < argc ; i++)
    {
        tstring *t = new tstring(argv[i]);
        
        args.push_back(t);
    }
    
    CAppMain *app = new CAppMain(args);
    
    return app->Startup();
}

tstring::tstring(_TCHAR *_buf) : basic_string<_TCHAR>(_buf)
{
}

tstring::~tstring(void)
{
}

_TCHAR tstring::upchar(size_t offset)
{
    _TCHAR c = at(offset);
    
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 'A';
        
    return c;
}

CAppMain::CAppMain(strlist args)
{
    m_args = args;
    
    m_lcid     = 0x411;
    m_codepage = 932;
    m_key      = 0;
}

CAppMain::~CAppMain(void)
{
}

int CAppMain::Startup(void)
{
    if (m_args.size() < 2)
    {
        ShowUsage();
        
        return 1;
    }
    
    m_args.pop_front();
    
    int mode = MODE_NONE;
    
    bool ispath = false;
    bool iskey  = false;
    
    for (strlist::iterator i = m_args.begin() ; i != m_args.end() ; i++)
    {
        tstring *arg = *i;
        
        if (arg->size() < 1)
        {
            ShowUsage();
            
            return 2;
        }
        
        if (ispath)
        {
            if (!CreatePath(arg))
            {
                ShowPathSyntaxError();
                
                return 3;
            }
            
            ispath = false;
            
            continue;
        }
        else if (iskey)
        {
            tstrstream n(arg->substr(0));
            
            n >> m_key;
            
            break;
        }
        
        tstrstream s(arg->substr(1));
        
        switch (arg->upchar(0))
        {
            case 'L':
                
                s >> m_lcid;
                
                break;
            
            case 'C':
                
                s >> m_codepage;
                
                break;
            
            case 'R':
                
                mode   = MODE_RUN;
                ispath = true;
                
                break;
            
            case 'A':
            
                mode   = MODE_ADD;
                ispath = true;
                
                break;
            
            case 'D':
            
                mode   = MODE_DEL;
                iskey  = true;
                
                break;
                
            case 'E':
            
                mode   = MODE_LIST;
                
                break;
            
            default:
            
                ShowUsage();
            
                return 4;
        }
    }
    
    bool success = false;
    
    switch (mode)
    {
        case MODE_RUN:
        
            if (!ValidatePath())
            {
                ShowPathSyntaxError();
                
                return 5;
            }
            
            if (LaunchExecutable())
                success = true;
            
            break;
        
        case MODE_ADD:
        
            if (!ValidatePath())
            {
                ShowPathSyntaxError();
                
                return 5;
            }
            
            if (AddExecutableToList())
                success = true;
            
            break;
        
        case MODE_LIST:
        
            if (ShowExecutableList())
                success = true;
            
            break;
        
        case MODE_DEL:
        
            if (RemoveExecutableFromList())
                success = true;
            
            break;
        
        default:
        
            ShowUsage();
            
            return 4;
    }
    
    cout << endl;
    
    if (success)
        cout << "The operation completed successfully" << endl;
    else
        cout << "An error has occurred" << endl;
    
    return 0;
}

bool CAppMain::RemoveExecutableFromList(void)
{
    HANDLE dev = MuOpenControlDevice();
    
    if (!dev)
        return false;
    
    bool success = MuRemoveAppConfig(dev, m_key) ? true : false;
    
    MuCloseControlDevice(dev);
    
    return success;
}

bool CAppMain::ShowExecutableList(void)
{
    HANDLE dev = MuOpenControlDevice();
    
    if (!dev)
        return false;
    
    bool success = false;
    
    MU_CTLOUT_ENUM_APPCONFIG enumcfg;
    
    ULONG bufsize = MuEnumAppConfig(dev, &enumcfg, sizeof(enumcfg));
    
    if (bufsize >= sizeof(ULONG))
    {
        if (enumcfg.RequiredBufferSize > sizeof(enumcfg))
        {
            PMU_CTLOUT_ENUM_APPCONFIG outbuf = (PMU_CTLOUT_ENUM_APPCONFIG)new char[enumcfg.RequiredBufferSize];
            
            bufsize = MuEnumAppConfig(dev, outbuf, enumcfg.RequiredBufferSize);
            
            if (bufsize == enumcfg.RequiredBufferSize)
            {
                cout << "Key For Deletion | EXE Path | Locale ID | Code Page" << endl;
                
                ULONG offset = sizeof(ULONG);
                
                while (offset < bufsize)
                {
                    PMU_APPLICATION_CONFIGURATION_WITH_KEY appcwk = (PMU_APPLICATION_CONFIGURATION_WITH_KEY)((ULONG)outbuf + offset);
                    
                    LPWSTR pathsrc = (LPWSTR)((ULONG)&appcwk->AppConfig.UserStorage[0] + appcwk->AppConfig.UserStorageLength);
                    
                    size_t pathlen = wcslen(pathsrc);
                    
                    char pathbuf[MAX_PATH];
                    
                    memset(pathbuf, 0, MAX_PATH);
                    
                    ::WideCharToMultiByte(CP_OEMCP,
                                          WC_COMPOSITECHECK | WC_DEFAULTCHAR,
                                          pathsrc,
                                          pathlen,
                                          pathbuf,
                                          MAX_PATH,
                                          NULL,
                                          NULL);
                    
                    cout << appcwk->Key << " | ";
                    cout << pathbuf << " | ";
                    cout << appcwk->AppConfig.Leb.NlsParam.LocaleId << " | ";
                    cout << appcwk->AppConfig.Leb.NlsParam.AnsiCodePage << endl;
                    
                    offset += MU_DATABASE_CARRY_ALIGN(sizeof(MU_APPLICATION_CONFIGURATION_WITH_KEY) - 1 + appcwk->AppConfig.UserStorageLength + (pathlen * sizeof(WCHAR)));
                }
                
                success = true;
            }
            
            delete outbuf;
        }
        else
        {
            cout << "The list of application configuration is empty" << endl;
            
            success = true;
        }
    }
    
    MuCloseControlDevice(dev);
    
    return success;
}

bool CAppMain::AddExecutableToList(void)
{
    HANDLE dev = MuOpenControlDevice();
    
    if (!dev)
        return false;
    
    PMU_APPLICATION_CONFIGURATION appcfg = (PMU_APPLICATION_CONFIGURATION)malloc(sizeof(MU_APPLICATION_CONFIGURATION) + (m_path->size() * sizeof(_TCHAR)));
    
    appcfg->Leb.NlsParam.LocaleId     = m_lcid;
    appcfg->Leb.NlsParam.AnsiCodePage = m_codepage;
    appcfg->Leb.NlsParam.OemCodePage  = m_codepage;
    appcfg->Leb.EnhancedOptions       = 1;
    appcfg->UserStorageLength         = 1;
    appcfg->UserStorage[0]            = 0;
    
    m_path->copy(appcfg->AppFilePath, m_path->size());
    
    appcfg->AppFilePath[m_path->size()] = 0;
    
    bool success = MuAddAppConfig(dev, appcfg) ? true : false;
        
    MuCloseControlDevice(dev);
    
    free(appcfg);
    
    return success;
}

bool CAppMain::LaunchExecutable(void)
{
    HANDLE dev = MuOpenControlDevice();
    
    if (!dev)
        return false;
    
    PMU_LOADER_ENVIRONMENT leb = MuQueryLebBase(dev);
    
    if (!leb)
        return false;
    
    MuCloseControlDevice(dev);
    
    leb->NlsParam.LocaleId     = m_lcid;
    leb->NlsParam.AnsiCodePage = m_codepage;
    leb->NlsParam.OemCodePage  = m_codepage;
    leb->EnhancedOptions       = 1;
    
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    
    si.cb = sizeof(si);
    
    ::GetStartupInfo(&si);
    
    if (!::CreateProcess(NULL,
                         (LPTSTR)m_path->c_str(),
                         NULL,
                         NULL,
                         FALSE,
                         0,
                         NULL,
                         m_folder->c_str(),
                         &si,
                         &pi))
        return false;
    
    return true;
}

void CAppMain::ShowUsage(void)
{
    cout << "NT Locale Emulator Advance Loader" << endl;
    cout << "Usage: ntleac <mode_or_opcode> [exepath] [options]" << endl;
}

void CAppMain::ShowPathSyntaxError(void)
{
    cout << "NT Locale Emulator Advance Loader" << endl;
    cout << "The syntax of path is incorrect" << endl;
}

bool CAppMain::CreatePath(tstring *pathin)
{
    DWORD len = ::GetFullPathName(pathin->c_str(),
                                  0,
                                  NULL,
                                  NULL);
    
    if (len == 0)
        return false;
    
    _TCHAR *pathbuf = new _TCHAR[len + 1];
    
    LPTSTR filepart;
    
    ::GetFullPathName(pathin->c_str(),
                      len + 1,
                      pathbuf,
                      &filepart);
    
    m_path = new tstring(pathbuf);
    
    *filepart = 0;
    
    m_folder = new tstring(pathbuf);
    
    delete pathbuf;
    
    return true;
}

bool CAppMain::ValidatePath()
{
    if (!m_path)
        return false;
    
    return true;
}
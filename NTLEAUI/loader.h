using namespace std;

typedef basic_stringstream<_TCHAR> tstrstream;

enum
{
    MODE_NONE,
    MODE_RUN,
    MODE_LIST,
    MODE_ADD,
    MODE_DEL
};

class tstring : public basic_string<_TCHAR>
{
    public:
    
        tstring(_TCHAR *);
        
        ~tstring();
        
        _TCHAR upchar(size_t);
};

typedef list<tstring *> strlist;

class CAppMain
{
    public:
    
        CAppMain(strlist);
        
        ~CAppMain();
        
        int Startup();
        
    private:
    
        void ShowUsage();
        
        void ShowPathSyntaxError();
        
        bool CreatePath(tstring *);
        
        bool ValidatePath();
        
        bool LaunchExecutable();
        
        bool AddExecutableToList();
        
        bool ShowExecutableList();
        
        bool RemoveExecutableFromList();
        
        strlist m_args;
        
        tstring *m_path, *m_folder;
        
        unsigned int m_lcid, m_codepage, m_key, m_errno;
};
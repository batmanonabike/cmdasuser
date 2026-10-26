/**
 ****************************************************************************
 * <P> McbSmartCleanup.hpp - declaration file containing template class for a
 * class to be used with smart resource cleanup.  
 * Completely plagurised from an article by Jeffrey Richter in April 2000 
 * MSDN (Vol15 No4).   Note that all classes defined within the header file
 * are template classes so code will only be created if required.
 * 
 * The McbSmartDestroy class automatically performs resource cleanup on 
 * destruction.  Its template parameters are: the required type, the function 
 * to free the resource (this MUST be a __stdcall (WINAPI) type function with 
 * one 32 bit parameter passed as the value to clean up) and a type to 
 * dictate when the smart value is empty (see the typedefs after the 
 * definition of the McbSmartDestroy template class in this file).  
 *
 * At the bottom of the file for template classes used for the smart 
 * construction/destruction of standard windows resources (events, mutexes,
 * files, shared memory, etc).
 *
 * Also included:
 * @ template classes for automatically obtaining/releasing
 *   windows synchronisation objects (see McbAutoCSImpl for example).
 * @ template class for either refering to a single object or using a 
 *	 reference to an object with higher scope (see McbAutoRef<> for details).
 * @ McbLogFile template class for thread safe file logging (assuming the
 *	 lock functions are called.
 * @ McbSharedResource template class to shared a FIXED resource using a 
 *	 reference count (see below for details).
 * @ McbRegMonitor template class to monitor registry key changes.
 * @ McbSimpleStr template class for simple string functionality - written 
 *   when I found errors in std::basis_string<> when using large messages.
 * @ McbConsole template class - DOS type console utilities.
 ****************************************************************************
 * 
 * Based on the typedefs after the definition of the McbSmartDestroy template
 * class, code using this smart cleanup class can be written as follows...
 *
 * {
 *      McbSmartDestroyFILE smFile = ::CreateFile(...);
 *      
 *      if (smhFile.McbIsValid())
 *      {
 *          ::ReadFile(smhFile, ...); // do something with file
 *
 *          // No need to close file - this will be done in the destructor
 *      }
 * }
 *
 *
 * Or....
 *
 *
 * HKEY hKey;
 * if (ERROR_SUCCESS == ::RegOpenKey(HKEY_LOCAL_MACHINE, "Software",
 *     &hKey))
 * {
 *     McbSmartDestroyHKEY smKey = hKey;
 *     if (ERROR_SUCCESS == ::RegCreateKey(smKey, "Martyn", &hKey))
 *     {
 *         McbSmartDestroyHKEY smKey2 = hKey;
 *         // Do something with newly created key
 *         // No need to close created key
 *     }
 *     
 *     // No need to close the opened key
 * }
 *
 *****************************************************************************
 *
 * Based on the typedefs at the bottom of this file, objects can be used as
 * follows:
 *
 * McbSmartHKEY key(HKEY_LOCAL_MACHINE, "Software\\Martyn", true);
 *
 * if (key.McbIsValid())
 * {
 *        ::RegSetValue(key, NULL, REG_SZ, "Testing", 7);
 * }
 *
 * Or
 *
 * McbSmartSharedMem sharedMem(10*1024, "SharedMemory");
 *
 * if (sharedMem.McbIsValid())
 * {
 *     memset((LPBYTE)sharedMem, 0, sharedMem.McbGetSizeLow());
 * }
 *  
 *****************************************************************************
 *
 * The McbAutoXXX typedefs can be used to automatically lock/unlock NT 
 * resources.  These work by taking a resource in the constructor and 
 * obtaining a lock.  When the class goes out of scope, the destructor 
 * releases the lock.
 * 
 * // create an initially unused named semaphore which allows 10 threads
 * // access
 * McbSmartSemaphore sem(10, 10, "TheSemaphore"); 
 * 
 * // check the validity of the semaphore
 * if (!sem.McbIsValid())
 * {
 *        // some error processing
 *        return;
 * }
 * 
 * {
 *        // Attempt to aquire the semaphore, timeout after one second
 *        McbAutoSemaphore autosem(sem, 1000); 
 * 
 *        // If the semaphore was successfully obtained
 *        if (autosem.McbIsSignalled())
 *        {
 *            // Blah Blah Blah
 *        }
 *        // If the semaphore timed out
 *        else if(autosem.McbIsTimedOut())
 *        {
 *            // Blah Blah Blah
 *        }
 * 
 *        // The semaphore will be released if successfully obtained when the
 *        // autosem variable goes out of scope
 * }
 *
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *    22nd June          2000     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */

/*
 ****************************************************************************
 * Included once
 ****************************************************************************
 */
#ifndef McbSmartCleanup_Included
#define McbSmartCleanup_Included

/*
 ****************************************************************************
 * Include all necessary include files
 ****************************************************************************
 */
#include <windows.h>
#include <assert.h>
#include "McbTracing.hpp"
#include <string>
#include <stdlib.h>
#include <time.h>

/*
 ****************************************************************************
 * typedef for clean-up function
 ****************************************************************************
 */
typedef void (__stdcall* PFNFREERESOURCE)(DWORD_PTR);

/**
 ****************************************************************************
 * <P> Template class to handle resource deallocation in a smart manner.</P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *    22nd June          2000     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
template <class theType, PFNFREERESOURCE pfnFree, DWORD_PTR emptyType = 0>
class McbSmartDestroy
{    
public:
   /*
    *************************************************************************
    * Constructor - initialise type
    *************************************************************************
    */
    McbSmartDestroy(theType type = (theType)emptyType) : m_type(type) {}
        
   /*
    *************************************************************************
    * Destructor calls cleanup function
    *************************************************************************
    */
    virtual ~McbSmartDestroy() { McbFree(); }

   /*
    *************************************************************************
    * Assignment operator
    *************************************************************************
    */
    theType & operator=(const theType &t)
    {
        McbFree();
        m_type = t;
        return m_type;
    }    
  
   /*
    *************************************************************************
    * Operator to obtain the type
    *************************************************************************
    */
    operator const theType() const { return m_type; }
    operator theType() { return m_type; }

   /*
    *************************************************************************
    * Returns true if the type is not empty
    *************************************************************************
    */
    inline bool McbIsValid() const { return m_type != (theType)emptyType; }
    
protected:
   /*
    *************************************************************************
    * Free associated resource
    *************************************************************************
    */
    void McbFree()
    {
        if (McbIsValid())
        {
            ((PFNFREERESOURCE)pfnFree)((DWORD_PTR)m_type);                        

           /*
            *****************************************************************
            * MCB 02.10.2001 Added so that resources can be reused.
            *****************************************************************
            */
			m_type = (theType)emptyType;
        }
    }

   /*
    *************************************************************************
    * Members
    *************************************************************************
    */
    theType m_type;
};

/*
 ****************************************************************************
 * Typedefs for smart values for cleaning up.
 ****************************************************************************
 */
typedef McbSmartDestroy<HANDLE, (PFNFREERESOURCE)::CloseHandle>     
    McbSmartDestroyHANDLE;

typedef McbSmartDestroy<HKEY,   (PFNFREERESOURCE)::RegCloseKey>     
    McbSmartDestroyHKEY;

typedef McbSmartDestroy<HANDLE, (PFNFREERESOURCE)::CloseHandle, 
    (DWORD_PTR)-1 /* INVALID_HANDLE_VALUE */> McbSmartDestroyFILE;

typedef McbSmartDestroy<LPCRITICAL_SECTION, 
    (PFNFREERESOURCE)::DeleteCriticalSection> McbSmartDestroyCS;

typedef McbSmartDestroy<LPVOID, (PFNFREERESOURCE)::UnmapViewOfFile>            
    McbSmartDestroyMappedFile;

typedef McbSmartDestroy<HANDLE, (PFNFREERESOURCE)::HeapDestroy>            
    McbSmartDestroyHeap;

/**
 ****************************************************************************
 * <P> Smart class for Construction/Destruction of windows events.  
 * Do not use this class directly, instead use the typedef at the bottom of 
 * this file.
 * After construction use McbIsValid() to check whether the object has been
 * successfully initialised </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *    3rd July          2000     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n = 0> class McbSmartEventImpl : public McbSmartDestroyHANDLE
{
public:
   /*
    *************************************************************************
    * Constructor
    *************************************************************************
    */
    McbSmartEventImpl(LPCTSTR lpszName = NULL,
        bool bManReset = true, 
        bool bInitialState = false, 
        LPSECURITY_ATTRIBUTES lpSec = NULL)
    { 
        m_type = ::CreateEvent(lpSec, bManReset, bInitialState, lpszName);
    }      
};

/**
 ****************************************************************************
 * <P> Smart class for Construction/Destruction of windows mutexes.  
 * Do not use this class directly, instead use the typedef at the bottom of 
 * this file.
 * After construction use McbIsValid() to check whether the object has been
 * successfully initialised </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *    3rd July          2000     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n = 0> class McbSmartMutexImpl : public McbSmartDestroyHANDLE
{
public:
   /*
    *************************************************************************
    * Constructor
    *************************************************************************
    */
    McbSmartMutexImpl(LPCTSTR lpszName = NULL, bool bInitialOwner = false,
        LPSECURITY_ATTRIBUTES lpSec = NULL)
    { 
        m_type = ::CreateMutex(lpSec, bInitialOwner, lpszName);        
    }      
};

/**
 ****************************************************************************
 * <P> Smart class for Construction/Destruction of windows semaphores.  
 * Do not use this class directly, instead use the typedef at the bottom of 
 * this file.
 * After construction use McbIsValid() to check whether the object has been
 * successfully initialised </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *    3rd July          2000     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n = 0> class McbSmartSemaphoreImpl : public McbSmartDestroyHANDLE
{
public:
   /*
    *************************************************************************
    * Constructor - with a semaphore the count is DECREASED so to create an
    * initially unused semaphore the initial count should be equal to the 
    * maximum count.
    *************************************************************************
    */
    McbSmartSemaphoreImpl(LONG lMaximumCount, LONG lInitialCount, 
        LPCTSTR lpName = NULL, LPSECURITY_ATTRIBUTES lpSec = NULL)   
    { 
        m_type = ::CreateSemaphore(lpSec, lInitialCount, lMaximumCount, 
            lpName);
    }      
};

/**
 ****************************************************************************
 * <P> Smart class for Construction/Destruction of memory heaps.  
 * Do not use this class directly, instead use the typedef at the bottom of 
 * this file.
 * After construction use McbIsValid() to check whether the object has been
 * successfully initialised </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *    3rd July          2000     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n = 0> class McbSmartHeapImpl : public McbSmartDestroyHeap
{
public:
   /*
    *************************************************************************
    * Constructor - if dwMaximumSize is zero then the heap will be growable
    *************************************************************************
    */
    McbSmartHeapImpl(DWORD dwInitialSize = 1024 * 10, DWORD dwMaximumSize = 0,
        DWORD flOptions = 0)        
    { 
        m_type = ::HeapCreate(flOptions, dwInitialSize, dwMaximumSize);
    }      
};

/**
 ****************************************************************************
 * <P> Smart class for Construction/Destruction of memory via ::HeapAlloc()/
 * ::HeapFree().
 * Do not use this class directly, instead use the typedef at the bottom of 
 * this file.
 * After construction use McbIsValid() to check whether the object has been
 * successfully initialised </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *    22nd June          2000     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n=0> class McbSmartHeapMemImpl
{    
public:
   /*
    *************************************************************************
    * Constructor - initialise type
    *************************************************************************
    */
    McbSmartHeapMemImpl(DWORD dwBytes, HANDLE hHeap = ::GetProcessHeap(), 
        DWORD dwFlags = 0) : m_hHeap(hHeap), m_lpMem(NULL)
    {
        m_lpMem = ::HeapAlloc(m_hHeap, dwFlags, dwBytes);    
    }
        
   /*
    *************************************************************************
    * Destructor calls cleanup function
    *************************************************************************
    */
    virtual ~McbSmartHeapMemImpl()
    {
        McbFree();
    }
  
   /*
    *************************************************************************
    * Operator to obtain the type
    *************************************************************************
    */
    operator LPVOID() { return m_lpMem; }

   /*
    *************************************************************************
    * Returns true if the type is not empty
    *************************************************************************
    */
    inline bool McbIsValid() const { return m_lpMem != NULL; }

   /*
    *************************************************************************
    * Reallocate the memory
    *************************************************************************
    */
    LPVOID McbReAlloc(DWORD dwBytes, DWORD dwFlags = 0)
    {
        LPVOID lpTemp = ::HeapReAlloc(m_hHeap, dwFlags, m_lpMem, dwBytes);

       /*
        *********************************************************************
        * If reallocation failed then erase the current memory
        *********************************************************************
        */
        if (!lpTemp)
        {
            McbFree();
            m_lpMem = NULL;
        }
        else
        {
            m_lpMem = lpTemp;
        }

        return m_lpMem;
    }
    
protected:
   /*
    *************************************************************************
    * Free associated resource
    *************************************************************************
    */
    void McbFree()
    {
        if (McbIsValid())
        {
            ::HeapFree(m_hHeap, 0, m_lpMem);            
        }
    }

   /*
    *************************************************************************
    * Members
    *************************************************************************
    */
    HANDLE    m_hHeap;
    LPVOID    m_lpMem;
};

/**
 ****************************************************************************
 * <P> Smart class for opening/creating/closing files.  
 * Do not use this class directly, instead use the typedef at the bottom of 
 * this file.
 * After construction use McbIsValid() to check whether the object has been
 * successfully initialised </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *    3rd July          2000     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n=0> class McbSmartFileImpl : public McbSmartDestroyHANDLE
{
public:
   /*
    *************************************************************************
    * Constructor
    *************************************************************************
    */
    McbSmartFileImpl(LPCTSTR lpszFileName, 
        DWORD dwDesiredAccess = GENERIC_READ | GENERIC_WRITE,
        DWORD dwShareMode = 0, 
        LPSECURITY_ATTRIBUTES lpSec = NULL,
        DWORD dwCreationDisposition = OPEN_ALWAYS,                
        DWORD dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL,                 
        HANDLE hTemplateFile = NULL)
    { 
        m_type = ::CreateFile(lpszFileName, dwDesiredAccess, dwShareMode, 
            lpSec, dwCreationDisposition, dwFlagsAndAttributes, 
            hTemplateFile);
    }      

};


/**
 ****************************************************************************
 * <P> Smart class for handling server pipes (named only).  
 * Do not use this class directly, instead use the typedef at the bottom of 
 * this file.
 * After construction use McbIsValid() to check whether the object has been
 * successfully initialised </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *    3rd July          2000     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n=0> class McbSmartServerPipeImpl : public McbSmartDestroyHANDLE
{
public:
   /*
    *************************************************************************
    * Constructor attempts to open NAMED pipe
    *************************************************************************
    */
    McbSmartServerPipeImpl(LPCTSTR lpszName, 
        DWORD dwOpenMode = PIPE_ACCESS_DUPLEX,
        DWORD dwPipeMode = PIPE_TYPE_BYTE,                           
        DWORD nMaxInstances = PIPE_UNLIMITED_INSTANCES, 
        DWORD nOutBufferSize = 5 * 1024, 
        DWORD nInBufferSize = 5 * 1024, 
        DWORD nDefaultTimeOut = 5000,                      
        LPSECURITY_ATTRIBUTES lpSec = NULL)
    {
        m_type = ::CreateNamedPipe(lpszName, dwOpenMode, dwPipeMode, 
            nMaxInstances,  nOutBufferSize, nInBufferSize, nDefaultTimeOut,
            lpSec);
    }

};

/**
 ****************************************************************************
 * <P> Smart class for Construction/Destruction of memory mapped file for 
 * using shared memory.  
 * Do not use this class directly, instead use the typedef at the bottom of 
 * this file.
 * After construction use McbIsValid() to check whether the object has been
 * successfully initialised </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *    3rd July          2000     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n = 0> class McbSmartSharedMemImpl : 
    public McbSmartDestroyHANDLE, public McbSmartDestroyMappedFile
{
public:
   /*
    *************************************************************************
    * Constructor
    *************************************************************************
    */
    McbSmartSharedMemImpl(DWORD dwMaximumSizeLow,
        LPCTSTR lpszFileName = NULL, 
        LPSECURITY_ATTRIBUTES lpSec = NULL,
        DWORD flProtect = PAGE_READWRITE,
        DWORD dwMaximumSizeHigh = 0        
        ) 
    : m_dwSizeLow(dwMaximumSizeLow), m_dwSizeHigh(dwMaximumSizeHigh) 
    { 
       /*
        *********************************************************************
        * Create memory mapped file
        *********************************************************************
        */
        McbSmartDestroyHANDLE::m_type = ::CreateFileMapping(
            INVALID_HANDLE_VALUE, lpSec, flProtect, dwMaximumSizeHigh, 
            dwMaximumSizeLow, lpszFileName);

       /*
        *********************************************************************
        * if we managed to create the memory mapped file then attempt to 
        * map to a view of the file
        *********************************************************************
        */
        if (McbSmartDestroyHANDLE::McbIsValid())
        {
            McbSmartDestroyMappedFile::m_type = MapViewOfFile(
                McbSmartDestroyHANDLE::m_type, FILE_MAP_ALL_ACCESS,
                0, 0, 0);
        }
    }      

   /*
    *************************************************************************
    * Resolve the ambiquity cause by multiply inheriting 
    * McbSmartDestroy<>::McbIsValid()
    *************************************************************************
    */
    bool McbIsValid() const { return McbSmartDestroyMappedFile::McbIsValid(); }
    
   /*
    *************************************************************************
    * Operator overloads for obtaining the contained memory
    *************************************************************************
    */
    operator LPBYTE () 
        { return (unsigned char *)McbSmartDestroyMappedFile::m_type; }

    operator const LPBYTE() const 
        { return (unsigned char *)McbSmartDestroyMappedFile::m_type; }

    operator LPTSTR() 
        { return (LPTSTR)McbSmartDestroyMappedFile::m_type; }

    operator LPCTSTR() const 
        { return (LPCTSTR)McbSmartDestroyMappedFile::m_type; }

   /*
    *************************************************************************
    * Return size of allocated memory
    *************************************************************************
    */
    DWORD McbGetSizeLow() const { return m_dwSizeLow; }
    DWORD McbGetSizeHigh() const { return m_dwSizeHigh; }

protected:
   /*
    *************************************************************************
    * Members
    *************************************************************************
    */
    DWORD m_dwSizeLow; 
    DWORD m_dwSizeHigh; 
};

/**
 ****************************************************************************
 * <P> Smart class for Construction/Destruction of registry hkeys.  
 * Do not use this class directly, instead use the typedef at the bottom of 
 * this file.
 * After construction use McbIsValid() to check whether the object has been
 * successfully initialised </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *    3rd July          2000     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n = 0> class McbSmartHKEYImpl : public McbSmartDestroyHKEY
{
public:
   /*
    *************************************************************************
    * Constructor - specifying false for the bOpen parameter indicates that
    * the key will be created if it does not exist.
    *************************************************************************
    */
    McbSmartHKEYImpl(HKEY hKey, LPCTSTR lpSubKey, bool bOpen = false, 
        LPTSTR lpClass = NULL, DWORD dwOptions = REG_OPTION_NON_VOLATILE, 
        REGSAM samDesired = KEY_ALL_ACCESS, 
        LPSECURITY_ATTRIBUTES lpSec = NULL)
        : m_dwDisposition(0)
    {
        if (bOpen)
        {
           /*
            *****************************************************************
            * Attempt to open the registry key
            *****************************************************************
            */
            if (ERROR_SUCCESS == ::RegOpenKeyEx(hKey, lpSubKey, 0, 
                samDesired, &m_type))
            {
                m_dwDisposition = REG_OPENED_EXISTING_KEY;
            }
        }
        else
        {
           /*
            *****************************************************************
            * Attempt to create the key
            *****************************************************************
            */
            ::RegCreateKeyEx(hKey, lpSubKey, 0, lpClass, dwOptions, 
                samDesired, lpSec, &m_type, &m_dwDisposition);
        }
    }

   /*
    *************************************************************************
    * Return how the key was created.
    *************************************************************************
    */
    DWORD McbGetDisposition() const { return m_dwDisposition; }

protected:
   /*
    *************************************************************************
    * Members
    *************************************************************************
    */
    DWORD m_dwDisposition;
};

/**
 ****************************************************************************
 * <P> Smart class for Construction/Destruction of IO completion ports.  
 * Do not use this class directly, instead use the typedef at the bottom of 
 * this file.
 * After construction use McbIsValid() to check whether the object has been
 * successfully initialised </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *    3rd July          2000     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n = 0> class McbSmartIOPortImpl : public McbSmartDestroyHANDLE
{
public:
   /*
    *************************************************************************
    * Constructor 
    *************************************************************************
    */
    McbSmartIOPortImpl(HANDLE hFile = INVALID_HANDLE_VALUE,
        HANDLE hExistingPort = NULL, ULONG CompletionKey = 0,
        DWORD NumberOfConcurrentThreads = 0)
    {
        m_type = ::CreateIoCompletionPort(hFile, hExistingPort, 
            CompletionKey, NumberOfConcurrentThreads);
    }
};

/**
 ****************************************************************************
 * <P> Smart class for Construction/Destruction of windows critical sections.  
 * Do not use this class directly, instead use the typedef at the bottom of 
 * this file or alternatively use the McbSMARTCS and McbIMPLEMENTSMARTCS macros
 * defined below for extra logging useful when searching for deadlocks.  
 * Critical sections break the McbSmartDestroy model because they deal with a 
 * pointer.  </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *    22nd June          2000     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n=0> class McbSmartCSImpl
{    
public:
   /*
    *************************************************************************
    * Constructor - initialise type
    *************************************************************************
    */
    McbSmartCSImpl()
    {
#ifdef _DEBUG
        try
        {
            ::InitializeCriticalSection(&m_cs);
        }
        catch(...)
        {
            McbTRACE((McbTRACESMARTCLEANUPDEADLOCKS, 
				_T("%s(%d): [%d] Exception thrown! ")
				_T("(McbSmartCSImpl::McbSmartCSImpl())\n"),
				_T(__FILE__), __LINE__, ::GetCurrentThreadId()))
        }
#else //_DEBUG
        ::InitializeCriticalSection(&m_cs);
#endif //_DEBUG
    }
            
   /*
    *************************************************************************
    * Destructor calls cleanup function
    *************************************************************************
    */
    virtual ~McbSmartCSImpl()
    {
#ifdef _DEBUG
        try
        {
			::DeleteCriticalSection(&m_cs);
        }
        catch(...)
        {
            McbTRACE((McbTRACESMARTCLEANUPDEADLOCKS, 
				_T("%s(%d): [%d] Exception thrown! ")
				_T("(McbSmartCSImpl::~McbSmartCSImpl())\n"),
				_T(__FILE__), __LINE__, ::GetCurrentThreadId()))
        }
#else //_DEBUG
		::DeleteCriticalSection(&m_cs);
#endif //_DEBUG        
    }
     
   /*
    *************************************************************************
    * Operator to obtain the type
    *************************************************************************
    */
    operator LPCRITICAL_SECTION() { return &m_cs; }

protected:
   /*
    *************************************************************************
    * Members
    *************************************************************************
    */
    CRITICAL_SECTION m_cs;
};

/**
 ****************************************************************************
 * <P> Smart class for Construction/Destruction of windows critical sections
 * with extra logging.
 * Do not use this class directly, instead use the typedef at the bottom of 
 * this file.  Critical sections break the McbSmartDestroy model because they
 * deal with a pointer.</P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *    22nd June          2000     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n=0> class McbTraceCSImpl
{    
public:
   /*
    *************************************************************************
    * Constructor - initialise type
    *************************************************************************
    */
    McbTraceCSImpl(LPCTSTR lpszUsage) : m_lpszUsage(lpszUsage)
    {
        try
        {
            ::InitializeCriticalSection(&m_cs);

			McbTRACE((McbTRACESMARTCLEANUPDEADLOCKS, 
				_T("%s(%d): [%d] %s critical section created\n"),
				_T(__FILE__), __LINE__, ::GetCurrentThreadId(), m_lpszUsage))				
        }
        catch(...)
        {
            McbTRACE((McbTRACESMARTCLEANUPDEADLOCKS, 
				_T("%s(%d): [%d] Exception thrown! ")
				_T("(McbTraceCSImpl::McbTraceCSImpl())\n"),
				_T(__FILE__), __LINE__, ::GetCurrentThreadId()))
        }
    }
            
   /*
    *************************************************************************
    * Destructor calls cleanup function
    *************************************************************************
    */
    virtual ~McbTraceCSImpl()
    {
        try
        {
			::DeleteCriticalSection(&m_cs);

			McbTRACE((McbTRACESMARTCLEANUPDEADLOCKS, 
				_T("%s(%d): %s critical section destroyed\n"),
				_T(__FILE__), __LINE__, m_lpszUsage))				

        }
        catch(...)
        {
            McbTRACE((McbTRACESMARTCLEANUPDEADLOCKS, 
				_T("%s(%d): [%d] Exception thrown! ")
				_T("(McbTraceCSImpl::~McbTraceCSImpl())\n"),
				_T(__FILE__), __LINE__, ::GetCurrentThreadId()))
        }
    }
     
   /*
    *************************************************************************
    * Operator to obtain the type
    *************************************************************************
    */
    operator LPCRITICAL_SECTION() { return &m_cs; }

	LPCTSTR McbGetUsage() const { return m_lpszUsage; }

protected:
   /*
    *************************************************************************
    * Members
    *************************************************************************
    */
    CRITICAL_SECTION	m_cs;
	LPCTSTR				m_lpszUsage;
};

typedef McbTraceCSImpl<> McbTraceCS;

/*
 ****************************************************************************
 * DEBUG version with tracing on allow extra logging for the critical section
 ****************************************************************************
 */
#if defined(_DEBUG) && defined(McbTRACESMARTCLEANUPDEADLOCKS)
	#pragma message("Using TRACE critical sections")
	#define McbSMARTCSDECLARE(cs)				McbTraceCS cs
	#define McbSMARTCSIMPLEMENT(cs, usage)		McbTraceCS cs(usage)	
	#define McbSMARTCSINIT(cs, usage)			cs(usage)	
#else //_DEBUG
	#pragma message("Using Normal critical sections")
	#define McbSMARTCSDECLARE(cs)				McbSmartCS cs
	#define McbSMARTCSIMPLEMENT(cs, usage)		McbSmartCS cs
	#define McbSMARTCSINIT(cs, usage)			cs()	

#endif //_DEBUG

/**
 ****************************************************************************
 * <P> Class for automatically locking/unlocking a critical section.
 * Do not use this class directly, instead use the typedef at the bottom of 
 * this file.</P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *    3rd July          2000     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n = 0> class McbAutoCSImpl
{
public:
   /*
    *************************************************************************
    * Constructor attempts to obtain lock
    *************************************************************************
    */
#if defined(McbTRACESMARTCLEANUPDEADLOCKS) && defined(_DEBUG)
    McbAutoCSImpl(LPCRITICAL_SECTION pCS) : m_pCS(pCS), m_pTraceCS(NULL)
#else //#if defined(McbTRACESMARTCLEANUPDEADLOCKS) && defined(_DEBUG)
	McbAutoCSImpl(LPCRITICAL_SECTION pCS) : m_pCS(pCS)
#endif //#if defined(McbTRACESMARTCLEANUPDEADLOCKS) && defined(_DEBUG)
    {
#ifdef _DEBUG
        try
        {
			McbTRACE((McbTRACESMARTCLEANUPDEADLOCKS, 
				_T("%s(%d): [%d] Waiting for critical section 0x%08X ")
				_T("(McbAutoCSImpl::McbAutoCSImpl())\n"),
				_T(__FILE__), __LINE__, ::GetCurrentThreadId(),
				m_pCS))

			::EnterCriticalSection(m_pCS);

			McbTRACE((McbTRACESMARTCLEANUPDEADLOCKS, 
				_T("%s(%d): [%d] Aquired critical section 0x%08X ")
				_T("(McbAutoCSImpl::McbAutoCSImpl())\n"),
				_T(__FILE__), __LINE__, ::GetCurrentThreadId(),
				m_pCS))
        }
        catch(...)
        {
            McbTRACE((McbTRACESMARTCLEANUPDEADLOCKS, 
				_T("%s(%d): [%d] Exception thrown! ")
				_T("(McbAutoCSImpl::McbAutoCSImpl())\n"),
				_T(__FILE__), __LINE__, ::GetCurrentThreadId()))
        }
#else //_DEBUG
		::EnterCriticalSection(m_pCS);
#endif //_DEBUG
    }

/*
 ****************************************************************************
 * If DEBUG version and tracing required then we may require to use version
 * of critical section with extra logging.
 ****************************************************************************
 */
#if defined(McbTRACESMARTCLEANUPDEADLOCKS) && defined(_DEBUG)
   /*
    *************************************************************************
    * Constructor for trace type of critical section
    *************************************************************************
    */
	McbAutoCSImpl(McbTraceCS &cs) : m_pTraceCS(&cs)
	{
        try
        {
			McbTRACE((McbTRACESMARTCLEANUPDEADLOCKS, 
				_T("%s(%d): [%d] Waiting for %s critical section ")
				_T("(McbAutoCSImpl::McbAutoCSImpl())\n"),				
				_T(__FILE__), __LINE__, ::GetCurrentThreadId(),
				m_pTraceCS->McbGetUsage()))

			::EnterCriticalSection(*m_pTraceCS);

			McbTRACE((McbTRACESMARTCLEANUPDEADLOCKS, 
				_T("%s(%d): [%d] Aquired %s critical section ")
				_T("(McbAutoCSImpl::McbAutoCSImpl())\n"),
				_T(__FILE__), __LINE__, ::GetCurrentThreadId(),
				m_pTraceCS->McbGetUsage()))
        }
        catch(...)
        {
            McbTRACE((McbTRACESMARTCLEANUPDEADLOCKS, 
				_T("%s(%d): [%d] Exception thrown while ")
				_T("entering %s critical section! ")
				_T("(McbAutoCSImpl::McbAutoCSImpl())\n"),
				_T(__FILE__), __LINE__, ::GetCurrentThreadId(),
				m_pTraceCS->McbGetUsage()))
        }
	}
#endif //defined(McbTRACESMARTCLEANUPDEADLOCKS) && defined(_DEBUG)

   /*
    *************************************************************************
    * Destructor releases lock.
    *************************************************************************
    */
    ~McbAutoCSImpl()
    {
#if defined(McbTRACESMARTCLEANUPDEADLOCKS) && defined(_DEBUG)
		if (m_pTraceCS)
		{
			try
			{
				::LeaveCriticalSection(*m_pTraceCS);

				McbTRACE((McbTRACESMARTCLEANUPDEADLOCKS, 
					_T("%s(%d): [%d] Released %s critical section ")
					_T("(McbAutoCSImpl::~McbAutoCSImpl())\n"),
					_T(__FILE__), __LINE__, ::GetCurrentThreadId(),
					m_pTraceCS->McbGetUsage()))
			}
			catch(...)
			{
				McbTRACE((McbTRACESMARTCLEANUPDEADLOCKS, 
					_T("%s(%d): [%d] Exception thrown while leaving %s ")
					_T("critical section! ")
					_T("(McbAutoCSImpl::~McbAutoCSImpl())\n"),
					_T(__FILE__), __LINE__, ::GetCurrentThreadId(),
					m_pTraceCS->McbGetUsage()))
			}
		}
		else
#endif //#if defined(McbTRACESMARTCLEANUPDEADLOCKS) && defined(_DEBUG)

#ifdef _DEBUG
		{
			try
			{
				::LeaveCriticalSection(m_pCS);

				McbTRACE((McbTRACESMARTCLEANUPDEADLOCKS, 
					_T("%s(%d): [%d] Released critical section 0x%08X ")
					_T("(McbAutoCSImpl::~McbAutoCSImpl())\n"),
					_T(__FILE__), __LINE__, ::GetCurrentThreadId(),
					m_pCS))

			}
			catch(...)
			{
				McbTRACE((McbTRACESMARTCLEANUPDEADLOCKS, 
					_T("%s(%d): [%d] Exception thrown! ")
					_T("(McbAutoCSImpl::~McbAutoCSImpl())\n"),
					_T(__FILE__), __LINE__, ::GetCurrentThreadId()))
			}
		}
#else //_DEBUG
		::LeaveCriticalSection(m_pCS);
#endif //_DEBUG
    }

protected:
   /*
    *************************************************************************
    * Members
    *************************************************************************
    */
    LPCRITICAL_SECTION	m_pCS;

/*
 ****************************************************************************
 * DEBUG version with tracing may require trace version of critical section
 ****************************************************************************
 */
#if defined(McbTRACESMARTCLEANUPDEADLOCKS) && defined(_DEBUG)
	McbTraceCS			*m_pTraceCS;
#endif //#if defined(McbTRACESMARTCLEANUPDEADLOCKS) && defined(_DEBUG)
};


/**
 ****************************************************************************
 * <P> Class for defining the behaviour for automatically aquiring/releasing 
 * a windows synchonisation handle.  Do not use this class directly, it is 
 * used as a base class for other implementable automatic template classes.
 * </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *    3rd July          2000     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n=0> class McbAutoImpl
{
public:
   /*
    *************************************************************************
    * Constructor attempts to obtain object - specify bAlertable to be true 
    * if you require the wait to failed if the system queues an I/O 
    * completion routine or APC - if this does occur then McbIsAlertable() will
    * return true.  See ::WaitForSingleObjectEx() for more details.
    *************************************************************************
    */
    McbAutoImpl(HANDLE hObject, DWORD dwTimeout, bool bAlertable) 
     : m_hObject(hObject)
    {
        m_dwWait = ::WaitForSingleObjectEx(m_hObject, dwTimeout, bAlertable);
    }

   /*
    *************************************************************************
    * Check the status of attempting to aquire the object
    *************************************************************************
    */
    inline bool McbIsSignalled() const { return WAIT_OBJECT_0 == m_dwWait; }
    inline bool McbIsAbandoned() const { return WAIT_ABANDONED == m_dwWait; }
    inline bool McbIsTimedOut() const { return WAIT_TIMEOUT == m_dwWait; }
    inline bool McbIsFailed() const { return WAIT_FAILED == m_dwWait; }
    inline bool McbIsAlertable() const 
        { return WAIT_IO_COMPLETION == m_dwWait;}

protected:
   /*
    *************************************************************************
    * Members
    *************************************************************************
    */
    HANDLE    m_hObject;
    DWORD    m_dwWait;
};

/**
 ****************************************************************************
 * <P> Class for automatically locking/unlocking a mutex.
 * Do not use this class directly, instead use the typedef at the bottom of 
 * this file.</P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *    3rd July          2000     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n = 0> class McbAutoMutexImpl : public McbAutoImpl<>
{
public:
   /*
    *************************************************************************
    * Constructor attempts to obtain mutex via base class.
    *************************************************************************
    */
    McbAutoMutexImpl(HANDLE hMutex, DWORD dwTimeout = INFINITE, 
        bool bAlertable = false)
        : McbAutoImpl<>(hMutex, dwTimeout, bAlertable) {}

   /*
    *************************************************************************
    * Destructor releases mutex if it was successfully obtained.
    *************************************************************************
    */
    ~McbAutoMutexImpl()
    {
        if (McbIsSignalled())
        {
            ::ReleaseMutex(m_hObject);
        }        
    }
};

/**
 ****************************************************************************
 * <P> Class for automatically aquiring/releasing a semaphore.
 * Do not use this class directly, instead use the typedef at the bottom of 
 * this file.</P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *    3rd July          2000     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n = 0> class McbAutoSemaphoreImpl : public McbAutoImpl<>
{
public:
   /*
    *************************************************************************
    * Constructor attempts to obtain semaphore via base class
    *************************************************************************
    */
    McbAutoSemaphoreImpl(HANDLE hSemaphore, DWORD dwTimeout = INFINITE,
        bool bAlertable = false) 
        : McbAutoImpl<>(hSemaphore, dwTimeout, bAlertable) {}

   /*
    *************************************************************************
    * Destructor releases semaphore if it was successfully obtained.
    *************************************************************************
    */
    ~McbAutoSemaphoreImpl()
    {
        if (McbIsSignalled())
        {
            LONG lPrevCount;
            ::ReleaseSemaphore(m_hObject, 1, &lPrevCount);
        }        
    }
};

/**
 ****************************************************************************
 * <P> Class for automatically waiting in a windows event.
 * Do not use this class directly, instead use the typedef at the bottom of 
 * this file.</P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *    3rd July          2000     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n = 0> class McbAutoEventImpl : public McbAutoImpl<>
{
public:
   /*
    *************************************************************************
    * Constructor attempts to wait for an event via base class.
    * If bResetEvent is true and the event successfully became signalled then
    * the event will be reset in the destructor.
    *************************************************************************
    */
    McbAutoEventImpl(HANDLE hEvent, DWORD dwTimeout = INFINITE,
        bool bAlertable = false, bool bResetEvent = false) 
        :    m_bResetEvent(bResetEvent), 
            McbAutoImpl<>(hEvent, dwTimeout, bAlertable) {}

   /*
    *************************************************************************
    * Destructor resets event IF it became signalled and bResetEvent was true 
    * in the constructor 
    *************************************************************************
    */
    ~McbAutoEventImpl()
    {
        if (McbIsSignalled() && m_bResetEvent)
        {
            ::ResetEvent(m_hObject);
        }        
    }

protected:
   /*
    *************************************************************************
    * Members
    *************************************************************************
    */
    bool m_bResetEvent;
};


/**
 ****************************************************************************
 * <P> Simple class to thread safely implement a counter increment/decrement 
 * when the class is constructed/destructed (respectively).  This could be 
 * used to implement a server lifetime for example.  
 * Do not implement this class directly, instead use the typedef below the
 * class.  Using a template class in this way eliminates the need for a cpp
 * file but no other template functionality is used.
 * Note that the counter passed in must be on a 32 bit boundary.  This value
 * will be modified with ::InterlockedXXXX() which fail on a multi-processor 
 * x86 or non x86 platform if this is not on a 32 bit boundary.</P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *    1st September     2000     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n = 0> class McbAutoCounterImpl
{
public:
   /*
    *************************************************************************
    * Constructor takes reference to counter to be incremented which should 
    * be on a 32 bit boundary (see class header).
    * The following code would ensure g_lCounter is on a 32 bit boundary
    * (VC++ only):
    * #pragma pack(push, 4)    
    * LONG g_lCounter = 0;
    * #pragma pack(pop)    
    *************************************************************************
    */
    McbAutoCounterImpl(long &lCounter) : m_lCounter(lCounter)
    {
       /*
        *********************************************************************
        * Assert if the counter isn't on a 32 bit boundary
        *********************************************************************
        */
        assert(((long)&lCounter) % 4 == 0);

        ::InterlockedIncrement(&m_lCounter);
    }

   /*
    *************************************************************************
    * Decrement the counter.
    *************************************************************************
    */
    ~McbAutoCounterImpl()
    {
        ::InterlockedDecrement(&m_lCounter);
    }

protected:
   /*
    *************************************************************************
    * One and only member
    *************************************************************************
    */
    long &m_lCounter;
};

/**
 ****************************************************************************
 * <P> Template class to load a named resource as a library.  Use the typedef
 * (McbLoadLibrary) rather than the template class itself. </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *	2nd April     	2001	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n = 0> class McbLoadLibraryImpl
{
public:
   /*
    *************************************************************************
    * Construction/Destruction
    *************************************************************************
    */
	McbLoadLibraryImpl(LPCTSTR lpszName = NULL) : m_hLibrary(NULL)
	{
		if (lpszName) McbLoadLibrary(lpszName);		
	}

	~McbLoadLibraryImpl() { McbClose(); }

   /*
    *************************************************************************
    * Attempt to load the library associated with the given name
    *************************************************************************
    */
	HMODULE McbLoad(LPCTSTR lpszName)
	{
		McbClose();

		m_hLibrary = ::LoadLibraryEx(lpszName, NULL, 
			LOAD_LIBRARY_AS_DATAFILE);

		return m_hLibrary;
	}

   /*
    *************************************************************************
    * Access the loaded library instance
    *************************************************************************
    */
	operator HMODULE const() const { return m_hLibrary; }
	operator HMODULE () { return m_hLibrary; }

protected:
   /*
    *************************************************************************
    * Helper function
    *************************************************************************
    */
	void McbClose()
	{
		if (m_hLibrary && ::FreeLibrary(m_hLibrary)) m_hLibrary = NULL;
	}

   /*
    *************************************************************************
    * Members
    *************************************************************************
    */
	HMODULE m_hLibrary;
};

/**
 ****************************************************************************
 * <P> Template class to load a named resource as a library.  Use the typedef
 * (McbLoadLibrary2) rather than the template class itself. </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *	2nd April     	2001	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n = 0> class McbLoadLibrary2Impl
{
public:
   /*
    *************************************************************************
    * Construction/Destruction
    *************************************************************************
    */
	McbLoadLibrary2Impl(LPCTSTR lpszName = NULL) : m_hLibrary(NULL)
	{
		if (lpszName) McbLoad(lpszName);		
	}

	McbLoadLibrary2Impl(LPCTSTR lpszName, DWORD dwFlags) : m_hLibrary(NULL)
	{
		if (lpszName) McbLoad(lpszName, dwFlags);		
	}

	~McbLoadLibrary2Impl() { McbClose(); }

   /*
    *************************************************************************
    * Attempt to load the library associated with the given name
    *************************************************************************
    */
	HMODULE McbLoad(LPCTSTR lpszName, DWORD dwFlags = 0)
	{
		McbClose();

		m_hLibrary = ::LoadLibraryEx(lpszName, NULL, dwFlags);
			/*LOAD_LIBRARY_AS_DATAFILE);*/

		return m_hLibrary;
	}

	HMODULE McbLoadW(LPCWSTR lpszName, DWORD dwFlags = 0)
	{
		McbClose();

		m_hLibrary = ::LoadLibraryExW(lpszName, NULL, dwFlags);
			/*LOAD_LIBRARY_AS_DATAFILE);*/

		return m_hLibrary;
	}

	HMODULE McbLoadA(LPCSTR lpszName, DWORD dwFlags = 0)
	{
		McbClose();

		m_hLibrary = ::LoadLibraryExA(lpszName, NULL, dwFlags);
			/*LOAD_LIBRARY_AS_DATAFILE);*/

		return m_hLibrary;
	}

   /*
    *************************************************************************
    * Access the loaded library instance
    *************************************************************************
    */
	operator HMODULE const() const { return m_hLibrary; }
	operator HMODULE () { return m_hLibrary; }

protected:
   /*
    *************************************************************************
    * Helper function
    *************************************************************************
    */
	void McbClose()
	{
		if (m_hLibrary && ::FreeLibrary(m_hLibrary)) m_hLibrary = NULL;
	}

   /*
    *************************************************************************
    * Members
    *************************************************************************
    */
	HMODULE m_hLibrary;
};

/**
 ****************************************************************************
 * <P> Template class which allows access to an instance of a class either by
 * refering to an existing instance or creating and owning a new instance.
 * If the default constructor is used then an instance will be created on the
 * heap - the reference operator overloads will return the contents of the 
 * pointer to the owned member.
 * If the constructor which takes the class in as a parameter is used then
 * the pointer will use the address of this. the reference operator overloads
 * will now return the contents of this parameter and will not be responsible
 * for deleting the memory and associated resource.  
 *
 * A default constructor is required for the template parameter class for 
 * this to work.  </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *	4th June      	2001	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <class theClass>
class McbAutoRef
{
public:
   /*
    *************************************************************************
    * Constructor creates a new member
    *************************************************************************
    */
	McbAutoRef() : m_bOwn(true)
	{
		m_pValue = new theClass;
	}

   /*
    *************************************************************************
    * Constructor which points to the member passed in as a parameter 
    *************************************************************************
    */
	McbAutoRef(theClass &other) : m_bOwn(false), m_pValue(&other) {}

   /*
    *************************************************************************
    * Destructor deletes the class if it owns it
    *************************************************************************
    */
	~McbAutoRef()
	{
		if (m_bOwn)
		{
			delete m_pValue;
		}
	}
		
   /*
    *************************************************************************
    * Accessors
    *************************************************************************
    */
	operator theClass &() { return *m_pValue; }
	operator const theClass & () const { return *m_pValue; }
	
protected:
   /*
    *************************************************************************
    * Members
    *************************************************************************
    */
	theClass	*m_pValue;
	bool		m_bOwn;
};

/**
 ****************************************************************************
 * <P> Template class with static function to wait for a group of objects to
 * become signalled.  It expands on ::WaitForMultipleObjects() because 
 * ::WaitForMultipleObjects() only allows MAXIMUM_WAIT_OBJECTS number of
 * handles to be waited upon.  Use the typedef at the bottom of the file.
 * </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *	4th June      	2001	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> class McbThreadSynchroniseImpl
{
public:
   /*
    *************************************************************************
    * Wait for all of the events to become signalled
    *************************************************************************
    */
	static DWORD McbWaitForAllObjects(DWORD dwCount, 
		const HANDLE * lpObjects, DWORD dwTimeout = INFINITE)
	{
       /*
        *********************************************************************
        * Assume the worst
        *********************************************************************
        */
		DWORD dwResult = WAIT_TIMEOUT;

		DWORD dwTimeLeft = dwTimeout;
		DWORD dwTimeStarted = ::GetTickCount();
		
       /*
        *********************************************************************
        * Loop until all the events have become signalled or they timed out
        *********************************************************************
        */
		while(true)
		{
           /*
            *****************************************************************
            * Calculate time left to wait for the objects
            *****************************************************************
            */
			if (dwTimeLeft != INFINITE)
			{
               /*
                *************************************************************
                * Exit the loop if we have run out of time
                *************************************************************
                */
				int nTemp = ::GetTickCount() - (int)dwTimeStarted;

				if ((int)dwTimeLeft < nTemp)
				{
					break;
				}

				dwTimeLeft -= (DWORD)nTemp;
			}

           /*
            *****************************************************************
            * Calculate number of objects to wait for
            *****************************************************************
            */
			DWORD dwCount2 = (dwCount > MAXIMUM_WAIT_OBJECTS)
				? MAXIMUM_WAIT_OBJECTS : dwCount;

           /*
            *****************************************************************
            * Wait for the objects to become signalled
            *****************************************************************
            */
			DWORD dwTemp = ::WaitForMultipleObjects(dwCount2, lpObjects, 
				TRUE, dwTimeLeft);
			
           /*
            *****************************************************************
            * Decrement the number of handles left to wait for.
            *****************************************************************
            */
			dwCount -= dwCount2;

           /*
            *****************************************************************
            * If the group of handles became signalled
            *****************************************************************
            */
			if (dwTemp == WAIT_OBJECT_0)
			{
               /*
                *************************************************************
                * If there are no more handles to wait for then we have a 
				* result
                *************************************************************
                */
				if (dwCount == 0)
				{
                   /*
                    *********************************************************
                    * Set the result and exit the loop
                    *********************************************************
                    */
					dwResult = WAIT_OBJECT_0;
					break;
				}
               /*
                *************************************************************
                * If there are still handles to wait for
                *************************************************************
                */
                else 
				{
                   /*
                    *********************************************************
                    * Increase the handle pointer to point to the next group 
					* of handles 
                    *********************************************************
                    */
					lpObjects += dwCount2;
				}
			}
           /*
            *****************************************************************
            * If the wait did not result in all objects becoming signalled
            *****************************************************************
            */
            else 
			{
               /*
                *************************************************************
                * Set the result and exit the loop
                *************************************************************
                */
				dwResult = dwTemp;
				break;
			}
		}

		return dwResult;
	}
};

/**
 ****************************************************************************
 * <P> Template class to implement thread safe logging file (providing the 
 * appropriate locking functions are called).  Use the typedef at the bottom
 * of the file rather than this template class.  </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *	12th June      	2001	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> class McbLogFileImpl : public McbSmartDestroyHANDLE
{
public:
   /*
    *************************************************************************
    * Attempt to open a given file
    *************************************************************************
    */
	bool McbOpen(LPCTSTR lpszFileName)
	{
       /*
        *********************************************************************
        * Assume the worst
        *********************************************************************
        */
		bool bResult = true;

		assert(lpszFileName);

       /*
        *********************************************************************
        * Ensure any previous file is closed
        *********************************************************************
        */
		McbClose();

       /*
        *********************************************************************
        * Open the file for exclusive write access (allowing shared read).
        *********************************************************************
        */
		McbSmartDestroyHANDLE::m_type = ::CreateFile(lpszFileName, 
			GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);

		if (McbSmartDestroyHANDLE::McbIsValid())
		{
           /*
            *****************************************************************
            * Seek to the end of the file
            *****************************************************************
            */
			::SetFilePointer(McbGetFile(), 0, NULL, FILE_END);

			bResult = true;
		}

		return bResult;
	}

   /*
    *************************************************************************
    * Access the file handle
    *************************************************************************
    */
	HANDLE McbGetFile() { return McbSmartDestroyHANDLE::m_type; }

   /*
    *************************************************************************
    * Close the file (this is done automatically in McbSmartDestroyHANDLE's 
	* destructor).
    *************************************************************************
    */
	inline void McbClose() { McbSmartDestroyHANDLE::McbFree(); }

   /*
    *************************************************************************
    * Lock/Unlock access to the file
    *************************************************************************
    */
	void McbLock() { ::EnterCriticalSection(m_cs); }
	void McbUnLock() { ::LeaveCriticalSection(m_cs); }

protected:
   /*
    *************************************************************************
    * Members
    *************************************************************************
    */
	McbSmartCSImpl<>	m_cs;
};

/**
 ****************************************************************************
 * <P> Template class to shared a FIXED resource.  Each resource will only be
 * contained once in memory.  When the copy constructor or assignment 
 * operator is used for an existing resource then the object will point to a 
 * single instance of the object.  Each resource will have a reference count
 * which will dictate when the actual resource is deleted.  
 * Note that this is for FIXED resources only, ie if the resource changed 
 * then every object refering to the resource would point to the modified 
 * resource.  </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *	27th September 	2001	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <class resource> class McbSharedResource
{
private:
   /*
    *************************************************************************
    * Nested class to contain the single instance of the resource.  This 
	* manages a reference count for the resource which dictates when the
	* resource should be deleted
    *************************************************************************
    */
	class McbType
	{	
	public:
		McbType(resource *pType) : m_nRefCount(1), m_pType(pType) {}

		~McbType() 
		{
			if (m_pType)
			{
				delete m_pType;
			}
		}
		
		int			m_nRefCount;
		resource 	*m_pType;
	
#ifdef _DEBUG
	private:
       /*
        *********************************************************************
        * Make sure we aren't calling anything implicitly
        *********************************************************************
        */
		McbType(McbType &other) {};
		const McbType & operator=(const McbType &other) { return *this; }
#endif //_DEBUG
	};

public:
   /*
    *************************************************************************
    * Constructor which takes a copy of the resource .  The resource will now 
	* have a reference count of 1.
    *************************************************************************
    */
	explicit McbSharedResource(const resource &t)
	{
		resource * pType = new resource;
		*pType = t;

		m_pType = new McbType(pType);
	}

   /*
    *************************************************************************
    * Default constructor.
    *************************************************************************
    */
	McbSharedResource()
	{
		m_pType = new McbType(new resource);
	}

   /*
    *************************************************************************
    * Copy constructor will have a reference to the contained resource.
    *************************************************************************
    */
	McbSharedResource(const McbSharedResource &other) : m_pType(NULL)
	{
		*this = other;
	}

   /*
    *************************************************************************
    * Attach to a given resource.  This resource is now owned by us and will
	* have a reference count of one.
    *************************************************************************
    */
	void McbAttach(resource *pT)
	{
		McbClean();

		m_pType = new McbType(pT);
	}

   /*
    *************************************************************************
    * USE WITH CAUTION - this will detach the contained resource and pass it 
	* back to the client.  A default new resource will be created with the
	* reference count it had before.  Note that ALL objects which pointed at
	* the old resource will now point at the new default object.
	* You probably only want to call this function when the reference count
	* is one.
    *************************************************************************
    */
	resource * McbDetach()
	{
       /*
        *********************************************************************
        * Cache the contained resource so we cant return it to the punter
        *********************************************************************
        */
		resource * pType = m_pType->m_pType;
		
       /*
        *********************************************************************
        * Create a new default resource
        *********************************************************************
        */
		m_pType->m_pType = new resource;

		return pType;
	}

   /*
    *************************************************************************
    * Destructor
    *************************************************************************
    */
	virtual ~McbSharedResource()
	{
		McbClean();
	}

   /*
    *************************************************************************
    * Assignment operator will use a reference count to the existing 
	* resource.
    *************************************************************************
    */
	const McbSharedResource & operator=(const McbSharedResource &other)
	{
		if (&other != this)
		{
			McbClean();

			m_pType = other.m_pType;
			m_pType->m_nRefCount++;
		}

		return *this;
	}

   /*
    *************************************************************************
    * Assignment operator which takes a copy of the given resource.  The 
	* resource will now have a reference count of 1.
    *************************************************************************
    */
	const McbSharedResource & operator=(resource &t)
	{
		McbClean();

		resource * pType = new resource;
		*pType = t;

		m_pType = new McbType(pType);

		return *this;
	}

   /*
    *************************************************************************
    * Access the contained resource.
    *************************************************************************
    */
	operator resource() { return *(m_pType->m_pType); }
	operator const resource&() const { return *(m_pType->m_pType); }

   /*
    *************************************************************************
    * DONT ALLOW ACCESS TO NON CONSTANT REFERENCE as this could potentially 
	* change the underlying resource for ALL objects refering to it).
    *************************************************************************
    */
	/*operator resource&() { return *(m_pType->m_pType); }*/

   /*
    *************************************************************************
    * Less than operator so we can include the class in collections
    *************************************************************************
    */
	bool operator<(const McbSharedResource &other) const
	{		
		return ((const resource&)*this) < ((const resource&)other);
	}

   /*
    *************************************************************************
    * Operator equals
    *************************************************************************
    */
	bool operator==(const McbSharedResource &other) const
	{
		return ((const resource&)*this) == ((const resource&)other);
	}

   /*
    *************************************************************************
    * Return the reference count
    *************************************************************************
    */
	int McbGetRefCount() const { return m_pType->m_nRefCount; }

protected:

   /*
    *************************************************************************
    * Cleanup code decrements the reference count for the resource and 
	* deletes it if the reference count becomes zero.
    *************************************************************************
    */
	void McbClean()
	{
		if (m_pType)
		{
			m_pType->m_nRefCount--;

			if (m_pType->m_nRefCount == 0)
			{
				delete m_pType;
			}

			m_pType = NULL;
		}
	}

   /*
    *************************************************************************
    * One and only member is a pointer to the object managing the contained 
	* resource which inturn contains the reference count and the actual 
	* resource.
    *************************************************************************
    */
	McbType * m_pType;
};

/**
 ****************************************************************************
 * <P> Template class to monitor registry key changes.  </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *	28th September 	2001	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> class McbRegMonitorImpl
{
public:
   /*
    *************************************************************************
    * Constructor
    *************************************************************************
    */
	McbRegMonitorImpl(bool bPulsedEvent = true, bool bWatchTree = true, 
		DWORD dwFilter = REG_NOTIFY_CHANGE_LAST_SET, 
		HKEY hKeyRoot = HKEY_LOCAL_MACHINE)
	  : m_bWatchTree(bWatchTree), m_dwFilter(dwFilter), m_hKey(NULL),
		m_hKeyRoot(hKeyRoot)
	{
		m_hEvt = ::CreateEvent(NULL, bPulsedEvent == false, FALSE, NULL);
	}

   /*
    *************************************************************************
    * Destructor
    *************************************************************************
    */
	~McbRegMonitorImpl() 
	{ 
		McbCleanup(); 
		::CloseHandle(m_hEvt); 
	}

   /*
    *************************************************************************
    * Returns true if the key has become changed.  Note that when a change 
	* occurs you need to start the monitor again.
    *************************************************************************
    */
	bool McbHasChanged()
	{
		return ::WaitForSingleObject(m_hEvt, 0) == WAIT_OBJECT_0;
	}

   /*
    *************************************************************************
    * Return the event which will become signalled in the case of the key 
	* being changed.  
    *************************************************************************
    */
	HANDLE McbGetChangedEvent() const { return m_hEvt; }

   /*
    *************************************************************************
    * Set the name of the key to watch for changes
    *************************************************************************
    */
	void McbSetKey(LPCTSTR lpszKey)
	{
		assert(lpszKey && *lpszKey);

		m_strKey = lpszKey;

	}

   /*
    *************************************************************************
    * Start monitoring for changes.
    *************************************************************************
    */
	bool McbStartMonitor()
	{
		McbCleanup();

		LONG lResult = ::RegOpenKeyEx(m_hKeyRoot, m_strKey.c_str(), 0, 
			KEY_READ, &m_hKey);

		if (lResult == ERROR_SUCCESS)
		{
			lResult = ::RegNotifyChangeKeyValue(m_hKey, m_bWatchTree == true,
				m_dwFilter, m_hEvt, TRUE);
		}
		else
		{
			m_hKey = NULL;
		}

		return lResult == ERROR_SUCCESS;
	}

// @@protected:

   /*
    *************************************************************************
    * Helper function
    *************************************************************************
    */
	void McbCleanup()
	{
		if (m_hKey)
		{
			::RegCloseKey(m_hKey);
			m_hKey = NULL;
		}

		::ResetEvent(m_hEvt);
	}

   /*
    *************************************************************************
    * Members
    *************************************************************************
    */
	HANDLE						m_hEvt;
	HKEY						m_hKey;
	HKEY						m_hKeyRoot;
	bool						m_bWatchTree;
	DWORD						m_dwFilter;
	std::basic_string<TCHAR>	m_strKey;
};

/**
 ****************************************************************************
 * <P> Template class for SIMPLE string class which allows dynamic appending.
 * This was written because I found an error in the std::basic_string<>
 * template class when dealing with large messages.  </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *	1st October   	2001	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> class McbSimpleStrImpl
{

/*
 ****************************************************************************
 * Some reasonable defaults
 ****************************************************************************
 */
#define McbDEFAULTSIZE	5
#define McbGROWBY		5

public:
   /*
    *************************************************************************
    * Constructor reserves default amount of memory for character storage.
    *************************************************************************
    */
	McbSimpleStrImpl() : m_nReserved(0), m_nSize(0), m_lpsz(NULL)
	{
		McbReserve(McbDEFAULTSIZE);
	}

   /*
    *************************************************************************
    * Cleanup the owned memory in the destructor
    *************************************************************************
    */
	virtual ~McbSimpleStrImpl()
	{
		if (m_lpsz)
		{
			delete [] m_lpsz;
		}
	}

   /*
    *************************************************************************
    * Append characters
    *************************************************************************
    */
	LPCTSTR McbAppend(LPCTSTR lpszAppend, int cbAppend = 0)
	{
		if (lpszAppend)
		{
			if (cbAppend == 0)
			{
				cbAppend = ::_tcslen(lpszAppend);
			}

			int cbRequired = m_nSize + cbAppend;

			McbReserve(cbRequired);

			LPTSTR lpszMarker = m_lpsz + m_nSize;

			::memcpy(lpszMarker,  lpszAppend, 
				sizeof(TCHAR)*cbAppend);

			m_nSize += cbAppend;

			m_lpsz[m_nSize] = 0;
		}

		return m_lpsz;
	}

   /*
    *************************************************************************
    * Append n number of chars
    *************************************************************************
    */
	LPCTSTR McbAppendChar(TCHAR ch, int nNum)
	{
		McbReserve(m_nSize + nNum);

		::_tcsnset(m_lpsz + m_nSize, ch, nNum);

		m_nSize += nNum;
		m_lpsz[m_nSize] = 0;

		return m_lpsz;
	}

   /*
    *************************************************************************
    * Append a converted number as a string.
    *************************************************************************
    */
	LPCTSTR McbAppendNum(long lValue, int nRadix = 10)
	{
		TCHAR szBuffer[20];

		McbReserve(m_nSize + sizeof(szBuffer)-1);

		McbAppend(::_ltot(lValue, szBuffer,	nRadix));

		return m_lpsz;
	}

   /*
    *************************************************************************
    * Reserve some memory
    *************************************************************************
    */
	void McbReserve(int nReserve)
	{
		assert(nReserve);

		if (nReserve > m_nReserved)
		{
			int nGrow = (nReserve - m_nReserved)/
				McbGROWBY + 
				(((nReserve - m_nReserved) % McbGROWBY) 
				? 1 : 0);

			m_nReserved += (nGrow * McbGROWBY);

            LPTSTR lpszNew = new TCHAR[m_nReserved+1];

            if (m_nSize)
            {
                ::memcpy(lpszNew, m_lpsz, sizeof(TCHAR)*m_nSize);
            }

			if (m_lpsz)
			{
				delete [] m_lpsz;
			}

            m_lpsz = lpszNew;
		}
	}

   /*
    *************************************************************************
    * Set the size of the contained string.
    *************************************************************************
    */
	void McbSetSize(int nSize)
	{
		McbReserve(nSize);

		m_lpsz[nSize] = 0;

		m_nSize = nSize;
	}

   /*
    *************************************************************************
    * Accessors
    *************************************************************************
    */
	LPCTSTR McbGetStr() const { return m_lpsz; }
	LPTSTR McbGetStr() { return m_lpsz; }

	int McbGetSize() const { return m_nSize; }
	int McbGetCapacity() const { return m_nReserved; }

protected:
   /*
    *************************************************************************
    * Members
    *************************************************************************
    */
	LPTSTR	m_lpsz;
	int		m_nSize;
	int		m_nReserved;
};

/**
 ****************************************************************************
 * <P> DOS type console utilities.  </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *	7th November  	2001	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> class McbConsoleImpl
{
public:
   /*
    *************************************************************************
    * Turn console echoing off for ::ReadFile() or ::ReadConsole().  Useful
	* for obtaining passwords.
	* See "mk:@MSITStore:d:\MSDN98\98VSa\1033\winbase.chm::/devdoc/live/
	* pdwbase/conchar_7opx.htm" in the MSDN.
    *************************************************************************
    */
	class McbEchoOff
	{
	public:
		McbEchoOff() : m_dwMode(0)
		{
			DWORD dwOld = McbConsoleGet();

			if (dwOld)
			{
				DWORD dwNew = dwOld & ~(ENABLE_LINE_INPUT | 
					ENABLE_ECHO_INPUT); 

				if (McbConsoleSet(dwNew))
				{
					m_dwMode = dwOld;
				}
			}
		}

		~McbEchoOff()
		{
			if (m_dwMode)
			{
				McbConsoleSet(m_dwMode);
			}
		}

		DWORD m_dwMode;
	};

	static DWORD McbConsoleGet()
	{
		DWORD dwResult;
			
		if (::GetConsoleMode(::GetStdHandle(STD_INPUT_HANDLE), &dwResult))
		{
			return dwResult;
		}

		return 0;
	}

	static bool McbConsoleSet(DWORD dwMode)
	{
		return ::SetConsoleMode(::GetStdHandle(STD_INPUT_HANDLE), dwMode) 
			!= FALSE;
	}

   /*
    *************************************************************************
    * Obtain a password from the console.  This disables echoing for stdin so
	* that the password is not shown.  The number of characters obtained is
	* the return value.  For the second parameter this must be the total 
	* length of the output buffer INCLUDING a character for the NULL 
	* terminator.  For example, if a password 20 characters is required then
	* lpszPwd should point to a buffer of 21 characters and cbPwd should be
	* 21.
    *************************************************************************
    */
	static DWORD McbGetPasswordA(LPSTR lpszPwd, DWORD cbPwd)
	{
		McbEchoOff quiet;

		HANDLE hStdIn = ::GetStdHandle(STD_INPUT_HANDLE);
		HANDLE hStdout = ::GetStdHandle(STD_OUTPUT_HANDLE); 

		DWORD dwResult = 0;

		WORD wOldColorAttrs;
		CONSOLE_SCREEN_BUFFER_INFO screenInfo; 

		::GetConsoleScreenBufferInfo(hStdout, &screenInfo);
		wOldColorAttrs = screenInfo.wAttributes; 
		
        while(true)
        {               
            DWORD cbRead;
            char ch;

            if (!::ReadFile(hStdIn, &ch, 1, &cbRead, NULL) || (ch == '\r'))
            {
                break;
            }
            
            lpszPwd[dwResult++] = ch;		

			char chRnd = (rand() % 100) + 1;

			int nChars = chRnd < 50 ? 1 : (chRnd < 95) ? 2 : 3;

			for (int nChar=0; nChar < nChars; nChar++)
			{				
				WORD wColor = (rand() % 0xF) + 1;

				if (::SetConsoleTextAttribute(hStdout, wColor)) 
				{
					DWORD cbWritten;
					WriteFile(hStdout, "X", 1, &cbWritten, NULL);    
				}
			}									

            if (dwResult+1 == cbPwd)
            {
                break;
            }
        }

        lpszPwd[dwResult] = 0;

		::SetConsoleTextAttribute(hStdout, wOldColorAttrs);

		return dwResult;
	}
};

/*
 ****************************************************************************
 * Typedef for ease of use.
 ****************************************************************************
 */
typedef McbConsoleImpl<0> McbConsole;

/*
 ****************************************************************************
 * Typedef for class with static functions to wait for a group of handles
 ****************************************************************************
 */
typedef McbThreadSynchroniseImpl<0>	McbThreadSynchronise;

/*
 ****************************************************************************
 * Typedefs to simplify smart object creation
 ****************************************************************************
 */
typedef McbSmartEventImpl<>			McbSmartEvent;
typedef McbSmartCSImpl<>				McbSmartCS;
typedef McbSmartMutexImpl<>			McbSmartMutex;
typedef McbSmartSemaphoreImpl<>		McbSmartSemaphore;
typedef McbSmartSharedMemImpl<>		McbSmartSharedMem;
typedef McbSmartHKEYImpl<>			McbSmartHKEY;
typedef McbSmartFileImpl<>			McbSmartFile;
typedef McbSmartHeapImpl<>			McbSmartHeap;
typedef McbSmartHeapMemImpl<>		McbSmartHeapMem;
typedef McbSmartServerPipeImpl<>		McbSmartServerPipe;
typedef McbSmartIOPortImpl<>			McbSmartIOPort;

/*
 ****************************************************************************
 * Typedefs for automatically aquiring locks in the constructor and releasing
 * in the destructor
 ****************************************************************************
 */
typedef McbAutoCSImpl<>				McbAutoCS;
typedef McbAutoMutexImpl<>			McbAutoMutex;
typedef McbAutoSemaphoreImpl<>		McbAutoSemaphore;
typedef McbAutoEventImpl<>			McbAutoEvent;

/*
 ****************************************************************************
 * Typedef to automatically thread safely increment/decrement counter in the
 * constructor/destructor (respectively)
 ****************************************************************************
 */
typedef McbAutoCounterImpl<>			McbAutoCounter;

/*
 ****************************************************************************
 * Typedef for ease of use for loading a resource as a library
 ****************************************************************************
 */
typedef McbLoadLibraryImpl<>			McbLoadLibrary;
typedef McbLoadLibrary2Impl<>		McbLoadLibrary2;

/*
 ****************************************************************************
 * Typedef for ease of use for thread safe file logging
 ****************************************************************************
 */
typedef McbLogFileImpl<0>			McbLogFile;

/*
 ****************************************************************************
 * Typedef for ease of use for registry key monitoring
 ****************************************************************************
 */
typedef McbRegMonitorImpl<0>			McbRegMonitor;

/*
 ****************************************************************************
 * Typedef for ease of use for simple string class
 ****************************************************************************
 */
typedef McbSimpleStrImpl<0>			McbSimpleStr;

#endif /*McbSmartCleanup_Included*/

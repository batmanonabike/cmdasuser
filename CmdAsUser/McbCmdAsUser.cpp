// McbCmdAsUser.cpp : Defines the entry point for the console application.
//

/*
 ****************************************************************************
 * Include all necessary include files
 ****************************************************************************
 */
#include <stdio.h>
#include <iostream>
#include <vector>
#include "McbService.hpp"
#include "McbAccessControl2.hpp"
#include "McbFormatError.hpp"
#include "McbSmartCleanup.hpp"
#include "NullSecurityAttributes.h"
#include <tlhelp32.h>

class EveryoneSA : public SECURITY_ATTRIBUTES
{
public:
  EveryoneSA();

  SECURITY_DESCRIPTOR sd;
};

EveryoneSA::EveryoneSA()
{
  ::InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
  ::SetSecurityDescriptorDacl(&sd, TRUE, (PACL)NULL, FALSE);

  nLength = sizeof(SECURITY_ATTRIBUTES);
  lpSecurityDescriptor = &sd;
  bInheritHandle = FALSE;
}

/*
 ****************************************************************************
 * Defines for use with tracing macro (McbTRACE).
 ****************************************************************************
 */
#define McbTRACEGENERAL      0x00000001
#define McbTRACESIDS         0x00000002
#define McbTRACESHAREDMEM    0x00000004
#define McbTRACECOMPLETE     0x00000008
#define McbTRACELOGON        0x00000010

#define McbMAXMEM            1024*10
#define McbSERVICENAME       _T("McbCmdAsUser")
#define McbSHAREDMEM         _T("Global\\McbCmdAsUserMem")
#define McbCOMPLETEDEVENT    _T("Global\\McbCmdAsUserEventComplete")

/*
 ****************************************************************************
 * Some global data to control IPC
 ****************************************************************************
 */
//NullSA         g_sa;
EveryoneSA     g_sa;
McbSmartMutex  g_mutData(_T("Global\\McbCmdAsUserMut"), false, &g_sa);
McbSmartEvent  g_evtData(_T("Global\\McbCmdAsUserEventData"), true, false, &g_sa);

/**
 ****************************************************************************
 * <P> Class to parse the parameters in shared memory.  </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *    6th November      2001     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
class McbParams
{
public:
    McbParams() {}

#define McbMARSHALSTR(lpMem, str)                                           \
    {                                                                       \
        DWORD cbString = (DWORD)str.size();                                 \
        *((DWORD*)lpMem) = cbString;                                        \
        lpMem += sizeof(DWORD);                                             \
                                                                            \
        if (cbString) ::memcpy(lpMem, (LPBYTE)str.data(), cbString);        \
                                                                            \
        lpMem += cbString;                                                  \
    }

   /*
    *************************************************************************
    * Marshal the parameters into memory
    *************************************************************************
    */
    void McbMarshal(LPBYTE lpMem)
    {    
        McbMARSHALSTR(lpMem, m_strUser)
        McbMARSHALSTR(lpMem, m_strDomain)
        McbMARSHALSTR(lpMem, m_strPwd)
        McbMARSHALSTR(lpMem, m_strCmdLine)
    }

#define McbUNMARSHALSTR(lpMem, str)                                          \
    {                                                                       \
        DWORD cbString = *(DWORD*)lpMem;                                    \
        lpMem += sizeof(DWORD);                                             \
                                                                            \
        str.resize(cbString);                                               \
                                                                            \
        if (cbString) ::memcpy((LPBYTE)str.data(), lpMem, cbString);        \
                                                                            \
        lpMem += cbString;                                                  \
    }

   /*
    *************************************************************************
    * Unmarshal the parameters from memory
    *************************************************************************
    */
    void McbUnMarshal(LPBYTE lpMem)
    {
        McbUNMARSHALSTR(lpMem, m_strUser)
        McbUNMARSHALSTR(lpMem, m_strDomain)
        McbUNMARSHALSTR(lpMem, m_strPwd)
        McbUNMARSHALSTR(lpMem, m_strCmdLine)
    }

	bool McbIsSystemAccount() const
	{
		if (m_strUser.size())
		{
			return ::_tcsicmp(_T("System"), m_strUser.c_str()) == 0;
		}

		return false;
	}

//protected:
   /*
    *************************************************************************
    * Members
    *************************************************************************
    */
    std::string m_strUser;
    std::string m_strDomain;
    std::string m_strPwd;
    std::string m_strCmdLine;
};

/**
 ****************************************************************************
 * <P> Class to parse results in shared memory.  </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *    6th November      2001     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
class McbResults
{
public:
#define McbMARSHALLONG(lpMem, lValue)                                        \
    {                                                                       \
        *((DWORD*)lpMem) = lValue;                                          \
        lpMem += sizeof(DWORD);                                             \
    }

   /*
    *************************************************************************
    * Marshal the results into memory
    *************************************************************************
    */
    void McbMarshal(LPBYTE lpMem)
    {    
        McbMARSHALLONG(lpMem, m_dwError)
        McbMARSHALSTR(lpMem, m_strError)
    }

#define McbUNMARSHALLONG(lpMem, lValue)                                      \
    {                                                                       \
        lValue = *(DWORD*)lpMem;                                            \
        lpMem += sizeof(DWORD);                                             \
    }

   /*
    *************************************************************************
    * Unmarshal the parameters from memory
    *************************************************************************
    */
    void McbUnMarshal(LPBYTE lpMem)
    {
        McbUNMARSHALLONG(lpMem, m_dwError)
        McbUNMARSHALSTR(lpMem, m_strError)    
    }

//protected:
    DWORD        m_dwError;
    std::string  m_strError;
};

#ifdef _DEBUG
    void McbTraceError(LPCTSTR lpszDetails)
    {
        DWORD dwErr = ::GetLastError();

        McbFormatError2 err;

        ::McbTraceImpl<0>::McbOutput(McbTRACESIDS, _T("%s.  Error: %d - %s\n"),
            lpszDetails, dwErr, err.McbGetDescription(dwErr)); 
    }

    #define McbTRACEERROR(lpszDetails) McbTraceError(lpszDetails);

#else //_DEBUG

    #define McbTRACEERROR(lpszDetails)

#endif //_DEBUG

/**
 ****************************************************************************
 * <P> Add allowed access to a DACL for an object.  </P>
 *
 * @methodName  McbAddAllowedSID
 *
 * @param       hObject        
 * @param       objectType        
 * @param       pSID        
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *    7th November      2001     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
bool McbAddAllowedSID(HANDLE hObject, SE_OBJECT_TYPE objectType, PSID pSID)
{
    bool bResult = false;

    if (pSID && hObject)
    {
        McbSID sidAdd(pSID);

        McbTRACE((McbTRACESIDS, 
            _T("Attempting to add access to sid: %s\n"), 
            sidAdd.McbDump().c_str()))

       /*
        *********************************************************************
        * Obtain the access control list for the object
        *********************************************************************
        */
        McbSD sd;

        if (sd.McbGetFromObject(hObject, objectType, McbSD::UpdateDacl))
        {
           /*
            *****************************************************************
            * If the DACL is not present then everyone already has access
            *****************************************************************
            */
            if (!sd.McbIsPresentDACL())
            {
                bResult = true;
            }
            else
            {                                   
                bool bAddSID = true;
                bool bUpdateDACL = true;

               /*
                *************************************************************
                * Search for an ACL for the SID
                *************************************************************
                */
                McbACL acl(sd.McbGetDACL());

                DWORD dwMax = acl.McbGetACECount();

                for (DWORD dwIndex = 0; dwIndex < dwMax; 
                    dwIndex++)
                {
                    McbACE ace(acl.McbGetACE(dwIndex));
                    McbSID sid(ace.McbGetSID());

                   /*
                    *********************************************************
                    * If this is the SID we are looking for
                    *********************************************************
                    */
                    if (sid == sidAdd)
                    {
                       /*
                        *****************************************************
                        * Check whether we are already
                        * allowed access
                        *****************************************************
                        */
                        if (ace.McbIsAllowedAccess())
                        {
                            bAddSID = false;
                            bUpdateDACL = false;
                        }
                       /*
                        *****************************************************
                        * If we aren't allowed access
                        *****************************************************
                        */
                        else 
                        {
                            bAddSID = false;

                           /*
                            *************************************************
                            * Change the access to allowed
                            *************************************************
                            */
                            ace.McbSetAllowedAccess();
                        }

                        break;
                    }
                }

                bool bInvalidACL = false;

               /*
                *************************************************************
                * If we are flagged to add the SID to the DACL
                *************************************************************
                */
                if (bAddSID)
                {
                   /*
                    *********************************************************
                    * Create an access allowed ACE with the logged on SID and 
                    * add this to the DACL.
                    *********************************************************
                    */
                    McbACE aceAdd;
                    aceAdd.McbSetSID(sidAdd);
                    aceAdd.McbSetAllowedAccess();

                    if (!acl.McbAppendACE(aceAdd))
                    {
                        bInvalidACL = true;
                    }
                    else
                    {
                        McbTRACEERROR(_T("Failed to add ACE to ACL"))
                    }
                }

               /*
                *************************************************************
                * If we are flagged to update the DACL
                *************************************************************
                */
                if (bUpdateDACL)
                {
                   /*
                    *********************************************************
                    * Ensure we didn't have a problem adding to the ACL 
                    * earlier on
                    *********************************************************
                    */
                    if (!bInvalidACL)
                    {
                       /*
                        *****************************************************
                        * Update the DACL in the security descriptor
                        *****************************************************
                        */
                        if (sd.McbSetDACL(acl))
                        {
                           /*
                            *************************************************
                            * Apply the new DACL to the object
                            *************************************************
                            */
                            if (sd.McbSetToObject(hObject, objectType, 
                                McbSD::UpdateDacl))                                              
                            {
                                bResult = true;
                            }                                   
                            else
                            {
                                McbTRACEERROR(
                                    _T("Failed to set objects DACL"))
                            }

                        }
                        else
                        {
                            McbTRACEERROR(_T("Failed to set SDs DACL"))
                        }
                    }
                }
               /*
                *************************************************************
                * If we didnt need to update the DACL then the SID already
                * exists with allowed access.
                *************************************************************
                */
                else 
                {
                       bResult = true;
                }
            }                           
        }
        else
        {            
            McbTRACEERROR(_T("Failed to obtain objects security decriptor"))
        }
    }
    else
    {
        McbTRACEERROR(_T("Invalid SID or object"))
    }

    return bResult;

}/* McbAddAllowedSID */

void McbAddPrvileges(HANDLE hToken)
{
  McbAccessToken accessToken(hToken);

  //McbAccessToken::McbPrivileges privileges(accessToken.McbGetPrivileges());

  accessToken.McbEnablePrivilege(SE_CREATE_TOKEN_NAME);
  McbTRACE((McbTRACELOGON,
    _T("EnablePrivilege(SE_CREATE_TOKEN_NAME): %d"),
    ::GetLastError()))

  accessToken.McbEnablePrivilege(SE_DEBUG_NAME);
  McbTRACE((McbTRACELOGON,
    _T("EnablePrivilege(SE_DEBUG_NAME): %d"),
    ::GetLastError()))

  accessToken.McbEnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);
  McbTRACE((McbTRACELOGON, 
    _T("EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME): %d"),
    ::GetLastError()))

  accessToken.McbEnablePrivilege(SE_IMPERSONATE_NAME);
  McbTRACE((McbTRACELOGON,
    _T("EnablePrivilege(SE_IMPERSONATE_NAME): %d"),
    ::GetLastError()))

  accessToken.McbEnablePrivilege(SE_TCB_NAME);
  McbTRACE((McbTRACELOGON, 
    _T("EnablePrivilege(SE_TCB_NAME): %d"), 
    ::GetLastError()))

  accessToken.McbEnablePrivilege(SE_CREATE_TOKEN_NAME);
  McbTRACE((McbTRACELOGON, 
    _T("EnablePrivilege(SE_CREATE_TOKEN_NAME): %d"),
    ::GetLastError())) 
}

LPTSTR ParamAsVector(LPCTSTR pszParam, std::vector<TCHAR> & vt)
{
    vt.clear();

    if (pszParam == nullptr)
        return nullptr;

    size_t len = ::_tcslen(pszParam);

    // Dont include quotes.
    if (len > 0)
    {
        if (pszParam[0] == _T('"') && pszParam[len - 1] == _T('"'))
            vt.assign(pszParam + 1, pszParam + len - 1);
        else
            vt.assign(pszParam, pszParam + len);
    }

    vt.push_back(_T('\0'));
    return &vt[0];
}

/**
 ****************************************************************************
 * <P> Attempt to create process as a specified user.  </P>
 *
 * @methodName  McbCreateProcessAsUser
 *
 * @param       &params        
 * @param       &results        
 * @param       &bMissingLogonPrivilege        
 *
 * @return      void
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *    8th November      2001     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
void McbCreateProcessAsUser(const McbParams &params, McbResults &results, 
                           bool &bMissingLogonPrivilege)
{
    bMissingLogonPrivilege = false;

#define McbSTREMPTY(str) (str.size() ? str.c_str() : _T("{empty}"))
#define McbSTRNULL(str) (str.size() ? str.c_str() : NULL)

    LPCTSTR lpszUser = McbSTRNULL(params.m_strUser);
    LPCTSTR lpszPwd = McbSTRNULL(params.m_strPwd);
    LPCTSTR lpszDomain = McbSTRNULL(params.m_strDomain);
    LPCTSTR lpszCmdLine = McbSTRNULL(params.m_strCmdLine);
        
    HANDLE hToken;

    std::basic_string<TCHAR> strTemp;

	bool bCreateProcess = false;

   /*
    *************************************************************************
    * If the user is System then we will attempt to create the process as the
	* system account
    *************************************************************************
    */
	if (params.McbIsSystemAccount())
	{
       /*
        *********************************************************************
        * Obtain the process token
        *********************************************************************
        */
    DWORD dwTokenFlags = TOKEN_ALL_ACCESS;
    //TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES;
		if (::OpenProcessToken(::GetCurrentProcess(), dwTokenFlags, &hToken))
		{
			McbTRACE((McbTRACELOGON, _T("OpenProcessToken succeeded\n")))

			bCreateProcess = true;
		}
    /*
     *********************************************************************
     * If we failed to obtain the process token
     *********************************************************************
     */
    else
    {

#define McbERROR(a, b)                                                       \
      { \
      DWORD dwErr = ::GetLastError();                             \
      \
      McbFormatError2 err;                                         \
      \
      results.m_dwError = dwErr;                                  \
      results.m_strError.append(_T(a));                           \
      results.m_strError.append(_T(".  "));                       \
      results.m_strError.append(err.McbGetDescription(dwErr));     \
    }

      McbERROR("OpenProcessToken", results)

      if (results.m_dwError == ERROR_PRIVILEGE_NOT_HELD)
      {
        bMissingLogonPrivilege = true;
      }

      McbTRACE((McbTRACELOGON, _T("OpenProcessToken failed: %s\n"),
        results.m_strError.c_str()))
    }
	}
  /*
   *************************************************************************
   * If we need to logon (because we arent running under the system
   * account).
   *************************************************************************
   */
  else
  {
    /*
     *********************************************************************
     * Attempt to logon as the specified user
     *********************************************************************
     */
    if (::LogonUser((LPTSTR)lpszUser, (LPTSTR)lpszDomain,
      (LPTSTR)lpszPwd, LOGON32_LOGON_INTERACTIVE,
      LOGON32_PROVIDER_DEFAULT, &hToken))
    {
      McbTRACE((McbTRACELOGON, _T("LogonUser succeeded\n")))

        bCreateProcess = true;
    }
    /*
     *********************************************************************
     * If we failed to logon.
     *********************************************************************
     */
    else
    {
      McbERROR("LogonUser", results)

      if (results.m_dwError == ERROR_PRIVILEGE_NOT_HELD)
      {
        bMissingLogonPrivilege = true;
      }

      McbTRACE((McbTRACELOGON, _T("LogonUser failed: %s\n"),
        results.m_strError.c_str()))
    }
	}

   /*
    *************************************************************************
    * If everything went fine so far...
    *************************************************************************
    */
	if (bCreateProcess)
    {        

       /*
        *********************************************************************
        * Obtain the logon sid which identifies the logon session associated 
        * with an access token
        *********************************************************************
        */
        McbAccessToken accessTok(hToken);

        McbAddPrvileges(hToken);


        McbAccessToken::McbGroups groups(accessTok.McbGetGroups());

        McbSID sidLogon(accessTok.McbGetUser());

       /*
        *********************************************************************
        * According to article Q165194 in the MSDN we need to ensure that the 
        * logged on user has sufficient access to the interactive desktop and 
        * workstation.
        *********************************************************************
        */
        if ((PSID)sidLogon)
        {              
           /*
            *****************************************************************
            * Obtain a handle to the interactive windowstation
            *****************************************************************
            */
            HWINSTA hWndStation = ::OpenWindowStation(_T("winsta0"), 
                FALSE, READ_CONTROL | WRITE_DAC);

            if (hWndStation)
            {
               /*
                *************************************************************
                * Set the windowstation to winsta0 to obtain the correct 
                * default desktop
                *************************************************************
                */
                if (::SetProcessWindowStation(hWndStation))
                {          
                   /*
                    *********************************************************
                    * Attempt to add access to the logged on SID.
                    *********************************************************
                    */
                    if (!McbAddAllowedSID(hWndStation, 
                        SE_WINDOW_OBJECT, sidLogon))
                    {
                        McbERROR("Adding Window station access", 
                            results)
                    }
                }
               /*
                *************************************************************
                * If we failed to set the windowstation
                *************************************************************
                */
                else 
                {
                    McbERROR("SetProcessWindowStation", results)
                }

                ::CloseWindowStation(hWndStation);
            }
           /*
            *****************************************************************
            * If we failed to obtain the interactive window station
            *****************************************************************
            */
            else 
            {
                McbERROR("OpenWindowStation", results)                        
            }

           /*
            *****************************************************************
            * Obtain a handle to the "default" desktop
            *****************************************************************
            */
            HDESK hDesk = ::OpenDesktop(_T("default"), 0, FALSE,             
                READ_CONTROL | WRITE_DAC | DESKTOP_WRITEOBJECTS | 
                DESKTOP_READOBJECTS);

            if (hDesk)
            {
               /*
                *************************************************************
                * Attempt to add access to the logged on SID.
                *************************************************************
                */
                if (!McbAddAllowedSID(hDesk, SE_WINDOW_OBJECT, 
                    sidLogon))
                {
                    McbERROR("Adding Desktop access", results)
                }

				::SwitchDesktop(hDesk);
                ::CloseDesktop(hDesk);
            }
           /*
            *****************************************************************
            * If we failed to obtain the default desktop
            *****************************************************************
            */
            else 
            {
                McbERROR("OpenDesktop", results)
            }

            {                    
               /*
                *************************************************************
                * Test whether the command line to execute is just "cmd".
                * If it is we will append echoing the logged on SID
                *************************************************************
                */
                LPCTSTR lpszMarker = lpszCmdLine;
                size_t nIndex = params.m_strCmdLine.size() - 1;

                for (; lpszMarker[nIndex] == _T(' '); nIndex--);

                strTemp.erase();
                strTemp.append(lpszMarker, nIndex+1);

#define McbCMD    _T("cmd")

                size_t cbCmd = ::_tcslen(McbCMD);

                if (::_tcsnicmp(strTemp.c_str(), McbCMD, strTemp.size()) 
                    == 0)
                {
                    std::basic_string<TCHAR> strSid;
                    std::basic_string<TCHAR> strDomain, strUser;                    

                    strTemp.erase();
                    strTemp.append(lpszCmdLine, cbCmd);                        
                    strTemp.append(_T(" /K ECHO Account: "));

                    if (sidLogon.McbGetAccount(NULL, strUser, strDomain))
                    {                        
                        if (strDomain.size())
                        {
                            strTemp.append(strDomain.c_str());
                            strTemp.append(_T("\\"));
                        }

                        strTemp.append(strUser.c_str());                            
                    }
                    else
                    {
                        strTemp.append(_T("Unknown"));
                    }

                    if (sidLogon.McbGetString(strSid))
                    {
                        strTemp.append(_T(" - "));
                        strTemp.append(strSid.c_str());
                    }
                                        
                    lpszCmdLine = strTemp.c_str();
                }
            }
        }
       /*
        *********************************************************************
        * If we failed to find the logon sid
        *********************************************************************
        */
        else 
        {
            McbERROR("Obtain logged on SID", results)
        }

       /*
        *********************************************************************
        * Attempt to start the process under the logged on user
        *********************************************************************
        */
        STARTUPINFO startInfo;        
        ::GetStartupInfo(&startInfo);

        memset(&startInfo, sizeof(STARTUPINFO), 0);
        startInfo.cb = sizeof(STARTUPINFO);
        startInfo.lpDesktop = _T("winsta0\\default");

        startInfo.lpTitle = (LPTSTR)params.m_strCmdLine.c_str();
                      
        PROCESS_INFORMATION procInfo;
        std::vector<TCHAR> vtCmdLine;
        LPTSTR pszMutableCmdLine = ParamAsVector(lpszCmdLine, vtCmdLine);

        McbTRACE((McbTRACELOGON,
            _T("CreateProcessAsUser commandLine: [%s]\n"),
            pszMutableCmdLine))

        if (::CreateProcessAsUser(hToken, NULL, pszMutableCmdLine,
            NULL, NULL, FALSE, CREATE_NEW_CONSOLE | CREATE_BREAKAWAY_FROM_JOB,
            NULL, NULL, &startInfo, &procInfo))
        {
           /*
            *****************************************************************
            * Prepare the results
            *****************************************************************
            */
            results.m_dwError = ERROR_SUCCESS;                    
        }
       /*
        *********************************************************************
        * If we failed to create the process
        *********************************************************************
        */
        else 
        {
            McbERROR("CreateProcessAsUser", results)

            McbTRACE((McbTRACELOGON, 
              _T("CreateProcessAsUser failed: %s, %d\n")
              _T("CommandLine: [%s]"),
              results.m_strError.c_str(), results.m_dwError, pszMutableCmdLine))
        }

        ::CloseHandle(hToken);
    }

}/* McbCreateProcessAsUser */

/**
 *****************************************************************************
 * <P> Implement the service to spawn processes.  </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *    6th November      2001     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
class McbFakeService : public McbServiceEntry
{
public:
   /*
    *************************************************************************
    * Initialise shared memory and name the completed event.
    *************************************************************************
    */
    McbFakeService()
        : m_mem(McbMAXMEM, McbSHAREDMEM, &g_sa), 
          m_evtComplete(McbCOMPLETEDEVENT, true, false, &g_sa) {}

   /*
    *************************************************************************
    * Override called by the service framework to do the business.
    *************************************************************************
    */
    virtual void McbRun() 
    {    
        DWORD dwWait = ::WaitForSingleObject(g_evtData, 300);        
        
       /*
        *********************************************************************
        * If we have been given a request
        *********************************************************************
        */
        if (dwWait == WAIT_OBJECT_0)
        {
           /*
            *****************************************************************
            * g_evtData is a manual-reset event, so clear it now that we
            * have claimed this request.  The persistent service is reused
            * for many requests - without this reset McbRun() would re-fire
            * on every poll and re-run the last command repeatedly.
            *****************************************************************
            */
            ::ResetEvent(g_evtData);

            McbResults results;
            results.m_dwError = ERROR_BAD_COMMAND;

            McbParams params;

            {            
               /*
                *************************************************************
                * Lock the shared memory
                *************************************************************
                */
                McbAutoMutex automutex(g_mutData);

               /*
                *************************************************************
                * Unmarshal the parameters
                *************************************************************
                */
                params.McbUnMarshal((LPBYTE)m_mem);              
            }

            McbTRACE((McbTRACESHAREDMEM, 
                _T("UNMARSHALLED - User: %s\nDomain: %s\nPassword: %s\n")
                _T("Command Line: %s\n"), 
                McbSTREMPTY(params.m_strUser), McbSTREMPTY(params.m_strDomain),  
                McbSTREMPTY(params.m_strPwd), 
                McbSTREMPTY(params.m_strCmdLine))) 
            
           /*
            *****************************************************************
            * Attempt to create the process as the specified user.
            *****************************************************************
            */
            bool bMissingLogonPrivilege;
            McbCreateProcessAsUser(params, results, bMissingLogonPrivilege);

            {
               /*
                *************************************************************
                * Enter the shared memory lock while we marshal results
                *************************************************************
                */
                McbAutoMutex automutex(g_mutData);
                                   
               /*
                *************************************************************
                * marshal the results back into shared memory
                *************************************************************
                */
                results.McbMarshal((LPBYTE)m_mem);                
            }

           /*
            *****************************************************************
            * Set the complete event to tell the caller we have finished
            *****************************************************************
            */
            ::SetEvent(m_evtComplete);

            McbTRACE((McbTRACECOMPLETE, _T("Event set to complete\n")))
        }
    }

protected:
   /*
    *************************************************************************
    * Members
    *************************************************************************
    */
    McbSmartSharedMem    m_mem;
    McbSmartEvent        m_evtComplete;
};

/*
 ****************************************************************************
 * Implement the service map - this lists all the services controlled by the
 * exe.  
 ****************************************************************************
 */
McbBEGINSERVICEMAP()
    McbSERVICEENTRY(McbFakeService, McbSERVICENAME, 0, SERVICE_ACCEPT_STOP)
McbENDSERVICEMAP()

/**
 ****************************************************************************
 * <P> IPC fast-path: hand a request to an ALREADY RUNNING McbCmdAsUser
 * service and wait for its result.  This is the handshake that used to be
 * inline in McbInvokeService() once the service had been started.  The IPC
 * objects (shared memory, events, mutex) are created by the service with a
 * null DACL (EveryoneSA), so a NON-ELEVATED caller can reach them - this
 * path needs no SCM access at all, which is what lets the logon launcher
 * drive it without admin rights.  </P>
 *
 * @methodName  McbExecuteViaRunningService
 *
 * @param       &params
 * @param       &results
 *
 * @return      void
 *
 * @author      Martyn C Brown
 ****************************************************************************
 */
void McbExecuteViaRunningService(McbParams &params, McbResults &results)
{
    McbSmartSharedMem mem(McbMAXMEM, McbSHAREDMEM, &g_sa);

   /*
    *************************************************************************
    * Marshal the parameters into the shared memory under the lock.
    *************************************************************************
    */
    {
        McbAutoMutex automutex(g_mutData);
        params.McbMarshal((LPBYTE)mem);
    }

   /*
    *************************************************************************
    * The completion event is manual-reset and the service is long-lived,
    * so clear any previous completion before signalling a fresh request.
    *************************************************************************
    */
    McbSmartEvent evtComplete(McbCOMPLETEDEVENT, true, false, &g_sa);
    ::ResetEvent(evtComplete);

   /*
    *************************************************************************
    * Tell the service to process the request, then wait for it to finish.
    *************************************************************************
    */
    ::SetEvent(g_evtData);
    ::WaitForSingleObject(evtComplete, INFINITE);

   /*
    *************************************************************************
    * Unmarshal the results the service wrote back.
    *************************************************************************
    */
    {
        McbAutoMutex automutex(g_mutData);
        results.McbUnMarshal((LPBYTE)mem);
    }
}

/**
 ****************************************************************************
 * <P> Return true if the persistent McbCmdAsUser service is installed AND
 * currently running.  Opens the SCM with connect-only access and queries
 * the service status - both permitted for a standard (non-elevated) user -
 * so this is safe to call from the logon launcher.  </P>
 *
 * @methodName  McbIsServiceRunning
 *
 * @return      bool
 *
 * @author      Martyn C Brown
 ****************************************************************************
 */
bool McbIsServiceRunning()
{
    bool bRunning = false;

    SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM)
    {
        SC_HANDLE hService = ::OpenService(hSCM, McbSERVICENAME,
            SERVICE_QUERY_STATUS);
        if (hService)
        {
            SERVICE_STATUS ss = { 0 };
            if (::QueryServiceStatus(hService, &ss) &&
                ss.dwCurrentState == SERVICE_RUNNING)
            {
                bRunning = true;
            }
            ::CloseServiceHandle(hService);
        }
        ::CloseServiceHandle(hSCM);
    }

    return bRunning;
}

/**
 ****************************************************************************
 * <P> Stop the persistent service if it is installed and running, waiting
 * for it to reach the stopped state.  Used before redeploying the binary,
 * because a running service locks System32\CmdAsUser.exe.  Requires admin.
 * </P>
 *
 * @methodName  McbStopServiceIfRunning
 *
 * @return      void
 *
 * @author      Martyn C Brown
 ****************************************************************************
 */
void McbStopServiceIfRunning()
{
    SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM)
    {
        return;
    }

    SC_HANDLE hService = ::OpenService(hSCM, McbSERVICENAME,
        SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (hService)
    {
        SERVICE_STATUS ss = { 0 };
        if (::QueryServiceStatus(hService, &ss) &&
            ss.dwCurrentState != SERVICE_STOPPED)
        {
            if (::ControlService(hService, SERVICE_CONTROL_STOP, &ss))
            {
                while (::QueryServiceStatus(hService, &ss) &&
                    ss.dwCurrentState != SERVICE_STOPPED)
                {
                    ::Sleep(300);
                }
            }
        }
        ::CloseServiceHandle(hService);
    }
    ::CloseServiceHandle(hSCM);
}

/**
 ****************************************************************************
 * <P> Terminate every running process whose image name matches (case
 * insensitive).  Used at /install time to release System32 copies of
 * CommandServer.exe / CommandClient.exe that a running instance would lock,
 * so the fresh binaries can be deployed onto the PATH.  Requires admin to
 * terminate the SYSTEM-owned CommandServer.  </P>
 *
 * @methodName  McbTerminateProcessByName
 *
 * @param       pszImageName
 *
 * @return      void
 *
 * @author      Martyn C Brown
 ****************************************************************************
 */
void McbTerminateProcessByName(LPCTSTR pszImageName)
{
    HANDLE hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        return;
    }

    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    if (::Process32First(hSnap, &pe))
    {
        do
        {
            if (::_tcsicmp(pe.szExeFile, pszImageName) == 0)
            {
                HANDLE hProc = ::OpenProcess(PROCESS_TERMINATE, FALSE,
                    pe.th32ProcessID);
                if (hProc)
                {
                    ::TerminateProcess(hProc, 0);
                    ::CloseHandle(hProc);
                }
            }
        } while (::Process32Next(hSnap, &pe));
    }

    ::CloseHandle(hSnap);
}

/**
 ****************************************************************************
 * <P> Install (or adopt) the persistent McbCmdAsUser service: an
 * auto-start, LocalSystem service whose binary is the copy in System32.
 * Once installed it is always running as SYSTEM, so later NON-ELEVATED
 * invocations can reach it over the shared-memory IPC (see
 * McbExecuteViaRunningService) instead of needing admin to spin up a
 * transient service each time.  Requires admin (writes to the SCM).  </P>
 *
 * @methodName  McbInstallService
 *
 * @return      int    (a Win32 error code, ERROR_SUCCESS on success)
 *
 * @author      Martyn C Brown
 ****************************************************************************
 */
int McbInstallService()
{
    SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM)
    {
        DWORD dwErr = ::GetLastError();
        ::_tprintf(_T("OpenSCManager failed: %d (run elevated).\n"), dwErr);
        return dwErr;
    }

   /*
    *************************************************************************
    * Point the service at the System32 copy of this exe.
    *************************************************************************
    */
    TCHAR szSysDir[MAX_PATH];
    ::GetSystemDirectory(szSysDir, MAX_PATH);

    TCHAR szBinPath[MAX_PATH];
    ::_stprintf_s(szBinPath, _T("%s\\CmdAsUser.exe"), szSysDir);

    DWORD dwErr = ERROR_SUCCESS;

    SC_HANDLE hService = ::OpenService(hSCM, McbSERVICENAME,
        SERVICE_ALL_ACCESS);

    if (!hService)
    {
        hService = ::CreateService(hSCM, McbSERVICENAME,
            _T("CmdAsUser SYSTEM helper"),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            szBinPath,
            NULL, NULL, NULL,
            NULL,               /* NULL account => LocalSystem */
            NULL);

        if (!hService)
        {
            dwErr = ::GetLastError();
            ::_tprintf(_T("CreateService failed: %d\n"), dwErr);
            ::CloseServiceHandle(hSCM);
            return dwErr;
        }

        ::_tprintf(_T("Service '%s' created (auto-start, LocalSystem):\n")
            _T("   %s\n"), McbSERVICENAME, szBinPath);
    }
    else
    {
        ::_tprintf(_T("Service '%s' already installed.\n"), McbSERVICENAME);
    }

   /*
    *************************************************************************
    * Make sure it is running now, so this session can use it immediately.
    *************************************************************************
    */
    SERVICE_STATUS ss = { 0 };
    if (::QueryServiceStatus(hService, &ss) &&
        ss.dwCurrentState == SERVICE_RUNNING)
    {
        ::_tprintf(_T("Service already running.\n"));
    }
    else if (::StartService(hService, 0, NULL))
    {
        ::_tprintf(_T("Service started.\n"));
    }
    else
    {
        DWORD dwStart = ::GetLastError();
        if (dwStart == ERROR_SERVICE_ALREADY_RUNNING)
        {
            ::_tprintf(_T("Service already running.\n"));
        }
        else
        {
            dwErr = dwStart;
            ::_tprintf(_T("StartService failed: %d\n"), dwStart);
        }
    }

    ::CloseServiceHandle(hService);
    ::CloseServiceHandle(hSCM);
    return dwErr;
}

/**
 ****************************************************************************
 * <P> Stop and remove the persistent McbCmdAsUser service.  Requires
 * admin.  </P>
 *
 * @methodName  McbUninstallService
 *
 * @return      int    (a Win32 error code, ERROR_SUCCESS on success)
 *
 * @author      Martyn C Brown
 ****************************************************************************
 */
int McbUninstallService()
{
    SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM)
    {
        DWORD dwErr = ::GetLastError();
        ::_tprintf(_T("OpenSCManager failed: %d (run elevated).\n"), dwErr);
        return dwErr;
    }

    DWORD dwErr = ERROR_SUCCESS;

    SC_HANDLE hService = ::OpenService(hSCM, McbSERVICENAME,
        SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!hService)
    {
        dwErr = ::GetLastError();
        if (dwErr == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            ::_tprintf(_T("Service '%s' is not installed.\n"), McbSERVICENAME);
            dwErr = ERROR_SUCCESS;
        }
        else
        {
            ::_tprintf(_T("OpenService failed: %d\n"), dwErr);
        }
        ::CloseServiceHandle(hSCM);
        return dwErr;
    }

    SERVICE_STATUS ss = { 0 };
    if (::QueryServiceStatus(hService, &ss) &&
        ss.dwCurrentState != SERVICE_STOPPED)
    {
        if (::ControlService(hService, SERVICE_CONTROL_STOP, &ss))
        {
            while (::QueryServiceStatus(hService, &ss) &&
                ss.dwCurrentState != SERVICE_STOPPED)
            {
                ::Sleep(300);
            }
        }
    }

    if (::DeleteService(hService))
    {
        ::_tprintf(_T("Service '%s' removed.\n"), McbSERVICENAME);
    }
    else
    {
        dwErr = ::GetLastError();
        ::_tprintf(_T("DeleteService failed: %d\n"), dwErr);
    }

    ::CloseServiceHandle(hService);
    ::CloseServiceHandle(hSCM);
    return dwErr;
}

/**
 ****************************************************************************
 * <P> Initiate a request.  </P>
 *
 * @methodName  McbInvokeService
 *
 * @param       &params        
 * @param       &results        
 *
 * @return      void
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *    6th November      2001     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
void McbInvokeService(McbParams &params, McbResults &results)
{
   /*
    *************************************************************************
    * Open the service control manager
    *************************************************************************
    */
    SC_HANDLE hSCM = ::OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, 
        GENERIC_WRITE | GENERIC_READ | GENERIC_EXECUTE);

    if (hSCM)
    {                    
        DWORD dwAccess = GENERIC_WRITE | GENERIC_READ | GENERIC_EXECUTE |
            DELETE;        

       /*
        *********************************************************************
        * Obtain the path to this exe
        *********************************************************************
        */
        TCHAR szPath[_MAX_PATH+1];     
        ::GetModuleFileName(NULL, szPath, _MAX_PATH);  

       /*
        *********************************************************************
        * We are going to start a service running under the system account so
        * we will have sufficient security to call ::LogonUser().  Because of
        * this we need to ensure that the service exe is LOCAL because the 
        * system account cannot access network resources.
        *********************************************************************
        */        
        
       /*
        *********************************************************************
        * Obtain a temporary file name
        *********************************************************************
        */
        TCHAR szTempPath[_MAX_PATH+1];       
        TCHAR szTempFile[_MAX_PATH+1];     

        ::GetTempPath(sizeof(szTempPath)-1, szTempPath);
        ::GetTempFileName(szTempPath, _T("MCB"), 0, szTempFile);

       /*
        *********************************************************************
        * Create a copy of the file that we now will be local
        *********************************************************************
        */
        if (::CopyFile(szPath, szTempFile, FALSE))
        {                
           /*
            *****************************************************************
            * First attempt to open the service
            *****************************************************************
            */
            SC_HANDLE hService = ::OpenService(hSCM, McbSERVICENAME,
                dwAccess);

           /*
            *****************************************************************
            * Track whether WE created the service here.  If the persistent
            * McbCmdAsUser service (installed via /install) already exists we
            * adopt it - and we must NOT tear it down afterwards.
            *****************************************************************
            */
            bool bCreatedService = false;

            if (!hService)
            {
               /*
                *************************************************************
                * If we failed to open the service then attempt to create it
                *************************************************************
                */
              DWORD dwFlags = SERVICE_WIN32_OWN_PROCESS |
                SERVICE_INTERACTIVE_PROCESS;
                hService = ::CreateService(hSCM, McbSERVICENAME, NULL,
                    dwAccess, dwFlags, SERVICE_DEMAND_START,
                    SERVICE_ERROR_NORMAL, szTempFile, NULL, NULL, NULL,
                    NULL, NULL);

                if (hService)
                {
                    bCreatedService = true;
                }
            }

           /*
            *****************************************************************
            * If we managed to get a service handle either by opening or 
            * creating the service.
            *****************************************************************
            */
            if (hService)
            {
                bool bServiceRunning = false;
            
               /*
                *************************************************************
                * Attempt to start the service
                *************************************************************
                */
                if (::StartService(hService, 0, NULL))
                {
                    bServiceRunning = true;
                }
                else
                {
                    DWORD dwErr = ::GetLastError();
                
                   /*
                    *********************************************************
                    * Check to see if the service is already running
                    *********************************************************
                    */
                    if (dwErr == ERROR_SERVICE_ALREADY_RUNNING)
                    {
                        bServiceRunning = true;
                    }
                }

               /*
                *************************************************************
                * If the service is now running...
                *************************************************************
                */
                if (bServiceRunning)
                {
                   /*
                    *********************************************************
                    * Hand the request to the service and wait for it over
                    * the shared-memory IPC (same handshake a non-elevated
                    * caller uses against the persistent service).
                    *********************************************************
                    */
                    McbExecuteViaRunningService(params, results);

                   /*
                    *********************************************************
                    * Only tear down a service we CREATED here (the transient
                    * fallback).  If we adopted the persistent McbCmdAsUser
                    * service, leave it installed and running.
                    *********************************************************
                    */
                    if (bCreatedService)
                    {
                        SERVICE_STATUS status;
                        if (::ControlService(hService, SERVICE_CONTROL_STOP,
                            &status))
                        {
                           /*
                            *************************************************
                            * Query the service until it stops
                            *************************************************
                            */
                            while(::QueryServiceStatus(hService, &status) &&
                                status.dwCurrentState != SERVICE_STOPPED)
                            {
                                ::Sleep(300);
                            }

                            McbTRACE((McbTRACECOMPLETE, _T("Service ended\n")))
                        }
                    }
                }

               /*
                *************************************************************
                * Delete ONLY a service we created; never delete an adopted
                * persistent service.
                *************************************************************
                */
                if (bCreatedService)
                {
                    ::DeleteService(hService);
                }

               /*
                *************************************************************
                * The temp copy is only used by a transient service, but
                * delete it regardless so we never leave an orphan behind.
                *************************************************************
                */
                ::DeleteFile(szTempFile);

               /*
                *************************************************************
                * Close the service handle
                *************************************************************
                */
                ::CloseServiceHandle(hService);
            }
           /*
            *****************************************************************
            * If we failed to create or open the service
            *****************************************************************
            */
            else 
            {
                McbERROR("Create service failed", results)                         
            }
        }
        else
        {
            McbERROR("Failed to write to temp directory", results)
        }

       /*
        *********************************************************************
        * Close the service control manager
        *********************************************************************
        */
        ::CloseServiceHandle(hSCM);
    }
   /*
    *************************************************************************
    * If we failed to open the service control manager
    *************************************************************************
    */
    else 
    {
        McbERROR("Open SCM failed", results)                 
    }

}/* McbInvokeService */

#ifdef _DEBUG
   /*
    *************************************************************************
    * Debug only method to display SIDs.
    *************************************************************************
    */
    void McbTraceSID(LPCTSTR lpszPrefix, const McbSID &sid)
    {
        std::basic_string<TCHAR> strSid;

        if (sid.McbGetString(strSid))
        {       
            std::basic_string<TCHAR> strDomain, strUser;

            if (sid.McbGetAccount(NULL, strDomain, strUser))
            {
                McbTRACE((McbTRACESIDS, 
                    _T("[%d] %s: SID: %s, Domain: %s, User: %s\n"), 
                    ::GetCurrentProcessId(), lpszPrefix, strSid.c_str(), 
                    strDomain.c_str(), strUser.c_str()))
            }
        }
    }
#endif // _DEBUG

/**
 ****************************************************************************
 * <P> Compares the logged on SID with the system SID. </P>
 *
 * @methodName  McbIsSystem
 *
 * @param       none
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *    6th November      2001     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
bool McbIsSystemSID()
{
   /*
    *************************************************************************
    * Obtain the logged on SID
    *************************************************************************
    */
    McbSID sidProcess(McbSecurityUtils::McbGetProcessSID());

   /*
    *************************************************************************
    * Create a system SID
    *************************************************************************
    */
    McbSID sidSystem;
    sidSystem.McbCreateNTSID(1, 18);

#ifdef _DEBUG
    McbTraceSID(_T("Logged on SID"), sidProcess);
    McbTraceSID(_T("System SID   "), sidSystem);
#endif //_DEBUG

    return sidSystem == sidProcess;

}/* McbIsSystemSID */

/**
 ****************************************************************************
 * <P> Display utility usage.  </P>
 *
 * @methodName  McbUsage
 *
 * @param       none
 *
 * @return      void
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *    6th November      2001     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
void McbUsage()
{
    ::_tprintf(_T("CmdAsUser - start a command as a specified user.\n"));
    ::_tprintf(_T("\n"));
    ::_tprintf(_T("Usage: CmdAsUser <user> <domain> [/p <password>] [/c <command>]\n"));
    ::_tprintf(_T("       CmdAsUser /install\n"));
    ::_tprintf(_T("       CmdAsUser /uninstall\n"));
    ::_tprintf(_T("\n"));
    ::_tprintf(_T("Where:\n"));
    ::_tprintf(_T("   <user>        is the name of the user.\n"));
    ::_tprintf(_T("   <domain>      is the logon domain, specify a period '.' for local.\n"));
    ::_tprintf(_T("   <password>    (optional) is the users password.\n"));
    ::_tprintf(_T("   <command>     (optional) is the command line to execute as the specified\n"));
    ::_tprintf(_T("                 user.\n"));
    ::_tprintf(_T("   /install      (admin) deploy the binaries into System32/SysWOW64 and\n"));
    ::_tprintf(_T("                 register the persistent McbCmdAsUser service - an auto-start\n"));
    ::_tprintf(_T("                 LocalSystem service - then start it.\n"));
    ::_tprintf(_T("   /uninstall    (admin) stop and remove that service.\n"));
    ::_tprintf(_T("\n"));
    ::_tprintf(_T("Notes:\n"));
    ::_tprintf(_T("   If the password is not given then you will be prompted for it.\n"));
    ::_tprintf(_T("   If the command is not given then \"CommandServer.exe\" is assumed.\n"));
    ::_tprintf(_T("   When the System account is requested and the persistent service (installed\n"));
    ::_tprintf(_T("   with /install) is running, the request is handed to it over a shared-memory\n"));
    ::_tprintf(_T("   IPC - this needs NO administrative rights, so it works from a normal logon.\n"));
    ::_tprintf(_T("   If that service is not running, CmdAsUser falls back to spinning up a\n"));
    ::_tprintf(_T("   transient service, which DOES require the calling process to either have\n"));
    ::_tprintf(_T("   administrative privileges (ie in the local adminstrators group) or at LEAST\n"));
    ::_tprintf(_T("   the following privileges:\n"));
    ::_tprintf(_T("      \"Act as part of the operating system\" (SeTcbPrivilege),\n"));
    ::_tprintf(_T("      \"Bypass traverse checking\" (SeChangeNotifyPrivilege),\n"));
    ::_tprintf(_T("      \"Increase quotas\" (SeIncreaseQuotaPrivilege),\n"));
    ::_tprintf(_T("      \"Replace a process level token\" (SeAssignPrimaryTokenPrivilege).\n"));
    ::_tprintf(_T("   The utility may take a while if there is inappropriate security so please\n"));
    ::_tprintf(_T("   be patient.\n"));
    ::_tprintf(_T("\n"));
    ::_tprintf(_T("Examples:\n"));
    ::_tprintf(_T("   CmdAsUser /install\n"));
    ::_tprintf(_T("   CmdAsUser Martyn . /p GingerNinja /c regedit\n"));
    ::_tprintf(_T("   CmdAsUser System . /c CommandServer.exe\n"));
    ::_tprintf(_T("   CmdAsUser System .\n"));
    ::_tprintf(_T("   CommandClient.exe\n"));
    ::_tprintf(_T("\n"));
 
}/* McbUsage */


/**
 ****************************************************************************
 * <P> Parse parameters from the command line.  </P>
 *
 * @methodName  McbParseParams
 *
 * @param       argc        
 * @param       argv[]        
 * @param       &params        
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *    7th November      2001     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
bool McbParseParams(int argc, LPCTSTR argv[], McbParams &params)
{
    bool bResult = false;

    if (argc >= 3)
    {
       /*
        *********************************************************************
        * Add the user and domain
        *********************************************************************
        */
        params.m_strUser.append(argv[1]);
        params.m_strDomain.append(argv[2]);

        bool bPwdInvalid = false;    
        bool bPwdRequired = true;

		if (params.McbIsSystemAccount())
		{
			bPwdRequired = false;
		}
		else
		{
           /*
            *****************************************************************
            * Check for the password switch
            *****************************************************************
            */
            if (argc > 3 && ::_tcsicmp(argv[3], _T("/p")) == 0) 
            {
                if (argc > 4)
                {
                    if (::_tcsicmp(argv[4], _T("/c")) == 0)
                    {
                        bPwdInvalid = true;
                    }
                    else
                    {
                        params.m_strPwd.append(argv[4]);
                        bPwdRequired = false;
                    }                    
                }
                else
                {
                    bPwdInvalid = true;
                }
            }
		}

        if (!bPwdInvalid)
        {
           /*
            *****************************************************************
            * Attempt to determine command line parameters we need to pass on
            *****************************************************************
            */
            LPTSTR lpszCmdLine = ::GetCommandLine();
            size_t cbCmdLine = ::_tcsclen(lpszCmdLine);

            LPTSTR lpszMarker = ::_tcsstr(lpszCmdLine, _T("/c"));
            if (!lpszMarker) lpszMarker = ::_tcsstr(lpszCmdLine, _T("/C"));

            if (lpszMarker)
            {
                lpszMarker += ::_tcsclen(_T("/C"));
                
                TCHAR ch;
                for (; ch = (*lpszMarker); lpszMarker++)
                {
                    if (ch != _T(' '))
                    {
                        params.m_strCmdLine.append(lpszMarker);
                        break;
                    }
                }
            }        
           /*
            *****************************************************************
            * If we failed to find the command switch then assume we are 
            * invoking a command prompt with "cmd"
            *****************************************************************
            */
            else 
            {
                params.m_strCmdLine.append(_T("CommandServer.exe"));
            }

           /*
            *****************************************************************
            * If we managed to obtain command line parameters
            *****************************************************************
            */
            if (params.m_strCmdLine.size())
            {            
                if (!bPwdRequired)
                {
                    bResult = true;
                }
               /*
                *************************************************************
                * If we have no password then we need to obtain one from the 
                * user
                *************************************************************
                */
                else 
                {
                    char szPwd[100];

                    ::_tprintf("Password: ");

                    ::srand((unsigned)time(NULL));

                    if (McbConsole::McbGetPasswordA(szPwd, sizeof(szPwd)))
                    {
                        params.m_strPwd.append(szPwd);                            
                    }

                    ::_tprintf("\n");

                    bResult = true;
                }
            }

        }
    }

    return bResult; 

}/* McbParseParams */

bool CopyFileToDestination(LPCTSTR fileName, LPCTSTR destinationPath)
{
    TCHAR sourceFile[MAX_PATH];
    TCHAR destinationFile[MAX_PATH];

    // Look next to THIS executable first, so /install works regardless of the
    // current directory. GetModuleFileName gives the full path to CmdAsUser.exe;
    // strip the file name to get its folder.
    TCHAR moduleDir[MAX_PATH];
    sourceFile[0] = _T('\0');
    if (GetModuleFileName(NULL, moduleDir, MAX_PATH))
    {
        LPTSTR lastSlash = _tcsrchr(moduleDir, _T('\\'));
        if (lastSlash)
        {
            *lastSlash = _T('\0');
            _stprintf_s(sourceFile, _T("%s\\%s"), moduleDir, fileName);
        }
    }

    // If it is not alongside the exe, fall back to just the file name; the OS
    // resolves that against the current directory / search path.
    if (sourceFile[0] == _T('\0') ||
        GetFileAttributes(sourceFile) == INVALID_FILE_ATTRIBUTES)
    {
        _tcscpy_s(sourceFile, fileName);
    }

    // Construct the full path of the destination file
    _stprintf_s(destinationFile, _T("%s\\%s"), destinationPath, fileName);

    // Check that we actually found a source file
    if (GetFileAttributes(sourceFile) == INVALID_FILE_ATTRIBUTES)
    {
        std::cerr << "File does not exist: " << sourceFile << std::endl;
        return false;
    }

    // Nothing to do if the source already IS the destination (e.g. the
    // deployed System32 copy being asked to install itself) - CopyFile would
    // otherwise fail with a sharing violation.
    if (_tcsicmp(sourceFile, destinationFile) == 0)
    {
        std::cout << "Already in place: " << destinationFile << std::endl;
        return true;
    }

    // Copy the file to the destination directory
    if (!CopyFile(sourceFile, destinationFile, FALSE))
    {
        std::cerr << "Failed to copy " << sourceFile << " -> " << destinationFile
            << ". Error: " << GetLastError() << std::endl;
        return false;
    }

    std::cout << "Copied " << sourceFile << " -> " << destinationFile << std::endl;
    return true;
}

bool CopyFileToSysWOW64(LPCTSTR fileName)
{
    // Resolve the real SysWOW64 path rather than hardcoding C:\Windows.
    // Returns 0 on a system with no WOW64 subsystem - nothing to deploy there.
    TCHAR wow64Dir[MAX_PATH];
    if (GetSystemWow64Directory(wow64Dir, MAX_PATH) == 0)
    {
        return true;
    }
    return CopyFileToDestination(fileName, wow64Dir);
}

bool CopyFileToSystem32(LPCTSTR fileName)
{
    // Resolve the real System32 path rather than hardcoding C:\Windows.
    TCHAR sysDir[MAX_PATH];
    if (GetSystemDirectory(sysDir, MAX_PATH) == 0)
    {
        std::cerr << "Failed to resolve the System32 directory. Error: "
            << GetLastError() << std::endl;
        return false;
    }
    return CopyFileToDestination(fileName, sysDir);
}

/**
 ****************************************************************************
 * <P> Return true if the current process is running with an elevated
 * (administrator) token.  Used to decide whether to attempt the self-copy
 * into System32/SysWOW64: a non-elevated caller (e.g. the logon launcher)
 * cannot write there, so it skips the copy silently instead of printing a
 * row of "Failed to copy file. Error: 5" access-denied messages.  </P>
 *
 * @methodName  McbIsProcessElevated
 *
 * @return      bool
 *
 * @author      Martyn C Brown
 ****************************************************************************
 */
bool McbIsProcessElevated()
{
    bool bElevated = false;

    HANDLE hToken = NULL;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        TOKEN_ELEVATION elevation = { 0 };
        DWORD cbSize = sizeof(elevation);
        if (::GetTokenInformation(hToken, TokenElevation, &elevation,
            sizeof(elevation), &cbSize))
        {
            bElevated = (elevation.TokenIsElevated != 0);
        }
        ::CloseHandle(hToken);
    }

    return bElevated;
}

/**
 ****************************************************************************
 * <P> Deploy the three binaries into System32 and SysWOW64.  This is the
 * install-time self-copy; it only makes sense when running elevated.
 *
 * Returns true only if all three System32 copies succeeded - those are the
 * ones on the PATH (and the service runs System32\CmdAsUser.exe), so a
 * failure there must fail /install.  The SysWOW64 copies are best-effort
 * (this project is x64-only) and never fail the deploy.  </P>
 *
 * @methodName  McbDeployBinaries
 *
 * @return      bool
 *
 * @author      Martyn C Brown
 ****************************************************************************
 */
bool McbDeployBinaries()
{
    bool bOk = true;

    bOk = CopyFileToSystem32(_T("CmdAsUser.exe"))      && bOk;
    bOk = CopyFileToSystem32(_T("CommandClient.exe"))  && bOk;
    bOk = CopyFileToSystem32(_T("CommandServer.exe"))  && bOk;

    CopyFileToSysWOW64(_T("CmdAsUser.exe"));
    CopyFileToSysWOW64(_T("CommandClient.exe"));
    CopyFileToSysWOW64(_T("CommandServer.exe"));

    std::cout << std::endl;
    return bOk;
}

/**
 ****************************************************************************
 * <P> Entry point.  We will first be called from the command line, in which
 * case we will install ourself as a service and start the service up.  This 
 * entry point therefore needs to be able to be called by the service control
 * manager to start the service AND from the command line.  We are going to 
 * determine which called us based on the security identifier we are running
 * under as we can't rely on command line parameters (see below).
 * 
 * Once we are running as a service we will have sufficient access to call
 * ::LogonUser() which required the SE_TCB_NAME privilege which must users
 * don't seem to have.  Once we have successfully called LogonUser() we can 
 * then create the process under that user.  </P>
 *
 * @methodName  _tmain
 *
 * @param       argc        
 * @param       argv[]        
 *
 * @return      int
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *    6th November      2001     -     (V1.0) Creation (MCB)
 ****************************************************************************
 */
int _tmain(int argc, LPCTSTR argv[]) 
{    
    int nResult = 0;

   /*
    *************************************************************************
    * We cant rely on the given arguments to dictate whether we were called 
    * by a user or the SCM (invoked by McbInvokeService() above) because 
    * when called by the SCM these only become available in service main (ie 
    * they do not come through as argc, argv.  Instead we shall check the 
    * logged on SID to determine whether we were called by a user of the SCM.  
    * The SCM should be running as local system.
    *************************************************************************
    */
    if (McbIsSystemSID())
    {
       /*
        *********************************************************************
        * Start the service.  This API, if successful will not return until
        * the Service has stopped.
        *********************************************************************
        */        
        McbStartServices(argc, argv);
    }
   /*
    *************************************************************************
    * If we are being called from the command line....
    *************************************************************************
    */
    else
    {
       /*
        *********************************************************************
        * Service management verbs.  "/install" deploys the binaries and
        * registers the persistent auto-start SYSTEM service; "/uninstall"
        * removes it.  Both need administrator rights (they write to the
        * SCM) and are intended to be run from the elevated installer.
        *********************************************************************
        */
        if (argc >= 2 && ::_tcsicmp(argv[1], _T("/install")) == 0)
        {
            if (!McbIsProcessElevated())
            {
                ::_tprintf(_T("/install requires administrator rights.\n"));
                return ERROR_ACCESS_DENIED;
            }

           /*
            * Release every binary we are about to overwrite: stop the
            * service (unlocks System32\CmdAsUser.exe) and terminate any
            * running CommandServer / CommandClient (they lock their own
            * System32 copies).  Then deploy the fresh binaries onto the
            * PATH and (re)create and start the service.
            */
            McbStopServiceIfRunning();
            McbTerminateProcessByName(_T("CommandServer.exe"));
            McbTerminateProcessByName(_T("CommandClient.exe"));

            if (!McbDeployBinaries())
            {
                ::_tprintf(_T("Binary deployment failed; aborting install ")
                    _T("(the service was NOT changed).\n"));
                return ERROR_INSTALL_FAILURE;
            }

            return McbInstallService();
        }

        if (argc >= 2 && ::_tcsicmp(argv[1], _T("/uninstall")) == 0)
        {
            if (!McbIsProcessElevated())
            {
                ::_tprintf(_T("/uninstall requires administrator rights.\n"));
                return ERROR_ACCESS_DENIED;
            }

            return McbUninstallService();
        }

       /*
        *********************************************************************
        * The self-copy into System32/SysWOW64 is an install-time action and
        * only works elevated.  Skip it silently otherwise so a non-elevated
        * caller (the logon launcher) does not spew access-denied errors.
        *********************************************************************
        */
        if (McbIsProcessElevated())
        {
            McbDeployBinaries();
        }

       /*
        *********************************************************************
        * Parse parameters
        *********************************************************************
        */
        McbParams params;
        if (McbParseParams(argc, argv, params))
        {
            McbResults results;

            bool bInvokeAsSystem = false;

           /*
            *****************************************************************
            * Check if the user requested the system account.
            *****************************************************************
            */
			if (params.McbIsSystemAccount())
			{
				bInvokeAsSystem = true;
			}
			else
			{
               /*
                *************************************************************
                * Attempt to create process as user from THIS process.
                *************************************************************
                */
				bool bMissingPrivilege;
				McbCreateProcessAsUser(params, results, bMissingPrivilege);
				
				if (bMissingPrivilege)
				{
					::_tprintf(_T("SE_TCB_NAME not held.\n"));

					bInvokeAsSystem = true;
				}
				else
				{
					::_tprintf(_T("SE_TCB_NAME held.\n"));
				}
			}

           /*
            *****************************************************************
            * If the logon failed (LogonUser()) then this will be because
            * the calling user does not have "Act as part of operating sytem"
            * (SE_TCB_NAME) privilege,  Attempt to invoke the service 
            * instead.
            *****************************************************************
            */
            if (bInvokeAsSystem)
            {                				
               /*
                *************************************************************
                * Ensure we only have one caller at a time
                *************************************************************
                */
                McbSmartMutex mutSingleton(_T("McbCmdAsUserMutSingleton"));
                McbAutoMutex automutex(mutSingleton);
                                
               /*
                *************************************************************
                * Process the request.  If the persistent service is already
                * running, talk to it directly over the shared-memory IPC -
                * this needs NO admin rights, so the non-elevated logon
                * launcher works.  Otherwise fall back to the original
                * behaviour (spin up a transient service), which does need
                * admin.
                *************************************************************
                */
                results.m_dwError = 0;
                results.m_strError.erase();

                if (McbIsServiceRunning())
                {
                    McbExecuteViaRunningService(params, results);
                }
                else
                {
                    McbInvokeService(params, results);
                }
            }

           /*
            *****************************************************************
            * Display some results
            *****************************************************************
            */
            if (results.m_dwError != ERROR_SUCCESS)
            {
                ::_tprintf(_T("An error occurred: %d - %s\n"), 
                    results.m_dwError, results.m_strError.c_str());

               /*
                *************************************************************
                * If we attempted to invoke the service to process the 
                * request and this failed with access denied then tell the 
                * punter that they need adminstrative rights
                *************************************************************
                */
                if (bInvokeAsSystem && (results.m_dwError == 
					ERROR_ACCESS_DENIED))
                {
                    ::_tprintf(_T("Does the CURRENT user have ")
                        _T("administrative privileges?\n"));
                }
            }
            else
            {
                ::_tprintf(_T("Started \"%s\" under user: %s\n"), 
                    params.m_strCmdLine.c_str(), params.m_strUser.c_str());
            }

            nResult = results.m_dwError;
        }
        else
        {
            ::_tprintf(_T("Note: Bad command line parameters\n\n"));

            McbUsage();
        }        
    }

    return nResult;
    
}/* _tmain */


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
                    McbSmartSharedMem mem(McbMAXMEM, McbSHAREDMEM, &g_sa);

                    {
                       /*
                        *****************************************************
                        * Enter the shared memory lock
                        *****************************************************
                        */
                        McbAutoMutex automutex(g_mutData);
                                       
                       /*
                        *****************************************************
                        * Marshal the parameters into the shared memory.
                        *****************************************************
                        */
                        params.McbMarshal((LPBYTE)mem);                
                    }

                    McbTRACE((McbTRACESHAREDMEM, 
                        _T("MARSHALLED - User: %s\nDomain: %s\nPassword:")
                        _T(" %s\nCommand Line: %s\n"), 
                        McbSTREMPTY(params.m_strUser), 
                        McbSTREMPTY(params.m_strDomain),  
                        McbSTREMPTY(params.m_strPwd),                     
                        McbSTREMPTY(params.m_strCmdLine)))

                   /*
                    *********************************************************
                    * Set the event to tell the service to do something
                    *********************************************************
                    */
                    ::SetEvent(g_evtData);

                   /*
                    *********************************************************
                    * Now wait for the service to complete the task
                    *********************************************************
                    */
                    McbTRACE((McbTRACECOMPLETE, 
                        _T("Waiting for completion\n")))

                    McbSmartEvent evtComplete(McbCOMPLETEDEVENT, true, 
                      false, &g_sa);

                    ::WaitForSingleObject(evtComplete, INFINITE);

                    McbTRACE((McbTRACECOMPLETE, _T("Event completed\n")))

                    {
                       /*
                        *****************************************************
                        * Enter the shared memory lock
                        *****************************************************
                        */
                        McbAutoMutex automutex(g_mutData);
                                       
                       /*
                        *****************************************************
                        * unmarshal the results created by the service.
                        *****************************************************
                        */
                        results.McbUnMarshal((LPBYTE)mem);                
                    }

                   /*
                    *********************************************************
                    * Ask the service to stop
                    *********************************************************
                    */
                    SERVICE_STATUS status;
                    if (::ControlService(hService, SERVICE_CONTROL_STOP, 
                        &status))
                    {
                       /*
                        *****************************************************
                        * Query the service until it stops
                        *****************************************************
                        */
                        while(::QueryServiceStatus(hService, &status) && 
                            status.dwCurrentState != SERVICE_STOPPED)
                        {
                           /*
                            *************************************************
                            * Yield for a while
                            *************************************************
                            */
                            ::Sleep(300);
                        }

                        McbTRACE((McbTRACECOMPLETE, _T("Service ended\n")))
                    }                
                }

               /*
                *************************************************************
                * Attempt to delete the service
                *************************************************************
                */
                if (::DeleteService(hService))
                {
                   /*
                    *********************************************************
                    * Attempt to delete the file
                    *********************************************************
                    */
                    ::DeleteFile(szTempFile);                    
                }

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
    ::_tprintf(_T("\n"));
    ::_tprintf(_T("Where:\n"));
    ::_tprintf(_T("   <user>        is the name of the user.\n"));
    ::_tprintf(_T("   <domain>      is the logon domain, specify a period '.' for local.\n"));
    ::_tprintf(_T("   <password>    (optional) is the users password.\n"));
    ::_tprintf(_T("   <command>     (optional) is the command line to execute as the specified\n"));
    ::_tprintf(_T("                 user.\n"));
    ::_tprintf(_T("\n"));
    ::_tprintf(_T("Notes:\n"));
    ::_tprintf(_T("   If the password is not given then you will be prompted for it.\n"));
    ::_tprintf(_T("   If the command is not given then \"CommandServer.exe\" is assumed.\n"));
    ::_tprintf(_T("   The calling process needs to either have administrative privileges (ie in\n"));
    ::_tprintf(_T("   the local adminstrators group) or at LEAST the following privileges:\n"));        
    ::_tprintf(_T("      \"Act as part of the operating system\" (SeTcbPrivilege),\n"));    
    ::_tprintf(_T("      \"Bypass traverse checking\" (SeChangeNotifyPrivilege),\n"));
    ::_tprintf(_T("      \"Increase quotas\" (SeIncreaseQuotaPrivilege),\n"));
    ::_tprintf(_T("      \"Replace a process level token\" (SeAssignPrimaryTokenPrivilege).\n"));     
    ::_tprintf(_T("   The utility may take a while if there is inappropriate security so please\n"));
    ::_tprintf(_T("   be patient.\n"));
    ::_tprintf(_T("\n"));
    ::_tprintf(_T("Examples:\n"));
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
    TCHAR currentDir[MAX_PATH];
    TCHAR sourceFile[MAX_PATH];
    TCHAR destinationFile[MAX_PATH];

    // Get the current directory
    if (!GetCurrentDirectory(MAX_PATH, currentDir))
    {
        std::cerr << "Failed to get current directory. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Construct the full path of the source file
    _stprintf_s(sourceFile, _T("%s\\%s"), currentDir, fileName);

    // Construct the full path of the destination file
    _stprintf_s(destinationFile, _T("%s\\%s"), destinationPath, fileName);

    // Check if the file exists in the current directory
    if (GetFileAttributes(sourceFile) == INVALID_FILE_ATTRIBUTES)
    {
        std::cerr << "File does not exist: " << sourceFile << std::endl;
        return false;
    }

    // Copy the file to the destination directory
    if (!CopyFile(sourceFile, destinationFile, FALSE))
    {
        std::cerr << "Failed to copy file. Error: " << GetLastError() << std::endl;
        return false;
    }

    std::cout << "File copied successfully to " << destinationFile << std::endl;
    return true;
}

bool CopyFileToSysWOW64(LPCTSTR fileName)
{
    return CopyFileToDestination(fileName, _T("C:\\Windows\\SysWOW64"));
}

bool CopyFileToSystem32(LPCTSTR fileName)
{
    return CopyFileToDestination(fileName, _T("C:\\Windows\\System32"));
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
        CopyFileToSystem32(_T("CmdAsUser.exe"));
        CopyFileToSystem32(_T("CommandClient.exe"));
        CopyFileToSystem32(_T("CommandServer.exe"));

        CopyFileToSysWOW64(_T("CmdAsUser.exe"));
        CopyFileToSysWOW64(_T("CommandClient.exe"));
        CopyFileToSysWOW64(_T("CommandServer.exe"));
		std::cout << std::endl;

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
                * Process the request by invoking the service
                *************************************************************
                */
                results.m_dwError = 0;
                results.m_strError.erase();

                McbInvokeService(params, results);                                
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


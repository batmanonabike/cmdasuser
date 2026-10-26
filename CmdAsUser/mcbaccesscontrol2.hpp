/*
 ****************************************************************************
 *
 * @Name		McbAccessControl2.hpp - classes for NT security.
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *	15th February  	2000	 - 	(V1.0) Creation (MCB)
 *	12th October   	2001	 - 	(V2.0) Modified (MCB).  Now added as template 
 *								classes for minimal codes size.  Use the 
 *								typedefs near the bottom of the source file 
 *								for ease of use.
 ****************************************************************************
 *
 * Declaration for wrapper classes for use with the NT security model.  
 *
 * These classes thinly wrap the following NT objects:
 *  Security Identifiers (SIDs),
 *  Access Control Entries (ACEs),
 *  Access Control Lists (ACLs),
 *  Security Descriptors,
 *  Privileges,
 *  Access Tokens
 * In general, if a function call fails within these classes the win32 
 * GetLastError() can be used to obtain further details.
 ****************************************************************************
 */
 
/*
 ****************************************************************************
 * include only once
 ****************************************************************************
 */
#ifndef McbAccessControl2_Included
#define McbAccessControl2_Included

/*
 ****************************************************************************
 * Include all necessary include files
 ****************************************************************************
 */
#include <aclapi.h>
#include <tchar.h>
#include <string>

#include "McbStrTok.hpp"

/*
 ****************************************************************************
 * Macros to simplify memory allocation/deallocation
 ****************************************************************************
 */
#define McbHEAPALLOC(nSize)													\
	::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, nSize)

#define McbHEAPFREE(lpMem) ::HeapFree(::GetProcessHeap(), 0, lpMem)

/**
 ****************************************************************************
 * <P> Security Identifiers - a security identifier (SID) identifies a 
 * trustee (this can include users/groups). 
 *
 * A SID consists of:
 *  a revision level of the sid,
 *  an identifier authority - this defines the authority on which the sid 
 *      was allocated,
 *  a variable number of subauthorities (also known as RIDs or relative 
 *      identifiers) that uniquely identify the trustee relative to the
 *      authority on which the sid was allocated.
 *
 *
 * SIDs can be represented in standardized string notation for SIDs, which 
 * makes it simpler to visualize their components: 
 *
 *   
 *   S-R-I-S-S...
 *
 * In this notation, the first literal character S identifies the series of 
 * digits as a SID, R is the revision level, I is the identifier-authority 
 * value, and S... is one or more subauthority values. 
 *
 * The following example uses this notation to display the well-known 
 * domain-relative SID of the local Administrators group:
 *
 * S-1-5-32-544
 * 
 * In this example, the SID has the following components. The constants in 
 * parentheses are well-known identifier authority and RID values defined 
 * in WINNT.H. 
 *
 * A revision level of 1 
 * An identifier-authority value of 5 (SECURITY_NT_AUTHORITY) 
 * A first subauthority value of 32 (SECURITY_BUILTIN_DOMAIN_RID) 
 * A second subauthority value of 544 (DOMAIN_ALIAS_RID_ADMINS).
 *
 * This could be allocated with a call to McbCreateSID() using the following
 * syntax:
 *
 *      SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
 *
 *      McbCreateSID(auth, 2, SECURITY_BUILTIN_DOMAIN_RID, 
 *          DOMAIN_ALIAS_RID_ADMINS);
 *
 * Or with the McbCreateNTSID() function (designed specifically for creating
 * NT type sids (which use the SECURITY_NT_AUTHORITY identifier authority):
 *
 *      McbCreateNTSID(2, SECURITY_BUILTIN_DOMAIN_RID, 
 *          DOMAIN_ALIAS_RID_ADMINS);
 *   
 * </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *	15th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> class McbSIDImpl
{
public:
   /*
    *************************************************************************
    * C'tion/D'tion
    *************************************************************************
    */	
	McbSIDImpl(const PSID pSid = NULL);
	McbSIDImpl(const McbSIDImpl &other)
		: m_pSid(NULL) { *this = other.m_pSid; }
	~McbSIDImpl() { McbFree(); }

	McbSIDImpl(LPCTSTR lpszAccount, LPCTSTR lpszSystem = NULL) : m_pSid(NULL)
	{
		McbSetAccount(lpszSystem, lpszAccount);
	}

   /*
    *************************************************************************
    * operator overloads
    *************************************************************************
    */
	PSID operator=(const PSID pSid);
	McbSIDImpl & operator=(const McbSIDImpl &other) 
        { *this = other.m_pSid; return *this; }

	bool operator==(const PSID pSid);

	operator PSID() { return m_pSid; }
	operator const PSID() const { return m_pSid; }

   /*
    *************************************************************************
    * functionality
    *************************************************************************
    */
    void McbCreateSID(const SID_IDENTIFIER_AUTHORITY &auth, 
        BYTE nSubAuthorityCount, ...);	

   /*
    *************************************************************************
    * Also see macros after definition of class for generating well known
    * sids and sids for standard NT groups
    *************************************************************************
    */
	void McbCreateNTSID(BYTE nSubAuthorityCount=0, ...);
    void McbCreateNullSID(BYTE nSubAuthorityCount=0, ...);
    void McbCreateWorldSID(BYTE nSubAuthorityCount=0, ...);
    void McbCreateLocalSID(BYTE nSubAuthorityCount=0, ...);
    void McbCreateCreatorSID(BYTE nSubAuthorityCount=0, ...);
    	
	bool McbSetAccount(LPCTSTR lpszSystem, LPCTSTR lpszAccount);

	bool McbGetAccount(LPCTSTR lpszSystem, std::basic_string<TCHAR> &strName, 
		std::basic_string<TCHAR> &strDomain) const;

    bool McbGetSidUse(LPCTSTR lpszSystem, SID_NAME_USE &sidUse) const;    

	bool McbIsValid(LPCTSTR lpszSystem) const;
	inline bool McbIsValid() const;

    bool McbGetString(std::basic_string<TCHAR> &strSid) const;
    bool McbSetString(LPCTSTR lpszSid);

	std::basic_string<TCHAR> McbDump() const;
	std::basic_string<TCHAR> McbDumpXML() const;
				
protected:
   /*
    *************************************************************************
    * functionality
    *************************************************************************
    */
	inline void McbFree();	
    void McbCreateSIDFromList(const SID_IDENTIFIER_AUTHORITY &auth, 
		BYTE nSubAuthorityCount, va_list marker);	

   /*
    *************************************************************************
    * members
    *************************************************************************
    */
	PSID m_pSid;
};

/**
 ****************************************************************************
 * <P> Free the resource. </P>
 *
 * @methodName	McbSIDImpl<n>::McbFree
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
 *	15th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbSIDImpl<n>::McbFree()
{
	if (m_pSid)
	{		
		McbHEAPFREE(m_pSid);
		m_pSid = NULL;
	}

}/* McbSIDImpl<n>::McbFree */

/**
 ****************************************************************************
 * <P> C'tor </P>
 *
 * @methodName  McbSIDImpl<n>::McbSIDImpl
 *
 * @param       const PSID pSID
 *
 * @return      none
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	16th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> McbSIDImpl<n>::McbSIDImpl(const PSID pSid) : m_pSid(NULL)
{
	*this = pSid;

}/* McbSIDImpl<n>::McbSIDImpl */

/**
 ****************************************************************************
 * <P> Validates a sid on the local system </P>
 *
 * @methodName	McbSIDImpl<n>::McbIsValid
 *
 * @param       none
 *
 * @return      inline
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	22nd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> inline bool McbSIDImpl<n>::McbIsValid() const
{
	return McbIsValid(NULL);

}/* bool McbSIDImpl<n>::McbIsValid */

/**
 ****************************************************************************
 * <P> Assignment operator </P>
 *
 * @methodName  & McbSIDImpl<n>::operator=
 *
 * @param       SID &other		
 *
 * @return      McbSID
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	16th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> PSID McbSIDImpl<n>::operator=(const PSID pSid)
{
	if ((LPBYTE)pSid != (LPBYTE)m_pSid)
	{
		McbFree();

		if (pSid)
		{
           /*
            *****************************************************************
            * take copy of other sid
            *****************************************************************
            */
			DWORD cbSid = ::GetLengthSid((PSID)pSid);
		
			m_pSid = (PSID)McbHEAPALLOC(cbSid);

			::CopySid(cbSid, m_pSid, (PSID)pSid);
		}
  	}

	return m_pSid;

}/* & McbSIDImpl<n>::operator= */

/**
 ****************************************************************************
 * <P> Obtain the sid in string format </P>
 *
 * @methodName  McbSIDImpl<n>::McbGetString
 *
 * @param       &strSid		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	28th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSIDImpl<n>::McbGetString(
	std::basic_string<TCHAR> &strSid) const
{
    PSID_IDENTIFIER_AUTHORITY psia;    
    DWORD dwSubAuthorities;
    DWORD dwSidRev=SID_REVISION;    
    DWORD dwCounter;
    DWORD dwSidSize;

   /*
    *************************************************************************
    * Validate the binary SID
    *************************************************************************
    */
	if (!m_pSid || !IsValidSid(m_pSid))
    {
        return false;
    }
    
   /*
    *************************************************************************
    * Get the identifier authority value from the SID.
    *************************************************************************
    */
    psia = ::GetSidIdentifierAuthority(m_pSid);
    
   /*
    *************************************************************************
    * Get the number of subauthorities in the SID.
    *************************************************************************
    */
    dwSubAuthorities = *::GetSidSubAuthorityCount(m_pSid);

   /*
    *************************************************************************
    * Compute the buffer length.
    * S-SID_REVISION- + IdentifierAuthority- + subauthorities- + NULL
    *************************************************************************
    */
	dwSidSize=(15 + 12 + (12 * dwSubAuthorities) + 1) * sizeof(TCHAR);

   /*
    *************************************************************************
    * temporary buffer to hold the string sid
    *************************************************************************
    */
	std::basic_string<TCHAR> strTempSid;
    strTempSid.resize(dwSidSize);

    LPTSTR lpszSid = (LPTSTR)strTempSid.data();

   /*
    *************************************************************************
    * Add 'S' prefix and revision number to the string.
    *************************************************************************
    */
	dwSidSize=_stprintf(lpszSid, _T("S-%lu-"), dwSidRev);

   /*
    *************************************************************************
    * Add SID identifier authority to the string.
    *************************************************************************
    */
	if ((psia->Value[0] != 0) || (psia->Value[1] != 0))
    {
        dwSidSize+=wsprintf(lpszSid + lstrlen(lpszSid),
                    TEXT("0x%02Mcb%02Mcb%02Mcb%02Mcb%02Mcb%02Mcb"),
                    (USHORT)psia->Value[0],
                    (USHORT)psia->Value[1],
                    (USHORT)psia->Value[2],
                    (USHORT)psia->Value[3],
                    (USHORT)psia->Value[4],
                    (USHORT)psia->Value[5]);    
    }    
    else    
    {
        dwSidSize+=wsprintf(lpszSid + lstrlen(lpszSid),
                    TEXT("%lu"),
                    (ULONG)(psia->Value[5]      )   +
                    (ULONG)(psia->Value[4] <<  8)   +
                    (ULONG)(psia->Value[3] << 16)   +
                    (ULONG)(psia->Value[2] << 24)   );    
    }

   /*
    *************************************************************************
    * Add SID subauthorities to the string.
    *************************************************************************
    */
	for (dwCounter=0 ; dwCounter < dwSubAuthorities ; dwCounter++)	  
    {
        dwSidSize+=wsprintf(lpszSid + dwSidSize, TEXT("-%lu"),
            *::GetSidSubAuthority(m_pSid, dwCounter));        
    }
    
   /*
    *************************************************************************
    * resize buffer if too small
    *************************************************************************
    */
	if (strSid.size() <= dwSidSize)
    {
        strSid.resize(dwSidSize);
    }

   /*
    *************************************************************************
    * retrieve temporary sid
    *************************************************************************
    */
	strSid.erase();
    strSid.append(strTempSid.c_str(), dwSidSize);
       
    return true;

}/* McbSIDImpl<n>::McbGetString */

/**
 ****************************************************************************
 * <P> Set the sid from string format </P>
 *
 * @methodName  McbSIDImpl<n>::McbSetString
 *
 * @param       &strSid		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	28th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSIDImpl<n>::McbSetString(LPCTSTR lpszSidString)
{
    if (!lpszSidString)
    {
        return false;
    }

   /*
    *************************************************************************
    * This function sets a sid from the string format.
    * The strings format should be:
    *   S-R-I-S-S...
    *
    * In this notation, the first literal character S identifies the series
    * of digits as a SID, R is the revision level, I is the 
    * identifier-authority value, and S... is one or more subauthority 
	* values. 
    *
    * The following example uses this notation to display the well-known 
    * domain-relative SID of the local Administrators group:
    *
    * S-1-5-32-544
    * 
    * McbStrTok is used to find tokens within the string
    *************************************************************************
    */
	McbStrTok strToken(_T("-"), lpszSidString);

   /*
    *************************************************************************
    * bypass the first 'S'
    *************************************************************************
    */
	if (!strToken.McbGetNext())
    {
        return false;
    }

   /*
    *************************************************************************
    * find the revision (R) then convert to DWORD
    *************************************************************************
    */
	LPCTSTR lpszNext = strToken.McbGetNext();

    if (!lpszNext)
    {
        return false;
    }

//////////////////////////////////////////////////////////////////////////////
// COMMENTED OUT @14:42:05, on 8th March     2000
//
//	DWORD dwRevision = atol(lpszNext);
//
//////////////////////////////////////////////////////////////////////////////

   /*
    *************************************************************************
    * find the identifier-authority (I) and convert to DWORD
    *************************************************************************
    */
	lpszNext = strToken.McbGetNext();

    if (!lpszNext)
    {
        return false;
    }

    DWORD dwIdent = atol(lpszNext);

   /*
    *************************************************************************
    * subauthorities
    *************************************************************************
    */
	DWORD dwSubAuthorities[20];
    DWORD dwMaxAuthorities = 0;

   /*
    *************************************************************************
    * obtain each subauthority from the string
    *************************************************************************
    */
	while(lpszNext = strToken.McbGetNext())
    {
        dwSubAuthorities[dwMaxAuthorities++] = atol(lpszNext);
    }

   /*
    *************************************************************************
    * at least one sub authority is required for the sid
    *************************************************************************
    */
	if (!dwMaxAuthorities)
    {
        return false;
    }

    SID_IDENTIFIER_AUTHORITY auth = {0, 0, 0, 0, 0, 0};

    auth.Value[5] = (BYTE)dwIdent;
    auth.Value[4] = (BYTE)(dwIdent >> 8);
    auth.Value[3] = (BYTE)(dwIdent >> 16);
    auth.Value[2] = (BYTE)(dwIdent >> 24);    

   /*
    *************************************************************************
    * attempt to create the sid
    *************************************************************************
    */
	McbSIDImpl<n>::McbCreateSIDFromList(auth, dwMaxAuthorities, 
        (char*)dwSubAuthorities);
					   
      
    return true;

}/* McbSIDImpl<n>::McbSetString */

/**
 ****************************************************************************
 * <P> Allocate a SID (S-1-5) based on NT authority 
 * (SECURITY_NT_SID_AUTHORITY).
 *
 * The SECURITY_NT_AUTHORITY (S-1-5) predefined identifier authority produces 
 * SIDs that are not universal but are meaningful only on Windows NT/Windows 
 * 2000 installations. The following RID values can be used with 
 * SECURITY_NT_AUTHORITY to create well-known SIDs. 
 *
 * Constant                             Identifies 
 ****************************************************************************
 * SECURITY_DIALUP_RID                  Users who log on to terminals using a 
 * (S-1-5-1)                            dial-up modem. This is a group 
 *                                      identifier. 
 * SECURITY_NETWORK_RID                 Users who can log on across a network. 
 * (S-1-5-2)                            This is a group identifier. 
 * SECURITY_BATCH_RID                   Users who can log on using a batch 
 * (S-1-5-3)                            queue facility. This is a group 
 *                                      identifier. 
 * SECURITY_INTERACTIVE_RID             Users who can log on for interactive 
 * (S-1-5-4)                            operation. This is a group identifier. 
 * SECURITY_LOGON_IDS_RID               A logon session. This is used to 
 * (S-1-5-5-X-Y)                        ensure that only processes in a given 
 *                                      logon session can gain access to the 
 *                                      window-station objects for that 
 *                                      session. The X and Y values for these 
 *                                      SIDs are different for each logon 
 *                                      session. The value 
 *                                      SECURITY_LOGON_IDS_RID_COUNT is the 
 *                                      number of RIDs in this identifier 
 *                                      (5-X-Y). 
 * SECURITY_SERVICE_RID                 Accounts authorized to log on as a 
 * (S-1-5-6)                            service. 
 * SECURITY_ANONYMOUS_LOGON_RID         Anonymous logon, or null session 
 * (S-1-5-7)							logon. 
 * SECURITY_PROXY_RID
 * (S-1-5-8)   
 * SECURITY_ENTERPRISE_CONTROLLERS_RID
 * (S-1-5-9) 
 * SECURITY_PRINCIPAL_SELF_RID          The PRINCIPAL_SELF security 
 * (S-1-5-10)                           identifier can be used in the ACL of 
 *                                      a user or group object. During an 
 *                                      access check, the system replaces the 
 *                                      SID with the SID of the object. The 
 *                                      PRINCIPAL_SELF SID is useful for 
 *                                      specifying an inheritable ACE that 
 *                                      applies to the user or group object 
 *                                      that inherits the ACE. It the only 
 *                                      way of representing the SID of a 
 *                                      created object in the default 
 *                                      security descriptor in the schema.  
 * SECURITY_AUTHENTICATED_USER_RID      The authenticated users. 
 * (S-1-5-11) 
 * SECURITY_RESTRICTED_CODE_RID         Restricted code. 
 * (S-1-5-12) 
 * SECURITY_TERMINAL_SERVER_RID         Terminal Services: Automatically 
 * (S-1-5-13)							added to the security token of a user
 *                                      who logs on to a Terminal Server.  
 * SECURITY_LOCAL_SYSTEM_RID            A special account used by the 
 * (S-1-5-18)                           operating system. 
 * SECURITY_NT_NON_UNIQUE
 * (S-1-5-21)   
 * SECURITY_BUILTIN_DOMAIN_RID          The built-in system domain. 
 * (S-1-5-32) 
 ****************************************************************************
 *
 * @methodName  McbSIDImpl<n>::McbCreateNTSID
 *
 * @param       nSubAuthorityCount		
 * @param       ...		
 *
 * @return      void
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	28th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbSIDImpl<n>::McbCreateNTSID(BYTE nSubAuthorityCount, 
												  ...)
{
    SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;

   /*
    *************************************************************************
    * initialise variable args
    *************************************************************************
    */
	va_list marker;
    va_start(marker, nSubAuthorityCount);

    McbCreateSIDFromList(auth, nSubAuthorityCount, marker);

    va_end(marker);

}/* McbSIDImpl<n>::McbCreateNTSID */

/**
 ****************************************************************************
 * <P> Allocate a SID (S-1-0) based on null authority 
 * (SECURITY_NULL_SID_AUTHORITY).  If 0 is passed for the sub authority 
 * count then a NULL sid will be created (S-1-0-0).  This is a security 
 * identifier which represents a group with no members. This is often used 
 * when a SID value is not known. </P>
 *
 * @methodName  McbSIDImpl<n>::McbCreateNullSID
 *
 * @param       nSubAuthorityCount		
 * @param       ...		
 *
 * @return      void
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	28th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbSIDImpl<n>::McbCreateNullSID(BYTE nSubAuthorityCount, 
													...)
{
    SID_IDENTIFIER_AUTHORITY auth = SECURITY_NULL_SID_AUTHORITY;

    if (nSubAuthorityCount == 0)
    {
        McbCreateSID(auth, 1, SECURITY_NULL_RID);
        return;
    }

   /*
    *************************************************************************
    * initialise variable args
    *************************************************************************
    */
	va_list marker;
    va_start(marker, nSubAuthorityCount);

    McbCreateSIDFromList(auth, nSubAuthorityCount, marker);

    va_end(marker);

}/* McbSIDImpl<n>::McbCreateNullSID */

/**
 ****************************************************************************
 * <P> Allocate a SID (S-1-1) based on WORLD authority 
 * (SECURITY_WORLD_SID_AUTHORITY).  If 0 is passed for the sub authority 
 * count then a world sid will be created (S-1-1-0).  This is a 
 * security identifier that includes all users (everyone group). </P>
 *
 * @methodName  McbSIDImpl<n>::McbCreateWorldSID
 *
 * @param       nSubAuthorityCount		
 * @param       ...		
 *
 * @return      void
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	28th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbSIDImpl<n>::McbCreateWorldSID(BYTE nSubAuthorityCount, 
													 ...)
{
    SID_IDENTIFIER_AUTHORITY auth = SECURITY_WORLD_SID_AUTHORITY;

    if (nSubAuthorityCount == 0)
    {
        McbCreateSID(auth, 1, SECURITY_WORLD_RID);
        return;
    }

   /*
    *************************************************************************
    * initialise variable args
    *************************************************************************
    */
	va_list marker;
    va_start(marker, nSubAuthorityCount);

    McbCreateSIDFromList(auth, nSubAuthorityCount, marker);

    va_end(marker);

}/* McbSIDImpl<n>::McbCreateWorldSID */

/**
 ****************************************************************************
 * <P> Allocate a SID (S-1-2) based on local authority 
 * (SECURITY_LOCAL_SID_AUTHORITY).  If 0 is passed for the sub authority 
 * count then a local sid will be created (S-1-2-0).  This is a 
 * security identifier which represents users who log on to terminals locally 
 * (physically) connected to the system.</P>
 *
 * @methodName  McbSIDImpl<n>::McbCreateLocalSID
 *
 * @param       nSubAuthorityCount		
 * @param       ...		
 *
 * @return      void
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	28th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbSIDImpl<n>::McbCreateLocalSID(BYTE nSubAuthorityCount, 
													 ...)
{
    SID_IDENTIFIER_AUTHORITY auth = SECURITY_LOCAL_SID_AUTHORITY;

    if (nSubAuthorityCount == 0)
    {
        McbCreateSID(auth, 1, SECURITY_LOCAL_RID);
        return;
    }

   /*
    *************************************************************************
    * initialise variable args
    *************************************************************************
    */
	va_list marker;
    va_start(marker, nSubAuthorityCount);

    McbCreateSIDFromList(auth, nSubAuthorityCount, marker);

    va_end(marker);

}/* McbSIDImpl<n>::McbCreateLocalSID */

/**
 ****************************************************************************
 * <P> Allocate a SID (S-1-3) based on creator authority 
 * (SECURITY_CREATOR_SID_AUTHORITY).  If 0 is passed for the sub authority 
 * count then a creator owner sid will be created (S-1-3-0).  This is a 
 * security identifier to be replaced by the security identifier of the user 
 * who created a new object. This SID is used in inheritable ACEs.</P>
 *
 * @methodName  McbSIDImpl<n>::McbCreateCreatorSID
 *
 * @param       nSubAuthorityCount		
 * @param       ...		
 *
 * @return      void
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	28th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbSIDImpl<n>::McbCreateCreatorSID(
	BYTE nSubAuthorityCount, ...)
{
    SID_IDENTIFIER_AUTHORITY auth = SECURITY_CREATOR_SID_AUTHORITY;

    if (nSubAuthorityCount == 0)
    {
        McbCreateSID(auth, 1, SECURITY_CREATOR_OWNER_RID);
        return;
    }

   /*
    *************************************************************************
    * initialise variable args
    *************************************************************************
    */
	va_list marker;
    va_start(marker, nSubAuthorityCount);


    McbCreateSIDFromList(auth, nSubAuthorityCount, marker);

    va_end(marker);

}/* McbSIDImpl<n>::McbCreateCreatorSID */

/**
 ****************************************************************************
 * <P> Allocate any type of sid. </P>
 *
 * @methodName  McbSIDImpl<n>::McbCreateSID
 *
 * @param       SID_IDENTIFIER_AUTHORITY &auth		
 * @param       nSubAuthorityCount		
 * @param       ...		
 *
 * @return      void
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	28th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbSIDImpl<n>::McbCreateSID(
	const SID_IDENTIFIER_AUTHORITY &auth, BYTE nSubAuthorityCount, ...)
{
   /*
    *************************************************************************
    * initialise variable args
    *************************************************************************
    */
	va_list marker;
    va_start(marker, nSubAuthorityCount);    

    McbCreateSIDFromList(auth, nSubAuthorityCount, marker);

    va_end(marker);

}/* McbSIDImpl<n>::McbCreateSID */

/**
 ****************************************************************************
 * <P> Allocate a SID </P>
 *
 * @methodName  McbSIDImpl<n>::McbCreateSIDFromList
 *
 * @param       McbSIDAuthority &auth		
 * @param       ...		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	15th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbSIDImpl<n>::McbCreateSIDFromList(
	const SID_IDENTIFIER_AUTHORITY &authority, BYTE nSubAuthorityCount, 
	va_list marker)
{	
   /*
    *************************************************************************
    * free existing sid
    *************************************************************************
    */
	McbFree();

   /*
    *************************************************************************
    * calculate length of new sid
    *************************************************************************
    */
	DWORD cbSid = ::GetSidLengthRequired(nSubAuthorityCount);

   /*
    *************************************************************************
    * create buffer for new sid then initialise it
    *************************************************************************
    */
	m_pSid = (PSID)McbHEAPALLOC(cbSid);

	::InitializeSid(m_pSid, (PSID_IDENTIFIER_AUTHORITY)
			&authority, nSubAuthorityCount);

   /*
    *************************************************************************
    * obtain sub authorities from optional arguments
    *************************************************************************
    */
	for(BYTE nCount =0; nCount < nSubAuthorityCount; nCount++)	 
	{        
        DWORD dw = va_arg(marker, DWORD);				
        (*::GetSidSubAuthority(m_pSid, nCount)) = dw;
	}
  
}/* McbSIDImpl<n>::McbCreateSIDFromList */

/**
 ****************************************************************************
 * <P> **** overtype summary description **** </P>
 *
 * @methodName  McbSIDImpl<n>::operator==
 *
 * @param       SID &other		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	16th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSIDImpl<n>::operator==(const PSID pSid)
{
	return ::EqualSid(m_pSid, (PSID)pSid) == TRUE;

}/* McbSIDImpl<n>::operator */

/**
 ****************************************************************************
 * <P> Obtains details about the type of sid </P>
 *
 * @methodName  McbSIDImpl<n>::McbGetSidUse
 *
 * @param       &sidUse		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	24th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSIDImpl<n>::McbGetSidUse(LPCTSTR lpszSystem, 
	SID_NAME_USE &sidUse) const
{
	if (!m_pSid)
	{
		return false;
	}

	DWORD cbName = 0, cbDomain = 0;

   /*
    *************************************************************************
    * calculate size of buffers
    *************************************************************************
    */
	::LookupAccountSid(lpszSystem, m_pSid, NULL, &cbName, NULL, &cbDomain, 
		&sidUse);

   /*
    *************************************************************************
    * buffers for 'out' data
    *************************************************************************
    */
	std::basic_string<TCHAR> strDomain, strName;

   /*
    *************************************************************************
    * ensure out buffers are large enough
    *************************************************************************
    */
	strDomain.resize(cbDomain+1);
	strName.resize(cbName+1);
	
   /*
    *************************************************************************
    * Lookup the sid again
    *************************************************************************
    */
	return ::LookupAccountSid(
		lpszSystem, 
		m_pSid, 
		(std::basic_string<TCHAR>::pointer) strName.data(),
		&cbName, 
		(std::basic_string<TCHAR>::pointer) strDomain.data(), 
		&cbDomain, 
		&sidUse) == TRUE;

}/* McbSIDImpl<n>::McbGetSidUse */

/**
 ****************************************************************************
 * <P> Set the account to be associated with the sid</P>
 *
 * @methodName  McbSIDImpl<n>::McbSetAccount
 *
 * @param       lpszSystem		
 * @param       lpszAccount		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	24th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSIDImpl<n>::McbSetAccount(LPCTSTR lpszSystem, 
												 LPCTSTR lpszAccount)
{
   /*
    *************************************************************************
    * free existing sid
    *************************************************************************
    */
	McbFree();	

	DWORD cbSid = 0;
	DWORD cbDomain = 0;
    SID_NAME_USE sidUse;
	
   /*
    *************************************************************************
    * calculate the size of the required buffers
    *************************************************************************
    */
	::LookupAccountName(
		lpszSystem,				// system name
		lpszAccount,		    // account name
		NULL,					// security identifier (NULL to calculate 
								// size)
		&cbSid,					// size fo security identifier
		NULL,					// domain name (NULL to calculate size)
		&cbDomain,				// size of domain name
		&sidUse);				// type of size indicator

   /*
    *************************************************************************
    * create buffer large enough to hold domain
    *************************************************************************
    */
	std::basic_string<TCHAR> strDomain;
    if (cbDomain)
    {
	    strDomain.resize(cbDomain+1);
    }
		
   /*
    *************************************************************************
    * create buffer for new sid
    *************************************************************************
    */
    if (cbSid)
    {
	    m_pSid = (PSID)McbHEAPALLOC(cbSid);	
    }

   /*
    *************************************************************************
    * prime return value
    *************************************************************************
    */
	bool bResult = false;

   /*
    *************************************************************************
    * obtain required sid
    *************************************************************************
    */
	if (::LookupAccountName(
		lpszSystem,				// system name
		lpszAccount,		    // account name
		m_pSid,					// security identifier
		&cbSid,					// size fo security identifier
		(std::basic_string<TCHAR>::pointer) strDomain.data(),// domain name
		&cbDomain,				// size of domain name
		&sidUse))				// type of size indicator
	{	
		bResult = true;	
	}
   /*
    *************************************************************************
    * ...if sid could not be obtained
    *************************************************************************
    */
    else 
    {
		McbFree();
   		
    }/* end else */

	return bResult;

}/* McbSIDImpl<n>::McbSetAccount */

/**
 ****************************************************************************
 * <P> Obtain the account associated with the sid. </P>
 *
 * @methodName  McbSIDImpl<n>::McbGetAccount
 *
 * @param       std::basic_string<TCHAR> &strSystem		
 * @param       &strDomain		
 * @param       &sidUse		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	18th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSIDImpl<n>::McbGetAccount(LPCTSTR lpszSystem, 
	std::basic_string<TCHAR> &strName, std::basic_string<TCHAR> &strDomain) 
	const
{
	if (!m_pSid)
	{
		return false;
	}
	
    SID_NAME_USE sidUse;
	DWORD cbName = 0, cbDomain = 0;

   /*
    *************************************************************************
    * calculate size of buffers
    *************************************************************************
    */
	::LookupAccountSid(lpszSystem, m_pSid, NULL, &cbName, NULL, &cbDomain, 
		&sidUse);

   /*
    *************************************************************************
    * ensure out buffers are large enough
    *************************************************************************
    */
	if (cbDomain && strDomain.size() < cbDomain+1) 
	{	
		strDomain.resize(cbDomain+1);
	}

	if (cbName && strName.size() < cbName+1) 
	{
		strName.resize(cbName+1);
	}

	return ::LookupAccountSid(
		lpszSystem, 
		m_pSid, 
		(std::basic_string<TCHAR>::pointer) strName.data(),
		&cbName, 
		(std::basic_string<TCHAR>::pointer) strDomain.data(), 
		&cbDomain, 
		&sidUse) == TRUE;

}/* McbSIDImpl<n>::McbGetAccount */

/**
 ****************************************************************************
 * <P> Tests whether a SID is valid by first calling ::IsValidSid() then 
 * attempting to obtain the account information for the sid. </P>
 *
 * @methodName  McbSIDImpl<n>::McbIsValid
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
 *	22nd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSIDImpl<n>::McbIsValid(LPCTSTR lpszSystem) const
{	
	if (!m_pSid || !::IsValidSid(m_pSid))
	{
		return false;
	}
	
	std::basic_string<TCHAR> strName;
	std::basic_string<TCHAR> strDomain;
	
	return McbGetAccount(lpszSystem, strName, strDomain);

}/* McbSIDImpl<n>::McbIsValid */

/*
 ****************************************************************************
 * MACROS to help in the generation of SIDs
 ****************************************************************************
 */

/*
 ****************************************************************************
 * Generate NULL sid
 ****************************************************************************
 */
#define McbNULLSID(theMcbSid)													\
    theMcbSid.McbCreateNullSID(1, SECURITY_NULL_RID)

/*
 ****************************************************************************
 * Generate CREATOR OWNER sid
 ****************************************************************************
 */
#define McbCREATOROWNERSID(theMcbSid)											\
    theMcbSid.McbCreateCreatorSID(1, SECURITY_CREATOR_OWNER_RID)

/*
 ****************************************************************************
 * Generate CREATOR GROUP sid
 ****************************************************************************
 */
#define McbCREATORGROUPSID(theMcbSid)											\
    theMcbSid.McbCreateCreatorSID(1, SECURITY_CREATOR_GROUP_RID)

/*
 ****************************************************************************
 * Generate LOCAL sid
 ****************************************************************************
 */
#define McbLOCALSID(theMcbSid)										        \
    theMcbSid.McbCreateLocalSID(1, SECURITY_LOCAL_RID)

/*
 ****************************************************************************
 * Generate WORLD sid (everyone group)
 ****************************************************************************
 */
#define McbWORLDSID(theMcbSid)										        \
    theMcbSid.McbCreateWorldSID(1, SECURITY_WORLD_RID)

/*
 ****************************************************************************
 * Generate LOCAL ADMINSTRATORS GROUP sid 
 * A local group used for administration of the domain.
 ****************************************************************************
 */
#define McbLOCALADMINSSID(theMcbSid)											\
    theMcbSid.McbCreateNTSID(2, SECURITY_BUILTIN_DOMAIN_RID,                  \
        DOMAIN_ALIAS_RID_ADMINS)

/*
 ****************************************************************************
 * Generate LOCAL GUESTS GROUP sid
 * A local group representing guests of the domain.
 ****************************************************************************
 */
#define McbLOCALGUESTSSID(theMcbSid)											\
    theMcbSid.McbCreateNTSID(2, SECURITY_BUILTIN_DOMAIN_RID,                  \
        DOMAIN_ALIAS_RID_GUESTS)

/*
 ****************************************************************************
 * Generate LOCAL USERS GROUP sid
 * A local group representing all users in the domain.
 ****************************************************************************
 */
#define McbLOCALUSERSSID(theMcbSid)											\
    theMcbSid.McbCreateNTSID(2, SECURITY_BUILTIN_DOMAIN_RID,                  \
        DOMAIN_ALIAS_RID_USERS)

/*
 ****************************************************************************
 * Generate LOCAL POWER USERS GROUP sid
 * A local group used to represent a user or set of users who expect to treat 
 * a system as if it were their personal computer rather than as a 
 * workstation for multiple users.
 ****************************************************************************
 */
#define McbLOCALPOWERUSERSSID(theMcbSid)										\
    theMcbSid.McbCreateNTSID(2, SECURITY_BUILTIN_DOMAIN_RID,                  \
        DOMAIN_ALIAS_RID_POWER_USERS)

/*
 ****************************************************************************
 * Generate LOCAL ACCOUNT OPERATIONS GROUP sid
 * A local group existing only on systems running Windows NT Server/Windows 
 * 2000 Server. This local group permits control over non-administrator 
 * accounts.
 ****************************************************************************
 */
#define McbLOCALACCOUNTSOPSSID(theMcbSid)										\
    theMcbSid.McbCreateNTSID(2, SECURITY_BUILTIN_DOMAIN_RID,                  \
        DOMAIN_ALIAS_RID_ACCOUNT_OPS)

/*
 ****************************************************************************
 * Generate LOCAL SYSTEM OPERATIONS GROUP sid
 * A local group existing only on systems running Windows NT Server/Windows 
 * 2000 Server. This local group performs system administrative functions, 
 * not including security functions. It establishes network shares, controls 
 * printers, unlocks workstations, and performs other operations.
 ****************************************************************************
 */
#define McbLOCALSYSTEMOPSSID(theMcbSid)										\
    theMcbSid.McbCreateNTSID(2, SECURITY_BUILTIN_DOMAIN_RID,                  \
        DOMAIN_ALIAS_RID_SYSTEM_OPS)

/*
 ****************************************************************************
 * Generate LOCAL PRINTERS GROUP sid
 * A local group existing only on systems running Windows NT Server/Windows 
 * 2000 Server. This local group controls printers and print queues.
 ****************************************************************************
 */
#define McbLOCALPRINTEROPSSID(theMcbSid)										\
    theMcbSid.McbCreateNTSID(2, SECURITY_BUILTIN_DOMAIN_RID,                  \
        DOMAIN_ALIAS_RID_PRINT_OPS)

/*
 ****************************************************************************
 * Generate LOCAL BACKUP OPERATIONS GROUP sid
 * A local group used for controlling assignment of file backup-and-restore 
 * privileges.
 ****************************************************************************
 */
#define McbLOCALBACKUPOPSSID(theMcbSid)										\
    theMcbSid.McbCreateNTSID(2, SECURITY_BUILTIN_DOMAIN_RID,                  \
        DOMAIN_ALIAS_RID_BACKUP_OPS)

/*
 ****************************************************************************
 * Generate LOCAL REPLICATORS GROUP sid
 * A local group responsible for copying security databases from the primary 
 * domain controller to the backup domain controllers. These accounts are 
 * used only by the system.
 ****************************************************************************
 */
#define McbLOCALREPLICATORSSID(theMcbSid)										\
    theMcbSid.McbCreateNTSID(2, SECURITY_BUILTIN_DOMAIN_RID,                  \
        DOMAIN_ALIAS_RID_REPLICATOR)

//////////////////////////////////////////////////////////////////////////////
// COMMENTED OUT @17:51:09, on 28th February  2000
///*
// ****************************************************************************
// * Generate LOCAL RAS SERVERS GROUP sid
// * A local group representing RAS and IAS servers. This group permits access 
// * to various attributes of user objects.
// ****************************************************************************
// */
//#define Mcb_LOCAL_RAS_SERVERS_SID(theMcbSid)							      \
//    theMcbSid.McbCreateNTSID(2, SECURITY_BUILTIN_DOMAIN_RID,                  \
//        DOMAIN_ALIAS_RID_RAS_SERVERS)
//////////////////////////////////////////////////////////////////////////////

/*
 ****************************************************************************
 * typedef for pointer to an access control entry
 ****************************************************************************
 */
typedef LPVOID PACE;

/**
 ****************************************************************************
 * <P> Access Control Entries (ACE) - An access control entry specifies
 * access to an NT resource.  It contains exactly one SID, an access mask 
 * which specifies what type of access is applied to the resource.  An ACE 
 * can be one of the following types:
 *		access allowed type -	implying access is allowed to the resource 
 *								(or restricted),
 *		access denied type	-	implying access is denied,
 *		system audit		-	for auditing events (such as when someone
 *								attempted to gain access to a resource).
 * </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *	16th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> class McbACEImpl
{
public:
   /*
    *************************************************************************
    * C'tion/D'tion
    *************************************************************************
    */	
	McbACEImpl(const PACE pAce = NULL);	
	McbACEImpl(const McbACEImpl &other)
		: m_pAce(NULL) { *this = other.m_pAce; }
	~McbACEImpl() { McbFree(); }

   /*
    *************************************************************************
    * operator overloads
    *************************************************************************
    */
	PACE operator=(const PACE pAce);	
	McbACEImpl & operator=(const McbACEImpl &other) 
        { *this = other.m_pAce; return *this;}

	operator PACE() { return m_pAce; }	
	operator const PACE() const { return m_pAce; }	
		
   /*
    *************************************************************************
    * functionality
    *************************************************************************
    */
	BYTE McbGetType() const 
		{ return m_pAce ? ((ACE_HEADER*)m_pAce)->AceType : 0; }

	inline PSID McbGetSID() const;

	ACCESS_MASK McbGetAccessMask() const 
		{ return m_pAce ? ((ACCESS_ALLOWED_ACE*)m_pAce)->Mask : 0; }

	BYTE McbGetControlFlags() const 
		{ return m_pAce ? ((ACE_HEADER*)m_pAce)->AceFlags : 0; }

	DWORD McbGetSize() const 
		{ return m_pAce ? ((ACE_HEADER*)m_pAce)->AceSize : 0; }

	inline bool McbIsAllowedAccess() const;	
	inline bool McbIsDeniedAccess() const;	
	inline bool McbIsSystemAudit() const;	

	void McbSetSID(const PSID pSid);
	void McbSetAllowedAccess();
	void McbSetDeniedAccess();
	
    
   /*
    *************************************************************************
    * Note the SUCCESSFUL_ACCESS_ACE_FLAG and FAILED_ACCESS_ACE_FLAG as 
    * specified in the ace's CONTROL FLAGS when creating system audit aces.
    *************************************************************************
    */
	void McbSetSystemAudit();

	void McbSetType(BYTE nType);

   /*
    *************************************************************************
    * 
    * CONTROL FLAGS for the ACE
    *
	* Constant(s)			    Meaning
	* -----------------------------------------------------------------------
    * CONTAINER_INHERIT_ACE     Child objects that are containers, such as 
    *                               directories, inherit the ACE as an 
    *                               effective ACE. The inherited ACE is 
    *                               inheritable unless the 
    *                               NO_PROPAGATE_INHERIT_ACE bit flag is also 
    *                               set.  
    * FAILED_ACCESS_ACE_FLAG    Used with system-audit ACEs in a SACL to 
    *                               generate audit messages for failed access 
    *                               attempts. 
    * INHERIT_ONLY_ACE          Indicates an inherit-only ACE which does not 
    *                               control access to the object to which it 
    *                               is attached. If this flag is not set, the 
    *                               ACE is an effective ACE which controls 
    *                               access to the object to which it is 
    *                               attached. 
    *                               Both effective and inherit-only ACEs can 
    *                               be inherited depending on the state of 
    *                               the other inheritance flags. 
    * NO_PROPAGATE_INHERIT_ACE  If the ACE is inherited by a child object, 
    *                               the system clears the OBJECT_INHERIT_ACE 
    *                               and CONTAINER_INHERIT_ACE flags in the 
    *                               inherited ACE. This prevents the ACE from 
    *                               being inherited by subsequent generations 
    *                               of objects.  
    * OBJECT_INHERIT_ACE        Noncontainer child objects inherit the ACE as 
    *                               an effective ACE. 
    *                               For child objects that are containers, 
    *                               the ACE is inherited as an inherit-only 
    *                               ACE unless the NO_PROPAGATE_INHERIT_ACE 
    *                               bit flag is also set.
    * SUCCESSFUL_ACCESS_ACE_FLAG Used with system-audit ACEs in a SACL to 
    *                               generate audit messages for successful 
    *                               access attempts. 
    *************************************************************************
    */
    void McbSetControlFlags(BYTE nFlags);

   /*
    *************************************************************************
    * Sets up the access mask for the access control entry.  Access masks 
	* are bit fields which contain generic and specific rights.
    *************************************************************************
	*
	* STANDARD access masks
	*
	* Constant(s)				Access				
	* -----------------------------------------------------------------------
	* DELETE                    The right to delete the object. 
	* READ_CONTROL              The right to read the information in the 
    *                               object's security descriptor, not 
    *                               including the information in the SACL. 
	* SYNCHRONIZE               The right to use the object for 
    *                               synchronization. This enables a thread to 
    *                               wait until the object is in the signaled 
    *                               state. Some object types do not support 
    *                               this access right. 
	* WRITE_DAC                 The right to modify the DACL in the object's 
    *                               security descriptor. 
	* WRITE_OWNER               The right to change the owner in the object's 
    *                               security descriptor. 
    * STANDARD_RIGHTS_ALL       Combines DELETE, READ_CONTROL, WRITE_DAC, 
    *                               WRITE_OWNER, and SYNCHRONIZE access. 
    * STANDARD_RIGHTS_EXECUTE   Currently defined to equal READ_CONTROL. 
    * STANDARD_RIGHTS_READ      Currently defined to equal READ_CONTROL. 
    * STANDARD_RIGHTS_REQUIRED  Combines DELETE, READ_CONTROL, WRITE_DAC, 
    *                               and WRITE_OWNER access. 
    * STANDARD_RIGHTS_WRITE     Currently defined to equal READ_CONTROL. 
	*
    *************************************************************************
    *
	* Typical FILE access masks (see permissions from a file security dialog)
	*
	* Constant(s)				Access				Meaning
	* -----------------------------------------------------------------------
	* FILE_GENERIC_READ |		Change(RWXD)		Read, Write, Execute, 	
	*	FILE_GENERIC_WRITE |							Delete
	*	FILE_GENERIC_EXECUTE | 
	*	DELETE					
	* FILE_GENERIC_READ |		Read(RX)			Read, Execute
	*	FILE_GENERIC_WRITE
	* FILE_GENERIC_READ			Special Access(R)	Read	
	* FILE_GENERIC_WRITE		Special Access(W)	Write
	* FILE_GENERIC_EXECUTE		Special Access(X)	Execute
	* DELETE					Special Access(D)	Delete
	* WRITE_DAC					Special Access(P)	Change Permissions
	* WRITE_OWNER				Special Access(0)	Take Ownership
	* FILE_ALL_ACCESS			Full Control(all)	Full Control
    *
	* Note that when using access denied types with files, the access mask
	* should be set to FILE_ALL_ACCESS.
    *
    *************************************************************************
    *
    * REGISTRY access masks
    *
    * Constant(s)				Access				
	* -----------------------------------------------------------------------
    * KEY_CREATE_LINK           Permission to create a symbolic link. 
    * KEY_CREATE_SUB_KEY        Permission to create subkeys. 
    * KEY_ENUMERATE_SUB_KEYS    Permission to enumerate subkeys. 
    * KEY_EXECUTE               Permission for read access. 
    * KEY_NOTIFY                Permission for change notification. 
    * KEY_QUERY_VALUE           Permission to query subkey data. 
    * KEY_SET_VALUE             Permission to set subkey data. 
    * KEY_ALL_ACCESS            Combines the KEY_QUERY_VALUE, 
    *                               KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, 
    *                               KEY_CREATE_SUB_KEY, KEY_CREATE_LINK, and 
    *                               KEY_SET_VALUE access rights, plus all the 
    *                               standard access rights except SYNCHRONIZE.  
    * KEY_READ                  Combines the STANDARD_RIGHTS_READ, 
    *                               KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, 
    *                               and KEY_NOTIFY access rights. 
    * KEY_WRITE                 Combines the STANDARD_RIGHTS_WRITE, 
    *                               KEY_SET_VALUE, and KEY_CREATE_SUB_KEY 
    *                               access rights. 
    *************************************************************************
    *
    * PROCESS access masks
    *
    * Any combination of the following access flags can be specified in 
    * addition to the STANDARD_RIGHTS_REQUIRED access flags.
    *
    * Constant(s)				Access				Meaning
	* -----------------------------------------------------------------------
	* PROCESS_ALL_ACCESS        Specifies all possible access flags for the 
    *                               process object. 
	* PROCESS_CREATE_PROCESS    Used internally. 
	* PROCESS_CREATE_THREAD     Enables using the process handle in the 
    *                               CreateRemoteThread function to create a 
    *                               thread in the process. 
	* PROCESS_DUP_HANDLE        Enables using the process handle as either 
    *                               the source or target process in the 
    *                               DuplicateHandle function to duplicate a 
    *                               handle. 
	* PROCESS_QUERY_INFORMATION Enables using the process handle in the 
    *                               GetExitCodeProcess and GetPriorityClass 
    *                               functions to read information from the 
    *                               process object. 
	* PROCESS_SET_QUOTA         Enables using the process handle in the 
    *                               AssignProcessToJobObject and 
    *                               SetProcessWorkingSetSize functions to set 
    *                               memory limits.  
	* PROCESS_SET_INFORMATION   Enables using the process handle in the 
    *                               SetPriorityClass function to set the 
    *                               priority class of the process. 
	* PROCESS_TERMINATE         Enables using the process handle in the 
    *                                   TerminateProcess function to  
    *                                   terminate the process. 
	* PROCESS_VM_OPERATION      Enables using the process handle in the 
    *                                   VirtualProtectEx and  
    *                                   WriteProcessMemory functions to 
    *                                   modify the virtual memory of the 
	*									process. 
	* PROCESS_VM_READ           Enables using the process handle in the 
    *                                   ReadProcessMemory function to read 
    *                                   from the virtual memory of the 
	*									process. 
	* PROCESS_VM_WRITE          Enables using the process handle in the 
    *                                   WriteProcessMemory function to write
    *                                   to the virtual memory of the process. 
	* SYNCHRONIZE               Enables using the process handle in any of 
    *                                   the wait functions to wait for the 
    *                                   process to terminate. 
    *************************************************************************
    */
	void McbSetAccessMask(ACCESS_MASK mask);

	static DWORD McbGetSizeACE(const PACE lpAce);

	bool McbIsValid(LPCTSTR lpszSystem = NULL) const;

	std::basic_string<TCHAR> McbDump() const;
	std::basic_string<TCHAR> McbDumpXML() const;

protected:
   /*
    *************************************************************************
    * functionality
    *************************************************************************
    */
	inline void McbFree();	

   /*
    *************************************************************************
    * members
    *************************************************************************
    */	
	PACE m_pAce;
};

/**
 ****************************************************************************
 * <P> Free the resource. </P>
 *
 * @methodName	McbACEImpl<n>::McbFree
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
 *	18th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbACEImpl<n>::McbFree()
{
	if (m_pAce)
	{
		McbHEAPFREE(m_pAce);
		m_pAce = NULL;
	}

}/* McbACEImpl<n>::McbFree */

/**
 ****************************************************************************
 * <P> Tests whether type if is access allowed. </P>
 *
 * @methodName	McbACEImpl<n>::McbIsAllowedAccess
 *
 * @param       none
 *
 * @return      bool
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	18th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbACEImpl<n>::McbIsAllowedAccess() const
{ 
	if (!m_pAce)
	{
		return false;
	}

	return ((ACE_HEADER*)m_pAce)->AceType == ACCESS_ALLOWED_ACE_TYPE; 

}/* McbACEImpl<n>::McbIsAllowedAccess */

/**
 ****************************************************************************
 * <P> Tests whether type if is access denied. </P>
 *
 * @methodName	McbACEImpl<n>::McbIsDeniedAccess
 *
 * @param       none
 *
 * @return      bool
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	18th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbACEImpl<n>::McbIsDeniedAccess() const
{
	if (!m_pAce)
	{
		return false;
	}

	return ((ACE_HEADER*)m_pAce)->AceType == ACCESS_DENIED_ACE_TYPE; 

}/* McbACEImpl<n>::McbIsDeniedAccess */

/**
 ****************************************************************************
 * <P> Tests whether type if is system audit. </P>
 *
 * @methodName	McbACEImpl<n>::McbIsSystemAudit
 *
 * @param       none
 *
 * @return      bool
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	18th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbACEImpl<n>::McbIsSystemAudit() const 
{
	if (!m_pAce)
	{
		return false;
	}

	return ((ACE_HEADER*)m_pAce)->AceType == SYSTEM_AUDIT_ACE_TYPE; 

}/* McbACEImpl<n>::McbIsSystemAudit */

/**
 ****************************************************************************
 * <P> Obtain the sid from the ace. </P>
 *
 * @methodName	McbACEImpl<n>::McbGetSID
 *
 * @param       none
 *
 * @return      PSID
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	18th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> PSID McbACEImpl<n>::McbGetSID() const	
{
	if (!m_pAce)
	{
		return NULL;
	}
	
	return (PSID)&((PACCESS_ALLOWED_ACE)m_pAce)->SidStart;

}/* McbACEImpl<n>::McbGetSID */

/**
 ****************************************************************************
 * <P> C'tor </P>
 *
 * @methodName  McbACEImpl<n>::McbACE
 *
 * @param       ACCESS_ALLOWED_ACE &other		
 *
 * @return      none
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	16th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> McbACEImpl<n>::McbACEImpl(const PACE pAce) : m_pAce(NULL)
{
	*this = pAce;

}/* McbACEImpl<n>::McbACE */


/**
 ****************************************************************************
 * <P> **** overtype summary description **** </P>
 *
 * @methodName  McbACEImpl<n>::McbSetSID
 *
 * @param       PSID pSid		
 *
 * @return      void
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	21st February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbACEImpl<n>::McbSetSID(const PSID pSid)
{
   /*
    *************************************************************************
    * use default sid if NULL passed in as SID
    *************************************************************************
    */
	McbSID defaultSid;
	PSID pUseSid = pSid;

	if (!pSid)
	{
		defaultSid.McbCreateNullSID();
		pUseSid = (PSID)defaultSid;
	}
	
	DWORD cbSid = ::GetLengthSid(pUseSid);
	DWORD cbAce = sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + cbSid;

   /*
    *************************************************************************
    * allocate memory for new ACE
    *************************************************************************
    */
	PACE pAce = (PSID)McbHEAPALLOC(cbAce);	

   /*
    *************************************************************************
    * if previous ace exists
    *************************************************************************
    */
	if (m_pAce)
	{
       /*
        *********************************************************************
        * shallow copy part of previous ace
        *********************************************************************
        */
		*((ACCESS_ALLOWED_ACE*)pAce) = *((ACCESS_ALLOWED_ACE*)m_pAce);
	}
   /*
    *************************************************************************
    * set defaults for ace if no previous ace exists
    *************************************************************************
    */
    else 
    {
       /*
        *********************************************************************
        * default ace is access allowed
        *********************************************************************
        */
		((ACE_HEADER*)pAce)->AceType = ACCESS_ALLOWED_ACE_TYPE;
		((ACE_HEADER*)pAce)->AceFlags = 0; //CONTAINER_INHERIT_ACE;		

       /*
        *********************************************************************
        * all access rights
        *********************************************************************
        */
		((ACCESS_ALLOWED_ACE*)pAce)->Mask = FILE_ALL_ACCESS;
   		
    }/* end else */

   /*
    *************************************************************************
    * set ace size
    *************************************************************************
    */
	((ACE_HEADER*)pAce)->AceSize = (WORD)cbAce;

   /*
    *************************************************************************
    * take copy of sid 
    *************************************************************************
    */	
	::CopySid(cbSid, &((ACCESS_ALLOWED_ACE*)pAce)->SidStart, pUseSid);
	
   /*
    *************************************************************************
    * free previous ACE
    *************************************************************************
    */
	McbFree();

   /*
    *************************************************************************
    * set member to pointer to new ACE
    *************************************************************************
    */
	m_pAce = pAce;

}/* McbACEImpl<n>::McbSetSID */

/**
 ****************************************************************************
 * <P> Sets the type of ace. </P>
 *
 * @methodName  McbACEImpl<n>::McbSetType
 *
 * @param       nTypes		
 *
 * @return      void
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	21st February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbACEImpl<n>::McbSetType(BYTE nType)
{
   /*
    *************************************************************************
    * create default ACE if non-existant
    *************************************************************************
    */
	if (!m_pAce)
	{
		McbSetSID(NULL);
	}

   /*
    *************************************************************************
    * set the type
    *************************************************************************
    */
	((ACE_HEADER*)m_pAce)->AceType = nType;

}/* McbACEImpl<n>::McbSetType */

/**
 ****************************************************************************
 * <P> **** overtype summary description **** </P>
 *
 * @methodName  McbACEImpl<n>::McbSetControlFlags
 *
 * @param       nFlags		
 *
 * @return      void
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	21st February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbACEImpl<n>::McbSetControlFlags(BYTE nFlags)
{
   /*
    *************************************************************************
    * create default ACE if non-existant
    *************************************************************************
    */
	if (!m_pAce)
	{
		McbSetSID(NULL);
	}

   /*
    *************************************************************************
    * set the flags
    *************************************************************************
    */
	((ACE_HEADER*)m_pAce)->AceFlags = nFlags;

}/* McbACEImpl<n>::McbSetControlFlags */

/**
 ****************************************************************************
 * <P> Sets up the access mask for the access control entry.</P>
 *
 * @methodName  McbACEImpl<n>::McbSetAccessMask
 *
 * @param       mask		
 *
 * @return      void
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	21st February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbACEImpl<n>::McbSetAccessMask(ACCESS_MASK mask)
{
   /*
    *************************************************************************
    * create default ACE if non-existant
    *************************************************************************
    */
	if (!m_pAce)
	{
		McbSetSID(NULL);
	}

   /*
    *************************************************************************
    * set the mask
    *************************************************************************
    */
	((ACCESS_ALLOWED_ACE*)m_pAce)->Mask = mask;

}/* McbACEImpl<n>::McbSetAccessMask */

/**
 ****************************************************************************
 * <P> Sets the type of ACE to access allowed </P>
 *
 * @methodName  McbACEImpl<n>::McbSetAllowedAccess
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
 *	21st February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbACEImpl<n>::McbSetAllowedAccess()
{
   /*
    *************************************************************************
    * create default ace if not created
    *************************************************************************
    */
	if (!m_pAce)
	{
		McbSetSID(NULL);
	}

   /*
    *************************************************************************
    * set type to allowed access
    *************************************************************************
    */
	((ACE_HEADER*)m_pAce)->AceType = ACCESS_ALLOWED_ACE_TYPE; 

}/* McbACEImpl<n>::McbSetAllowedAccess */

/**
 ****************************************************************************
 * <P> Sets the type of ACE to access denied. </P>
 *
 * @methodName  McbACEImpl<n>::McbSetDeniedAccess
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
 *	21st February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbACEImpl<n>::McbSetDeniedAccess()
{
   /*
    *************************************************************************
    * create default ace if not created
    *************************************************************************
    */
	if (!m_pAce)
	{
		McbSetSID(NULL);
	}

   /*
    *************************************************************************
    * set type to denied access
    *************************************************************************
    */
	((ACE_HEADER*)m_pAce)->AceType = ACCESS_DENIED_ACE_TYPE; 

}/* McbACEImpl<n>::McbSetDeniedAccess */

/**
 ****************************************************************************
 * <P> Sets the type of ACE to system audit. </P>
 *
 * @methodName  McbACEImpl<n>::McbSetSystemAudit
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
 *	21st February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbACEImpl<n>::McbSetSystemAudit()
{
   /*
    *************************************************************************
    * create default ace if not created
    *************************************************************************
    */
	if (!m_pAce)
	{
		McbSetSID(NULL);
	}

   /*
    *************************************************************************
    * set type to system audit
    *************************************************************************
    */
	((ACE_HEADER*)m_pAce)->AceType = SYSTEM_AUDIT_ACE_TYPE; 

}/* McbACEImpl<n>::McbSetSystemAudit */

/**
 ****************************************************************************
 * <P> **** overtype summary description **** </P>
 *
 * @methodName  & McbACEImpl<n>::operator=
 *
 * @param       ACCESS_DENIED_ACE &other		
 *
 * @return      McbACE
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	16th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> PACE McbACEImpl<n>::operator=(const PACE pAce)
{
	if ((LPBYTE)pAce != (LPBYTE)m_pAce)
	{
		McbFree();

		if (pAce)
		{			
			
           /*
            *****************************************************************
            * obtain sid from passed in ACE
            *****************************************************************
            */
			PSID pSid = &((ACCESS_ALLOWED_ACE*)pAce)->SidStart;
			DWORD cbSid = ::GetLengthSid(pSid);

           /*
            *****************************************************************
            * obtain sid on new ACE and allocate it on the heap
            *****************************************************************
            */
			DWORD cbAce = sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + cbSid;
			
			m_pAce = (PSID)McbHEAPALLOC(cbAce);	

           /*
            *****************************************************************
            * shallow copy first part of ace
            *****************************************************************
            */
			*((ACCESS_ALLOWED_ACE *)m_pAce) = *((ACCESS_ALLOWED_ACE *)pAce);

           /*
            *****************************************************************
            * copy sid from source ace to destination ace
            *****************************************************************
            */
			::CopySid(cbSid, &(((ACCESS_ALLOWED_ACE*)m_pAce)->SidStart), 
				(PSID)pSid);
			
//////////////////////////////////////////////////////////////////////////////
// COMMENTED OUT @17:10:20, on 18th February  2000
//           /*
//            *****************************************************************
//            * create new ACE and copy contents
//            *****************************************************************
//            */
//			switch(((ACE_HEADER *)pAce)->AceType)
//			{
//				
//			case ACCESS_ALLOWED_ACE_TYPE:
//				m_pAce = new ACCESS_ALLOWED_ACE;
//				*((ACCESS_ALLOWED_ACE *)m_pAce) = *((ACCESS_ALLOWED_ACE *)pAce);
//				break;
//				
//			case ACCESS_DENIED_ACE_TYPE:
//				m_pAce = new ACCESS_DENIED_ACE;
//				*((ACCESS_DENIED_ACE *)m_pAce) = *((ACCESS_DENIED_ACE *)pAce);
//				break;
//				
//			case SYSTEM_AUDIT_ACE_TYPE:
//				m_pAce = new SYSTEM_AUDIT_ACE;
//				*((SYSTEM_AUDIT_ACE *)m_pAce) = *((SYSTEM_AUDIT_ACE *)pAce);
//				
//			}//////////////////////////////////////////////////////////////////////////////

		}
	}

	return m_pAce;

}/* & McbACEImpl<n>::operator= */

/**
 ****************************************************************************
 * <P> **** overtype summary description **** </P>
 *
 * @methodName  McbACEImpl<n>::McbGetSizeACE
 *
 * @param       PACE lpAce		
 *
 * @return      DWORD
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	22nd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> DWORD McbACEImpl<n>::McbGetSizeACE(const PACE lpAce)
{
	if (!lpAce)
	{
		return 0;
	}

   /*
    *************************************************************************
    * default size of sid as 4 (size of DWORD)
    *************************************************************************
    */
	DWORD cbSid = 4;
	PSID pSid = &((ACCESS_ALLOWED_ACE*)lpAce)->SidStart;

   /*
    *************************************************************************
    * if the ace contains a valid sid then obtain its size
    *************************************************************************
    */
	if (::IsValidSid(pSid)) //*((DWORD*)pSid))
	{		
		cbSid = ::GetLengthSid(pSid);
	}

   /*
    *************************************************************************
    * obtain size of new ace
    *************************************************************************
    */	
	switch(((ACE_HEADER *)lpAce)->AceType)
	{
	case ACCESS_ALLOWED_ACE_TYPE:
		return sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + cbSid;		

	case ACCESS_DENIED_ACE_TYPE:
		return sizeof(ACCESS_DENIED_ACE) - sizeof(DWORD) + cbSid;		

	case SYSTEM_AUDIT_ACE_TYPE:
		return sizeof(SYSTEM_AUDIT_ACE) - sizeof(DWORD) + cbSid;		
		
	default:
		return 0;		
	}

}/* McbACEImpl<n>::McbGetSizeACE */

/**
 ****************************************************************************
 * <P> Validates an ACE.  Checks whether the sid is valid, the type specified
 * in the ace header is valid, and that the size of the ace specifed in the
 * ace header matches the actual size of the ace.</P>
 *
 * @methodName  McbACEImpl<n>::McbIsValid
 *
 * @param       none
 *
 * @return      bool
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	22nd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbACEImpl<n>::McbIsValid(LPCTSTR lpszSystem) const
{
	if (!m_pAce)
	{
		return false;
	}
	
   /*
    *************************************************************************
    * validate the sid part of the ace
    *************************************************************************
    */
	McbSID sid(&((ACCESS_ALLOWED_ACE*)m_pAce)->SidStart);

	if (!sid.McbIsValid(lpszSystem))
	{
		return false;
	}

   /*
    *************************************************************************
    * validate the type of ace
    *************************************************************************
    */	
	switch(((ACE_HEADER *)m_pAce)->AceType)
	{
	case ACCESS_ALLOWED_ACE_TYPE:		
	case ACCESS_DENIED_ACE_TYPE:		
	case SYSTEM_AUDIT_ACE_TYPE:
		break;
		
	default:
		return false;		
	}

   /*
    *************************************************************************
    * ensure the size specified in the header equates to the size for the 
	* specific type of ACE plus the size of the contained sid
    *************************************************************************
    */
	if (McbGetSizeACE(m_pAce) != ((ACE_HEADER*)m_pAce)->AceSize)
	{
		return false;
	}

	return true;


}/* McbACEImpl<n>::McbIsValid */

/**
 ****************************************************************************
 * <P> Access Control Lists (ACL) - An Access control list is a list of 
 * access control entries.  There are two types of access control lists:
 *	Discretional Access Control List (DACL) - a DACL specifies access to 
 *		a resource an can contain allowed or denied access control entries,
 *	System Access Control List (SACL) - a SACL specifies auditing of events
 *		and can contain system audit access control entries.</P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *	17th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> class McbACLImpl
{
public:
   /*
    *************************************************************************
    * C'tion/D'tion
    *************************************************************************
    */
	McbACLImpl(const PACL pAcl = NULL);
	McbACLImpl(const McbACLImpl &other) : m_pAcl(NULL) 
		{ *this = other.m_pAcl; }
	~McbACLImpl() { McbFree(); }

   /*
    *************************************************************************
    * operator overloads
    *************************************************************************
    */
	PACL operator=(const PACL pAcl);
	McbACLImpl & operator=(const McbACLImpl &other) 
        { *this = other.m_pAcl; return *this; }

	operator PACL() { return m_pAcl; }
	operator const PACL() const { return m_pAcl; }

   /*
    *************************************************************************
    * Functionality
    *************************************************************************
    */
	BYTE McbGetRevision() const { return m_pAcl ? m_pAcl->AclRevision : 0; }
	DWORD McbGetSize() const { return m_pAcl ? m_pAcl->AclSize : 0; }
	DWORD McbGetACECount() const { return m_pAcl ? m_pAcl->AceCount : 0; }

	PACE McbGetACE(DWORD nIndex) const;
	bool McbInsertACE(const PACE lpAce, DWORD dwIndex);	

	bool McbAppendACE(const PACE lpAce) 
		{ return McbInsertACE(lpAce, MAXDWORD); }

	bool McbDeleteACE(DWORD dwIndex);

	void McbCreateEmptyACL();	
	int McbExtendACL(DWORD dwSizeExtend);

	bool McbIsValid(DWORD &dwBadACE) const;
	bool McbReOrder();
	DWORD McbRemoveInvalidACES();

	std::basic_string<TCHAR> McbDump() const;
	std::basic_string<TCHAR> McbDumpXML() const;

protected:
   /*
    *************************************************************************
    * functionality
    *************************************************************************
    */
	bool McbInsertACE(const PACE lpAce, DWORD dwIndex, DWORD dwSizeACE);
	inline void McbFree();

	static int McbExtendAndCopyACL(const PACL lpOldAcl, DWORD dwSizeExtend, 
		PACL &lpNewAcl);

   /*
    *************************************************************************
    * members
    *************************************************************************
    */
	PACL m_pAcl;
};

/**
 ****************************************************************************
 * <P> Free the resource. </P>
 *
 * @methodName	McbACLImpl<n>::McbFree
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
 *	18th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbACLImpl<n>::McbFree()
{
	if (m_pAcl)
	{
		McbHEAPFREE(m_pAcl);
		m_pAcl = NULL;
	}

}/* McbACLImpl<n>::McbFree */

/**
 ****************************************************************************
 * <P> **** overtype summary description **** </P>
 *
 * @methodName  McbACLImpl<n>::McbACL
 *
 * @param       none
 *
 * @return      none
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	17th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> McbACLImpl<n>::McbACLImpl(const PACL pAcl) : m_pAcl(NULL)
{
	*this = pAcl;

}/* McbACLImpl<n>::McbACL */

/**
 ****************************************************************************
 * <P> **** overtype summary description **** </P>
 *
 * @methodName  McbACLImpl<n>::McbGetACE
 *
 * @param       nIndex		
 *
 * @return      McbACE
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	17th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> PACE McbACLImpl<n>::McbGetACE(DWORD nIndex) const
{
	LPVOID lpAce = NULL;

	if (::GetAce((PACL)m_pAcl, nIndex, &lpAce))
	{
		return (PACE)lpAce;
	}

	return NULL;
		
}/* McbACLImpl<n>::McbGetACE */

/**
 ****************************************************************************
 * <P> **** overtype summary description **** </P>
 *
 * @methodName  McbACLImpl<n>::McbAddACE
 *
 * @param       ACCESS_ALLOWED_ACE &other		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	17th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbACLImpl<n>::McbInsertACE(const PACE lpAce, 
												DWORD dwIndex)
{
   /*
    *************************************************************************
    * obtain size of new ace
    *************************************************************************
    */
	DWORD dwSizeACE = McbACE::McbGetSizeACE(lpAce);

	if (dwSizeACE == 0)
	{
		return false;
	}

	return McbInsertACE(lpAce, dwIndex, dwSizeACE);

}

/**
 ****************************************************************************
 * <P> Given an access control list and a size to extend, this function 
 * allocates room for the old access control list + number of bytes specified 
 * in the size to extend then attempts to copy access control entries from 
 * the old access control list into the new one.  The total number of access
 * control entries added to the new access control list is the return value.
 * The new access control list will be NULL if the old access control list 
 * pointer was NULL. </P>
 *
 * @methodName  McbACLImpl<n>::McbExtendAndCopyACL
 *
 * @param       PACL lpOldAcl		
 * @param       dwSizeExtend		
 * @param       &lpNewAcl		
 *
 * @return      int
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	22nd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> int McbACLImpl<n>::McbExtendAndCopyACL(const PACL lpOldAcl, 
	DWORD dwSizeExtend, PACL &lpNewAcl)
{
	lpNewAcl = NULL;

   /*
    *************************************************************************
    * return if source acl does not exist
    *************************************************************************
    */
	if (!lpOldAcl)
	{
		return 0;
	}

	ACL_SIZE_INFORMATION AclSize;

   /*
    *************************************************************************
    * obtain current size of acl
    *************************************************************************
    */
	if (::GetAclInformation(
		lpOldAcl,						// access-control list
		&AclSize,						// ACL information
		sizeof(ACL_SIZE_INFORMATION),	// size of ACL information
		AclSizeInformation))			// info class
	{		
       /*
        *********************************************************************
        * create new acl with enough room for new ace
        *********************************************************************
        */
		DWORD cbNewAcl = AclSize.AclBytesInUse + dwSizeExtend;

		lpNewAcl = (PACL) McbHEAPALLOC(cbNewAcl);
		
		::InitializeAcl(lpNewAcl, cbNewAcl, ACL_REVISION);

       /*
        *********************************************************************
        * iterate through each ace on old acl 
        *********************************************************************
        */
		LPVOID lpAce;		
		int nAddedAces = 0;		
		for (int nAce = 0; nAce < lpOldAcl->AceCount; nAce++)
		{
           /*
            *****************************************************************
            * obtain old ace and add to new list
            *****************************************************************
            */
			if (::GetAce(lpOldAcl, nAce,(void**) &lpAce))
			{
				if (::AddAce(lpNewAcl, ACL_REVISION, MAXDWORD, lpAce, 
					((ACE_HEADER*)lpAce)->AceSize))
				{
					nAddedAces++;
				}

			}
		}	

       /*
        *********************************************************************
        * Return total number of access added.
        *********************************************************************
        */
		return nAddedAces;

	}

	return 0;

}/* McbACLImpl<n>::McbExtendAndCopyACL */

/**
 ****************************************************************************
 * <P> **** overtype summary description **** </P>
 *
 * @methodName  McbACLImpl<n>::McbExtendACL
 *
 * @param       dwSizeExtend		
 *
 * @return      int
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	22nd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> int McbACLImpl<n>::McbExtendACL(DWORD dwSizeExtend)
{
	PACL lpNewAcl;
	int nAces = McbExtendAndCopyACL(m_pAcl, dwSizeExtend, lpNewAcl);

   /*
    *************************************************************************
    * if a new acl was allocated...
    *************************************************************************
    */
	if (lpNewAcl)
	{
       /*
        *********************************************************************
        * if the correct number of ace's were copied
        *********************************************************************
        */
		if ((McbGetACECount() == nAces))
		{			
           /*
            *****************************************************************
            * free current acl
            *****************************************************************
            */
            McbFree();

           /*
            *****************************************************************
            * point to the new acl
            *****************************************************************
            */
            m_pAcl = lpNewAcl;

			return true;
		}

       /*
        *********************************************************************
        * delete the new acl
        *********************************************************************
        */
		McbHEAPFREE(lpNewAcl); 
       		
	}

	return false;

}/* McbACLImpl<n>::McbExtendACL */

/**
 ****************************************************************************
 * <P> **** overtype summary description **** </P>
 *
 * @methodName  McbACLImpl<n>::McbInsertACE
 *
 * @param       ACCESS_ALLOWED_ACE &other		
 * @param       dwIndex		
 * @param       dwSizeACE		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	18th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbACLImpl<n>::McbInsertACE(const PACE lpAce, 
	DWORD dwIndex, DWORD dwSizeACE)
{	
   /*
    *************************************************************************
    * create empty acl if not already created.
    *************************************************************************
    */
	if (!m_pAcl)
	{
		McbCreateEmptyACL();
	}

   /*
    *************************************************************************
    * create new acl large enough to hold previous ace's and the new one
    *************************************************************************
    */
	PACL lpNewAcl;
	int nAces = McbExtendAndCopyACL(m_pAcl, dwSizeACE, lpNewAcl);

   /*
    *************************************************************************
    * if a new acl was allocated...
    *************************************************************************
    */
	if (lpNewAcl)
	{
       /*
        *********************************************************************
        * if the correct number of ace's were copied
        *********************************************************************
        */
		if ((McbGetACECount() == nAces))
		{
			if (dwIndex > (DWORD)nAces) dwIndex = MAXDWORD;

           /*
            *****************************************************************
            * attempt to add ace the new acl
            *****************************************************************
            */
			if (::AddAce(lpNewAcl, ACL_REVISION, dwIndex, lpAce, dwSizeACE))
			{
               /*
                *************************************************************
                * free current acl
                *************************************************************
                */
				McbFree();

               /*
                *************************************************************
                * point to the new acl
                *************************************************************
                */
				m_pAcl = lpNewAcl;

				return true;

			}
		}

       /*
        *********************************************************************
        * delete the new acl
        *********************************************************************
        */
		McbHEAPFREE(lpNewAcl); 
       		
	}

	return false;

}/* McbACLImpl<n>::McbAddACE */

/**
 ****************************************************************************
 * <P> **** overtype summary description **** </P>
 *
 * @methodName  McbACLImpl<n>::McbCreateEmptyACL
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
 *	18th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbACLImpl<n>::McbCreateEmptyACL()
{
	McbFree();

	DWORD cbAcl = sizeof(ACL);

	m_pAcl = (PACL)McbHEAPALLOC(cbAcl);
	
	::InitializeAcl(m_pAcl, cbAcl, ACL_REVISION);
  
}/* McbACLImpl<n>::McbCreateEmptyACL */

/**
 ****************************************************************************
 * <P> **** overtype summary description **** </P>
 *
 * @methodName  McbACLImpl<n>::operator=
 *
 * @param       PACE pAce		
 *
 * @return      PACE
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	18th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> PACL McbACLImpl<n>::operator=(const PACL pAcl)
{
	if ((LPBYTE)pAcl != (LPBYTE)m_pAcl)
	{
		McbFree();

		if (pAcl)
		{
			ACL_SIZE_INFORMATION AclSize;
			
           /*
            *****************************************************************
            * obtain current size of acl
            *****************************************************************
            */
			if (::GetAclInformation(
				pAcl,							// access-control list
				&AclSize,						// ACL information
				sizeof(ACL_SIZE_INFORMATION),	// size of ACL information
				AclSizeInformation))			// info class
			{		
               /*
                *************************************************************
                * create new acl with enough room for new ace
                *************************************************************
                */
				DWORD cbNewAcl = AclSize.AclBytesInUse;

				m_pAcl = (PACL)McbHEAPALLOC(cbNewAcl);			
				
				::InitializeAcl(m_pAcl, cbNewAcl, ACL_REVISION);
								
               /*
                *************************************************************
                * iterate through each ace on passed in acl 
                *************************************************************
                */
				LPVOID lpAce;						
				for (int nAce = 0; nAce < pAcl->AceCount; nAce++)
				{
                   /*
                    *********************************************************
                    * obtain old ace and add to new list
                    *********************************************************
                    */
					if (::GetAce(pAcl, nAce,(void**) &lpAce))
					{
						::AddAce(m_pAcl, ACL_REVISION, MAXDWORD, lpAce, 
							((ACE_HEADER*)lpAce)->AceSize);
						
					}
				}	
			}				
		}
	}

	return m_pAcl;

}/* McbACLImpl<n>::operator= */


/**
 ****************************************************************************
 * <P> Validates an ACL.  Calls Win32 ::IsValidAcl(), obtains each ace from 
 * the acl, then validates the sid belonging to the ace by attempting to 
 * obtain the name of the account based on the sid.  Returns false if any 
 * part of the ACL is invalid.  If a sid or ace is in error then a zero based 
 * index representing the ace is returned in dwBadACE.  If the acl is in 
 * error for any other reason (not related to an ace or sid) then dwBadACE 
 * will be -1. </P>
 *
 * @methodName  McbACLImpl<n>::McbIsValid
 *
 * @param       none
 *
 * @return      bool
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	22nd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbACLImpl<n>::McbIsValid(DWORD &dwBadACE) const 
{
	dwBadACE = -1;

   /*
    *************************************************************************
    * ensure pointer is valid and revision for acl is valid
    *************************************************************************
    */
	if (!m_pAcl || !::IsValidAcl(m_pAcl))
	{
		return false;
	}

   /*
    *************************************************************************
    * count of aces as according to access control list structure
    *************************************************************************
    */
	DWORD dwAceCount = McbGetACECount();
	
   /*
    *************************************************************************
    * iterate through each ace in access control list
    *************************************************************************
    */
	PACE pAce;
	for (DWORD dwAce=0; dwAce<dwAceCount; dwAce++)
	{
		pAce = McbGetACE(dwAce);

       /*
        *********************************************************************
        * return if ace could not be obtained
        *********************************************************************
        */
		if (!pAce)
		{
			dwBadACE = dwAce;
			return false;
		}
		
       /*
        *********************************************************************
        * validate the ace
        *********************************************************************
        */
		McbACE ace(pAce);
		if (!ace.McbIsValid())
		{
			dwBadACE = dwAce;
			return false;
		}
	}

	return true;

}/* McbACLImpl<n>::McbIsValid */

/**
 ****************************************************************************
 * <P> Removes invalid aces from the list </P>
 *
 * @methodName  McbACLImpl<n>::McbRemoveInvalidACES
 *
 * @param       none
 *
 * @return      DWORD
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	24th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> DWORD McbACLImpl<n>::McbRemoveInvalidACES()
{
	DWORD dwTotalBad = 0;
	DWORD dwBadACE;

	while(!McbIsValid(dwBadACE))
	{
		if (McbDeleteACE(dwBadACE))
		{
			dwTotalBad++;
		}
	}

	return dwTotalBad;

}/* McbACLImpl<n>::McbRemoveInvalidACES */

/**
 ****************************************************************************
 * <P> Re-orders the ACL so that access denied access control entries precede
 * access allowed entries.  Returns true if the order was changed.</P>
 *
 * @methodName  McbACLImpl<n>::McbReOrder
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
 *	22nd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbACLImpl<n>::McbReOrder()
{
	if (!m_pAcl)
	{
		return false;
	}

	DWORD dwAceCount = McbGetACECount();

	if (dwAceCount < 2)
	{
		return false;
	}

   /*
    *************************************************************************
    * list of access denied and access allowed entries
    *************************************************************************
    */
	McbACL aclDenied;
	McbACL aclAllowed;

	PACE pAce;

	bool bHasAllowedEntries = false;
	bool bIsBadOrder = false;

	for(DWORD dwAce=0; dwAce<dwAceCount; dwAce++)
	{
		pAce = McbGetACE(dwAce);

		if (!pAce)
		{
			return false;
		}

       /*
        *********************************************************************
        * the access control entry should not be an audit type
        *********************************************************************
        */
		McbACE ace(pAce);
		if (ace.McbIsSystemAudit())
		{
			return false;
		}
		
       /*
        *********************************************************************
        * add ace to the appropriate list
        *********************************************************************
        */
		if (ace.McbIsAllowedAccess())
		{
			bHasAllowedEntries = true;

			if (!aclAllowed.McbAppendACE((PACE)ace))
			{
				return false;
			}
		}
		else
		{
           /*
            *****************************************************************
            * if a allowed entry has been encountered (followed by an denied
			* entry) then the order is bad
            *****************************************************************
            */
			if (bHasAllowedEntries)
			{
				bIsBadOrder = true;
			}			

			if (!aclDenied.McbAppendACE((PACE)ace))
			{
				return false;
			}
		}
	}

   /*
    *************************************************************************
    * if the acl order is bad
    *************************************************************************
    */
	if (bIsBadOrder)
	{				
       /*
        *********************************************************************
        * add entries from the allowed access control list to denied list
        *********************************************************************
        */
		dwAceCount = aclAllowed.McbGetACECount();
		for(dwAce = 0; dwAce < dwAceCount; dwAce++)
		{
			pAce = aclAllowed.McbGetACE(dwAce);

			if (!pAce || !aclDenied.McbAppendACE(pAce))
			{
				return false;
			}
		}

       /*
        *********************************************************************
        * set contents of this acl to the denied access control list which 
		* now has the allowed access control entries added to the end
        *********************************************************************
        */
		*this = (PACL)aclDenied;

       /*
        *********************************************************************
        * Return true as the contents of the access control list have changed
        *********************************************************************
        */
		return true;
	}
			
	return false;

}/* McbACLImpl<n>::McbReorder */

/**
 ****************************************************************************
 * <P> Deletes an access control entry from the list </P>
 *
 * @methodName  McbACLImpl<n>::McbDeleteACE
 *
 * @param       dwIndex		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	22nd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbACLImpl<n>::McbDeleteACE(DWORD dwIndex)
{
	if (!m_pAcl)
	{
		return false;
	}

	return ::DeleteAce(m_pAcl, dwIndex) == TRUE;
  
}/* McbACLImpl<n>::McbDeleteACE */

/**
 ****************************************************************************
 * <P> Security descriptors - a security descriptor is used to describe the
 * security associated with an NT resource.  A security descriptor contains
 * a security identifier for the owner of the resource (owner SID), a 
 * security identifier for the primary group (group SID), a discretionary 
 * access control list (DACL) and a system access control list (SACL).</P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *	22nd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> class McbSecurityDescriptorImpl
{
public:
   /*
    *************************************************************************
    * C'tion/D'tion
    *************************************************************************
    */
	McbSecurityDescriptorImpl(const PSECURITY_DESCRIPTOR pSD = NULL);
	McbSecurityDescriptorImpl(const McbSecurityDescriptorImpl &other) : 
		m_pSD(NULL) { *this = other.m_pSD; }

	~McbSecurityDescriptorImpl() { McbFree(); }

   /*
    *************************************************************************
    * operator overloads
    *************************************************************************
    */
	PSECURITY_DESCRIPTOR operator=(const PSECURITY_DESCRIPTOR pSec);
	McbSecurityDescriptorImpl & operator=(const McbSecurityDescriptorImpl 
		&other) { *this = other.m_pSD; return *this; }

	operator PSECURITY_DESCRIPTOR() { return m_pSD; }
	operator const PSECURITY_DESCRIPTOR() const { return m_pSD; }
	
   /*
    *************************************************************************
    * accessors/modifiers
    *************************************************************************
    */
	bool McbSetDACLDefault();	
	bool McbSetDACL(const PACL pAcl);	

	PACL McbGetDACL() const;
	bool McbIsDefaultDACL() const;
	bool McbIsPresentDACL() const;

	bool McbSetSACLDefault();	
	bool McbSetSACL(const PACL pAcl);
	
	PACL McbGetSACL() const;
	bool McbIsDefaultSACL() const;
	bool McbIsPresentSACL() const;

	bool McbSetSIDOwnerDefault();
	bool McbSetSIDOwner(const PSID pSid);

	bool McbIsDefaultSIDOwner() const;
	PSID McbGetSIDOwner() const;

	bool McbSetSIDGroupDefault();
	bool McbSetSIDGroup(const PSID pSid);

	bool McbIsDefaultSIDGroup() const;
	PSID McbGetSIDGroup() const;

   /*
    *************************************************************************
    * functionality
    *************************************************************************
    */
	enum Info { 
		UpdateDacl	= DACL_SECURITY_INFORMATION,
		UpdateSacl	= SACL_SECURITY_INFORMATION,
		UpdateGroup	= GROUP_SECURITY_INFORMATION,
		UpdateOwner	= OWNER_SECURITY_INFORMATION };

   /*
    *************************************************************************
    * set security information for file
    * If false is returned then GetLastError() can be used to obtain details.
    *************************************************************************
    */
	bool McbGetFromFile(HANDLE hFile, 
		DWORD dwSecurityInfo = UpdateDacl | UpdateSacl | UpdateGroup | 
		UpdateOwner)
        { return McbGetFromObject(hFile, SE_FILE_OBJECT, dwSecurityInfo); }

    bool McbGetFromFile(LPCTSTR lpszFile, 
        DWORD dwSecurityInfo = UpdateDacl | UpdateSacl | UpdateGroup | 
		UpdateOwner);

   /*
    *************************************************************************
    * obtain security information for a service (local or remote)
    * If false is returned then GetLastError() can be used to obtain details.
    *************************************************************************
    */
    bool McbGetFromService(HANDLE hService, 
		DWORD dwSecurityInfo = UpdateDacl | UpdateSacl | UpdateGroup | 
		UpdateOwner)
		{ return McbGetFromObject(hService, SE_SERVICE, dwSecurityInfo); }

   /*
    *************************************************************************
    * obtain security information for a printer (locate or remote)
    * If false is returned then GetLastError() can be used to obtain details.
    *************************************************************************
    */
    bool McbGetFromPrinter(HANDLE hPrinter, 
		DWORD dwSecurityInfo = UpdateDacl | UpdateSacl | UpdateGroup | 
		UpdateOwner)
        { return McbGetFromObject(hPrinter, SE_PRINTER, dwSecurityInfo); }

   /*
    *************************************************************************
    * obtain security information for registry
    * If false is returned then GetLastError() can be used to obtain details.
    *************************************************************************
    */
    bool McbGetFromRegistryKey(HKEY hKeyRoot, LPCTSTR lpszSubKey, 
        DWORD dwSecurityInfo = UpdateDacl | UpdateSacl | UpdateGroup | 
		UpdateOwner);

   /*
    *************************************************************************
    * obtain security information for a registry key
    * If false is returned then GetLastError() can be used to obtain details.
    *************************************************************************
    */
    bool McbGetFromRegistryKey(HANDLE hKey, 
		DWORD dwSecurityInfo = UpdateDacl | UpdateSacl | UpdateGroup | 
		UpdateOwner)
        { return McbGetFromObject(hKey, SE_REGISTRY_KEY, dwSecurityInfo); }

   /*
    *************************************************************************
    * obtain security information for a network share (local or remote)
    * If false is returned then GetLastError() can be used to obtain details.
    *************************************************************************
    */
    bool McbGetFromNetworkShare(HANDLE hLMShare, 
		DWORD dwSecurityInfo = UpdateDacl | UpdateSacl | UpdateGroup | 
		UpdateOwner)
        { return McbGetFromObject(hLMShare, SE_LMSHARE, dwSecurityInfo); }

   /*
    *************************************************************************
    * obtain security information for a local kernel object, which includes 
    * the following object types: process, thread, job, semaphore, event, 
    * mutex, file mapping, waitable timer, access token, named pipe, or 
    * anonymous pipe. 
    * If false is returned then GetLastError() can be used to obtain details.
    *************************************************************************
    */
    bool McbGetFromKernelObject(HANDLE hKernObject, 
		DWORD dwSecurityInfo = UpdateDacl | UpdateSacl | UpdateGroup | 
		UpdateOwner)
        { return McbGetFromObject(hKernObject, SE_KERNEL_OBJECT, 
		dwSecurityInfo); }

   /*
    *************************************************************************
    * obtain security information for a window station or desktop object on 
    * the local computer
    * If false is returned then GetLastError() can be used to obtain details.
    *************************************************************************
    */
    bool McbGetFromWindowObject(HANDLE hWndObject, 
		DWORD dwSecurityInfo = UpdateDacl | UpdateSacl | UpdateGroup | 
		UpdateOwner)
        { return McbGetFromObject(hWndObject, SE_WINDOW_OBJECT, 
		dwSecurityInfo); }

   /*
    *************************************************************************
    * update security information for a file
    * If false is returned then GetLastError() can be used to obtain details.
    *************************************************************************
    */
	bool McbSetToFile(HANDLE hFile, 
		DWORD dwSecurityInfo = UpdateDacl | UpdateSacl | UpdateGroup | 
		UpdateOwner) const
        { return McbSetToObject(hFile, SE_FILE_OBJECT, dwSecurityInfo); }

    bool McbSetToFile(LPCTSTR lpszFile, 
        DWORD dwSecurityInfo = UpdateDacl | UpdateSacl | UpdateGroup | 
		UpdateOwner) const;

   /*
    *************************************************************************
    * update security information for a service (local or remote)
    * If false is returned then GetLastError() can be used to obtain details.
    *************************************************************************
    */
    bool McbSetToService(HANDLE hService, 
		DWORD dwSecurityInfo = UpdateDacl | UpdateSacl | UpdateGroup | 
		UpdateOwner) const
        { return McbSetToObject(hService, SE_SERVICE, dwSecurityInfo); }

   /*
    *************************************************************************
    * update security information for a printer (locate or remote)
    * If false is returned then GetLastError() can be used to obtain details.
    *************************************************************************
    */
    bool McbSetToPrinter(HANDLE hPrinter, 
		DWORD dwSecurityInfo = UpdateDacl | UpdateSacl | UpdateGroup | 
		UpdateOwner) const
        { return McbSetToObject(hPrinter, SE_PRINTER, dwSecurityInfo); }

   /*
    *************************************************************************
    * update security information for a registry key
    * If false is returned then GetLastError() can be used to obtain details.
    *************************************************************************
    */
    bool McbSetToRegistryKey(HKEY hKeyRoot, LPCTSTR lpszSubKey, 
        DWORD dwSecurityInfo = UpdateDacl | UpdateSacl | UpdateGroup | 
		UpdateOwner);

    bool McbSetToRegistyKey(HANDLE hKey, 
		DWORD dwSecurityInfo = UpdateDacl | UpdateSacl | UpdateGroup | 
		UpdateOwner) const
        { return McbSetToObject(hKey, SE_REGISTRY_KEY, dwSecurityInfo); }

   /*
    *************************************************************************
    * update security information for a network share (local or remote)
    * If false is returned then GetLastError() can be used to obtain details.
    *************************************************************************
    */
    bool McbSetToNetworkShare(HANDLE hLMShare, 
		DWORD dwSecurityInfo = UpdateDacl | UpdateSacl | UpdateGroup | 
		UpdateOwner) const
        { return McbSetToObject(hLMShare, SE_LMSHARE, dwSecurityInfo); }

   /*
    *************************************************************************
    * update security information for a local kernel object, which includes 
    * the following object types: process, thread, job, semaphore, event, 
    * mutex, file mapping, waitable timer, access token, named pipe, or 
    * anonymous pipe. 
    * If false is returned then GetLastError() can be used to obtain details.
    *************************************************************************
    */
    bool McbSetToKernelObject(HANDLE hKernObject, 
		DWORD dwSecurityInfo = UpdateDacl | UpdateSacl | UpdateGroup | 
		UpdateOwner) const
        { return McbSetToObject(hKernObject, SE_KERNEL_OBJECT, 
		dwSecurityInfo); }

   /*
    *************************************************************************
    * update security information for a window station or desktop object on 
    * the local computer
    * If false is returned then GetLastError() can be used to obtain details.
    *************************************************************************
    */
    bool McbSetToWindowObject(HANDLE hWndObject, 
		DWORD dwSecurityInfo = UpdateDacl | UpdateSacl | UpdateGroup | 
		UpdateOwner) const
        { return McbSetToObject(hWndObject, SE_WINDOW_OBJECT, 
		dwSecurityInfo); }

	std::basic_string<TCHAR> McbDump() const;
	std::basic_string<TCHAR> McbDumpXML() const;

	bool McbGetFromObject(HANDLE hObject, SE_OBJECT_TYPE objectType, 
		DWORD dwSecurityInfo = UpdateDacl | UpdateSacl | UpdateGroup | 
		UpdateOwner);

	bool McbSetToObject(HANDLE hObject, SE_OBJECT_TYPE objectType, 
		DWORD dwSecurityInfo = UpdateDacl | UpdateSacl | UpdateGroup | 
		UpdateOwner) const;

protected:

   /*
    *************************************************************************
    * functionality
    *************************************************************************
    */
	inline void McbFree();
	void McbCreateEmpty();
	void McbEnsureAvailable();

   /*
    *************************************************************************
    * members
    *************************************************************************
    */
	PSECURITY_DESCRIPTOR m_pSD;

    McbSIDImpl<0> m_sidOwner;
    McbSIDImpl<0> m_sidGroup;
    McbACLImpl<0> m_dacl;
    McbACLImpl<0> m_sacl;
};

/**
 ****************************************************************************
 * <P> Free the resource. </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbFree
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
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbSecurityDescriptorImpl<n>::McbFree()
{
	if (m_pSD)
	{
		McbHEAPFREE(m_pSD);
		m_pSD = NULL;
	}

}/* McbSecurityDescriptorImpl<n>::McbFree */

/**
 ****************************************************************************
 * <P> Constructor </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbSecurityDescriptor
 *
 * @param       none
 *
 * @return      none
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> McbSecurityDescriptorImpl<n>::McbSecurityDescriptorImpl(
	const PSECURITY_DESCRIPTOR pSD) 
 :	m_pSD(NULL)
{
	*this = pSD;

}/* McbSecurityDescriptorImpl<n>::McbSecurityDescriptor */

/**
 ****************************************************************************
 * <P> Assignment operator </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::operator=
 *
 * @param       PSECURITY_DESCRIPTOR pSD		
 *
 * @return      PSECURITY_DESCRIPTOR
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> PSECURITY_DESCRIPTOR McbSecurityDescriptorImpl<n>::operator=(
	const PSECURITY_DESCRIPTOR pSD) 
{
	if (pSD != m_pSD)
	{
		McbFree();

		if (pSD)
		{
			DWORD cbSD = ::GetSecurityDescriptorLength(pSD);

			m_pSD = McbHEAPALLOC(sizeof(SECURITY_DESCRIPTOR));

           /*
            *****************************************************************
            * create default security descriptor
            *****************************************************************
            */
			::InitializeSecurityDescriptor(m_pSD, 				
				SECURITY_DESCRIPTOR_REVISION);

			BOOL bPresent, bDefault;
			PACL pAcl;
			PSID pSid;          
		
           /*
            *****************************************************************
            * take copies of the owner sid, group sid, sacl and dacl.  This 
            * is done because the ::SetSecurityDescriptorXXXX() sets the 
            * objects as a reference - we have no guarantee that the 
            * security descriptor passed in will stay in scope for the 
            * duration of this McbSecurityDescriptor().
            *****************************************************************
            */

           /*
            *****************************************************************
            * set the dacl for the security descriptor
            *****************************************************************
            */
			if (::GetSecurityDescriptorDacl(pSD, &bPresent, &pAcl, 
				&bDefault))
			{
                if (!bPresent)
                {
                    pAcl = NULL;
                }

                m_dacl = pAcl;

				::SetSecurityDescriptorDacl(m_pSD, bPresent, (PACL)m_dacl, 
                    bDefault);
			}
            else
            {
                m_dacl = NULL;
            }

           /*
            *****************************************************************
            * set the sacl for the security descriptor
            *****************************************************************
            */
			if (::GetSecurityDescriptorSacl(pSD, &bPresent, &pAcl, 
				&bDefault))
			{
                if (!bPresent)
                {
                    pAcl = NULL;
                }

                m_sacl = pAcl;

				::SetSecurityDescriptorSacl(m_pSD, bPresent, (PACL)m_sacl, 
                    bDefault);
			}
            else
            {
                m_sacl = NULL;
            }

           /*
            *****************************************************************
            * set the owner for the security descriptor
            *****************************************************************
            */
			if (::GetSecurityDescriptorOwner(pSD, &pSid, &bDefault))
			{
//////////////////////////////////////////////////////////////////////////////
// COMMENTED OUT @16:20:17, on 19th October   2000
//                if (!bPresent)
//                {
//                    pSid = NULL;
//                }
//////////////////////////////////////////////////////////////////////////////

                m_sidOwner = pSid;

				::SetSecurityDescriptorOwner(m_pSD, (PSID)m_sidOwner, 
					bDefault);
			}
            else
            {
                m_sidOwner = NULL;
            }

           /*
            *****************************************************************
            * set the group for the security descriptor
            *****************************************************************
            */
			if (::GetSecurityDescriptorGroup(pSD, &pSid, &bDefault))
			{
//////////////////////////////////////////////////////////////////////////////
// COMMENTED OUT @16:20:21, on 19th October   2000
//                if (!bPresent)
//                {
//                    pSid = NULL;
//                }
//////////////////////////////////////////////////////////////////////////////

                m_sidGroup = pSid;

				::SetSecurityDescriptorGroup(m_pSD, (PSID)m_sidGroup, 
					bDefault);
			}
            else
            {
                m_sidGroup = NULL;
            }
		}   
	}

	return m_pSD;

}/* McbSecurityDescriptorImpl<n>::operator= */

/**
 ****************************************************************************
 * <P> Creates an empty security descriptor </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbCreateEmpty
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
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbSecurityDescriptorImpl<n>::McbCreateEmpty()
{
	McbFree();
        
	m_pSD = McbHEAPALLOC(sizeof(SECURITY_DESCRIPTOR));

	::InitializeSecurityDescriptor(m_pSD, 				
		SECURITY_DESCRIPTOR_REVISION);

}/* McbSecurityDescriptorImpl<n>::McbCreateEmpty */

/**
 ****************************************************************************
 * <P> Ensures a security descriptor is available by creating a default one 
 * if one does not exist.  </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbEnsureAvailable
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
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbSecurityDescriptorImpl<n>::McbEnsureAvailable()
{
	if (!m_pSD)
	{
		m_pSD = McbHEAPALLOC(sizeof(SECURITY_DESCRIPTOR));

		::InitializeSecurityDescriptor(m_pSD, 				
			SECURITY_DESCRIPTOR_REVISION);
	}

}/* McbSecurityDescriptorImpl<n>::McbEnsureAvailable */

/**
 ****************************************************************************
 * <P> Sets the DACL for the security descriptor to the default - meaning 
 * that if will be obtained from the creator's access token.  </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbSetDACLDefault
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
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSecurityDescriptorImpl<n>::McbSetDACLDefault()
{
	McbEnsureAvailable();

	return ::SetSecurityDescriptorDacl(m_pSD, TRUE, NULL, TRUE) == TRUE;

}/* McbSecurityDescriptorImpl<n>::McbSetDACLDefault */

/**
 ****************************************************************************
 * <P> Sets the DACL for the security descriptor.  If this is NULL then this 
 * will set an empty DACL - meaning that everyone will have access. </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbSetDACL
 *
 * @param       PACL pAcl		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSecurityDescriptorImpl<n>::McbSetDACL(const PACL pAcl)
{
	McbEnsureAvailable();
    
    m_dacl = pAcl;

	return ::SetSecurityDescriptorDacl(m_pSD, (PACL)m_dacl != NULL, 
		(PACL)m_dacl, FALSE) == TRUE;
	
}/* McbSecurityDescriptorImpl<n>::McbSetDACL */

/**
 ****************************************************************************
 * <P> Returns the DACL from the security descriptor.   For an empty DACL, 
 * this will be NULL (implying that everyone has access).  bIsDefault will be
 * set to true if the DACL is a default DACL - meaning that it is obtained
 * from the owners access token.  </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbGetDACL
 *
 * @param       &bIsDefault		
 *
 * @return      PACL
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> PACL McbSecurityDescriptorImpl<n>::McbGetDACL() const
{
	if (!McbIsPresentDACL())
	{		
		return NULL;
	}
	
	return ((SECURITY_DESCRIPTOR*)m_pSD)->Dacl;

}/* McbSecurityDescriptorImpl<n>::McbGetDACL */

/**
 ****************************************************************************
 * <P> Returns true if the DACL is a default DACL - meaning that it is 
 * obtained from the owners access token. </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbIsDefaultDACL
 *
 * @param       none
 *
 * @return      bool
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSecurityDescriptorImpl<n>::McbIsDefaultDACL() const
{
	if (!m_pSD)
	{
		return false;
	}

	return (((SECURITY_DESCRIPTOR*)m_pSD)->Control & SE_DACL_DEFAULTED) !=0;

}/* McbSecurityDescriptorImpl<n>::McbIsDefaultDACL */

/**
 ****************************************************************************
 * <P> Returns true if a DACL is present (if false then this means everyone 
 * has access) </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbIsPresentDACL
 *
 * @param       none
 *
 * @return      bool
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSecurityDescriptorImpl<n>::McbIsPresentDACL() const
{
	if (!m_pSD)
	{
		return false;
	}

	return (((SECURITY_DESCRIPTOR*)m_pSD)->Control & SE_DACL_PRESENT) != 0;

}/* McbSecurityDescriptorImpl<n>::McbIsPresentDACL */

/**
 ****************************************************************************
 * <P> Sets the SACL for the security descriptor to the default - meaning 
 * that if will be obtained from the creator's access token.  </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbSetSACLDefault
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
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSecurityDescriptorImpl<n>::McbSetSACLDefault()
{
	McbEnsureAvailable();

	return ::SetSecurityDescriptorSacl(m_pSD, TRUE, NULL, TRUE) == TRUE;

}/* McbSecurityDescriptorImpl<n>::McbSetSACLDefault */

/**
 ****************************************************************************
 * <P> Sets the SACL for the security descriptor.  If this is NULL then this 
 * will set an empty SACL - no auditing will take place.  </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbSetSACL
 *
 * @param       PACL pAcl		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSecurityDescriptorImpl<n>::McbSetSACL(const PACL pAcl)
{
	McbEnsureAvailable();

    m_sacl = pAcl;

	return ::SetSecurityDescriptorSacl(m_pSD, (BOOL)(PACL)m_sacl, pAcl, 
		FALSE) == TRUE;

}/* McbSecurityDescriptorImpl<n>::McbSetSACL */

/**
 ****************************************************************************
 * <P> Returns the SACL from the security descriptor.   For an empty SACL, 
 * this will be NULL (implying that no auditing will take place).</P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbGetSACL
 *
 * @return      PACL
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> PACL McbSecurityDescriptorImpl<n>::McbGetSACL() const
{
	if (!McbIsPresentSACL())
	{		
		return NULL;
	}
	
	return ((SECURITY_DESCRIPTOR*)m_pSD)->Sacl;

}/* McbSecurityDescriptorImpl<n>::McbGetSACL */

/**
 ****************************************************************************
 * <P> Returns true if the SACL is a default SACL - meaning that it is 
 * obtained from the owners access token. </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbIsDefaultSACL
 *
 * @param       none
 *
 * @return      bool
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSecurityDescriptorImpl<n>::McbIsDefaultSACL() const
{
	if (!m_pSD)
	{
		return false;
	}

	return (((SECURITY_DESCRIPTOR*)m_pSD)->Control & SE_SACL_DEFAULTED) !=0;

}/* McbSecurityDescriptorImpl<n>::McbIsDefaultSACL */

/**
 ****************************************************************************
 * <P> Returns true if a SACL is present (if false then no auditing will take
 * place. </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbIsPresentSACL
 *
 * @param       none
 *
 * @return      bool
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSecurityDescriptorImpl<n>::McbIsPresentSACL() const
{
	if (!m_pSD)
	{
		return false;
	}

	return (((SECURITY_DESCRIPTOR*)m_pSD)->Control & SE_SACL_PRESENT) != 0;

}/* McbSecurityDescriptorImpl<n>::McbIsPresentSACL */

/**
 ****************************************************************************
 * <P> Sets the owner sid for the security descriptor to default.  This 
 * means is will be obtained from the owners access token. </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbSetSIDOwnerDefault
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
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSecurityDescriptorImpl<n>::McbSetSIDOwnerDefault()
{
	McbEnsureAvailable();

	return ::SetSecurityDescriptorOwner(m_pSD, NULL, TRUE) == TRUE;
  
}/* McbSecurityDescriptorImpl<n>::McbSetSIDOwnerDefault */

/**
 ****************************************************************************
 * <P> Sets the owner sid for the security descriptor.  If this passed NULL 
 * then the owner sid will be set to default (see McbSetSIDOwnerDefault()).
 * </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbSetSIDOwner
 *
 * @param       PSID pSid		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSecurityDescriptorImpl<n>::McbSetSIDOwner(
	const PSID pSid)
{
	McbEnsureAvailable();

    m_sidOwner = pSid;

	if (!pSid)
	{
		return McbSetSIDOwnerDefault();
	}
	else
	{
		return ::SetSecurityDescriptorOwner(m_pSD, (PSID)m_sidOwner, FALSE) 
            == TRUE;
	}

}/* McbSecurityDescriptorImpl<n>::McbSetSIDOwner */

/**
 ****************************************************************************
 * <P> Returns true if the owner sid is default (meaning that the sid is 
 * obtained from the owners access token).</P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbIsDefaultSIDOwner
 *
 * @param       none
 *
 * @return      bool
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSecurityDescriptorImpl<n>::McbIsDefaultSIDOwner() 
	const
{
	if (!m_pSD)
	{
		return false;
	}

	return (((SECURITY_DESCRIPTOR*)m_pSD)->Control & SE_OWNER_DEFAULTED) !=0;

}/* McbSecurityDescriptorImpl<n>::McbIsDefaultSIDOwner */

/**
 ****************************************************************************
 * <P> Returns the owner sid for the security descriptor.</P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbGetSIDOwner
 *
 * @param       &bIsDefault		
 *
 * @return      PSID
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> PSID McbSecurityDescriptorImpl<n>::McbGetSIDOwner() const
{
	if (!m_pSD)
	{		
		return NULL;
	}
	
	return ((SECURITY_DESCRIPTOR*)m_pSD)->Owner;

}/* McbSecurityDescriptorImpl<n>::McbGetSIDOwner */

/**
 ****************************************************************************
 * <P> Sets the group sid for the security descriptor to default.  This 
 * means is will be obtained from the owners access token. </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbSetSIDGroupDefault
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
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSecurityDescriptorImpl<n>::McbSetSIDGroupDefault()
{
	McbEnsureAvailable();

	return ::SetSecurityDescriptorGroup(m_pSD, NULL, TRUE) == TRUE;
  
}/* McbSecurityDescriptorImpl<n>::McbSetSIDGroupDefault */

/**
 ****************************************************************************
 * <P> Sets the group sid for the security descriptor.  If this passed NULL 
 * then the group sid will be set to default (see McbSetSIDGroupDefault()).
 * </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbSetSIDGroup
 *
 * @param       PSID pSid		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSecurityDescriptorImpl<n>::McbSetSIDGroup(
	const PSID pSid)
{
	McbEnsureAvailable();

    m_sidGroup = pSid;

	if (!pSid)
	{
		return McbSetSIDGroupDefault();
	}
	else
	{
		return ::SetSecurityDescriptorGroup(m_pSD, (PSID)m_sidGroup, FALSE) 
            == TRUE;
	}

}/* McbSecurityDescriptorImpl<n>::McbSetSIDGroup */

/**
 ****************************************************************************
 * <P> Returns true if the group sid is default (meaning that the sid is 
 * obtained from the owners access token).</P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbIsDefaultSIDGroup
 *
 * @param       none
 *
 * @return      bool
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSecurityDescriptorImpl<n>::McbIsDefaultSIDGroup() 
	const
{
	if (!m_pSD)
	{
		return false;
	}

	return (((SECURITY_DESCRIPTOR*)m_pSD)->Control & SE_GROUP_DEFAULTED) !=0;

}/* McbSecurityDescriptorImpl<n>::McbIsDefaultSIDGroup */

/**
 ****************************************************************************
 * <P> Returns the group sid for the security descriptor. </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbGetSIDGroup
 *
 * @return      PSID
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> PSID McbSecurityDescriptorImpl<n>::McbGetSIDGroup() const
{
	if (!m_pSD)
	{		
		return NULL;
	}

	return ((SECURITY_DESCRIPTOR*)m_pSD)->Group;

}/* McbSecurityDescriptorImpl<n>::McbGetSIDGroup */

/**
 ****************************************************************************
 * <P> Function to obtain security information for a given object.
 * This function wraps a call to ::GetSecurityInfo() and if successfull, puts
 * a copy of the returned security descriptor in the security descriptor.  
 * The dwSecurityInfo parameter specifies what information is required in the
 * security descriptor and can be calculated by 'OR'ing values from the info 
 * enum (which maps directly to the win32 SECURITY_INFORMATION structure).
 * If an false is returned then ::GetLastError() can be used to obtain 
 * details </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbGetFromObject
 *
 * @param       hObject		
 * @param       ObjectType		
 * @param       dwSecurityInfo		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSecurityDescriptorImpl<n>::McbGetFromObject(
	HANDLE hObject, SE_OBJECT_TYPE objectType, DWORD dwSecurityInfo)
{	
	PSID pSidOwner = NULL;
	PSID pSidGroup = NULL;
	PACL pDacl = NULL;
	PACL pSacl = NULL;
	PSECURITY_DESCRIPTOR pSD;

   /*
    *************************************************************************
    * attempt to obtain security information
    *************************************************************************
    */
	DWORD dwResult = ::GetSecurityInfo(hObject, objectType, dwSecurityInfo, 
		&pSidOwner, &pSidGroup, &pDacl, &pSacl, &pSD);

	if (dwResult == ERROR_SUCCESS)
	{
		
       /*
        *********************************************************************
        * use operator overload to take copy of security descriptor.
        *********************************************************************
        */
		*this = pSD;

		return true;
	}

    return false;

}/* McbSecurityDescriptorImpl<n>::McbGetFromObject */

/**
 ****************************************************************************
 * <P> Function to set security information for a given object from the
 * security descriptor.
 * This function wraps a call to ::SetSecurityInfo() and if successfull, 
 * updates the security descriptor for a specified object. 
 * The dwSecurityInfo parameter specifies what information requires updating
 * in the security descriptor and can be calculated by 'OR'ing values from 
 * the info  enum (which maps directly to the win32 SECURITY_INFORMATION 
 * structure).
 * If an false is returned then ::GetLastError() can be used to obtain 
 * details. </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbSetToObject
 *
 * @param       hObject		
 * @param       objectType		
 * @param       dwSecurityInfo		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	23rd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSecurityDescriptorImpl<n>::McbSetToObject(
	HANDLE hObject, SE_OBJECT_TYPE objectType, DWORD dwSecurityInfo) const
{
	
	PSID pSidOwner = McbGetSIDOwner();
	PSID pSidGroup = McbGetSIDGroup();
	PACL pDacl = McbGetDACL();
	PACL pSacl = McbGetSACL();

   /*
    *************************************************************************
    * attempt to update security information
    *************************************************************************
    */
	DWORD dwResult = ::SetSecurityInfo(hObject, objectType, dwSecurityInfo, 
		pSidOwner, pSidGroup, pDacl, pSacl);
	
	if (dwResult == ERROR_SUCCESS)
	{
		return true;
	}

    return false;

}/* McbSecurityDescriptorImpl<n>::McbSetToObject */

/**
 ****************************************************************************
 * <P> Gets the security descriptor for a file.  If the return value is false
 * GetLastError() can be used to obtain more details.</P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbGetFromFile
 *
 * @param       lpszFile		
 * @param       dwSecurityInfo		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	25th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSecurityDescriptorImpl<n>::McbGetFromFile(
	LPCTSTR lpszFile, DWORD dwSecurityInfo)
{
   /*
    *************************************************************************
    * calculate required access to the file
    * Note:  To gain access to a security access control list (SACL), a 
    * process must have the SE_SECURITY_NAME privilege. When requesting 
    * access, the calling process must request ACCESS_SYSTEM_SECURITY in the 
    * desired access mask. ("Manage auditing and security log" under user 
    * rights in user manager).
    *************************************************************************
    */    
	DWORD dwAccess = 
        ((dwSecurityInfo & (UpdateDacl | UpdateSacl | UpdateGroup))
            ? READ_CONTROL : 0) |             
        ((dwSecurityInfo & UpdateSacl) != 0 ? ACCESS_SYSTEM_SECURITY : 0);

    //DWORD dwAccess = ACCESS_SYSTEM_SECURITY | FILE_ALL_ACCESS;

   /*
    *************************************************************************
    * attempt to open the file
    *************************************************************************
    */
	HANDLE hFile = ::CreateFile(lpszFile, dwAccess, 
        0, //FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile != INVALID_HANDLE_VALUE)
    {
       /*
        *********************************************************************
        * attempt to get the file's security descriptor
        *********************************************************************
        */
		bool bResult = McbGetFromFile(hFile, dwSecurityInfo);
        
        ::CloseHandle(hFile);

        return bResult;
    }

    return false;

}/* McbSecurityDescriptorImpl<n>::McbGetFromFile */

/**
 ****************************************************************************
 * <P> Sets the security descriptor for a file.  If the return value is false
 * GetLastError() can be used to obtain more details.</P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbSetToFile
 *
 * @param       lpszFile		
 * @param       dwSecurityInfo		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	25th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSecurityDescriptorImpl<n>::McbSetToFile(
	LPCTSTR lpszFile, DWORD dwSecurityInfo) const
{
   /*
    *************************************************************************
    * calculate required access to the file
    * Note:  To gain access to a security access control list (SACL), a 
    * process must have the SE_SECURITY_NAME privilege. When requesting 
    * access, the calling process must request ACCESS_SYSTEM_SECURITY in the 
    * desired access mask. ("Manage auditing and security log" under user 
    * rights in user manager).
    *************************************************************************
    */    
	DWORD dwAccess = 
        (dwSecurityInfo & UpdateDacl ? WRITE_DAC : 0) |
        (dwSecurityInfo & UpdateSacl ? ACCESS_SYSTEM_SECURITY : 0) |
        (dwSecurityInfo & UpdateGroup ? WRITE_OWNER : 0) | // ????TODO
        (dwSecurityInfo & UpdateOwner ? WRITE_OWNER : 0);

   /*
    *************************************************************************
    * attempt to open the file
    *************************************************************************
    */
	HANDLE hFile = ::CreateFile(lpszFile, dwAccess, 
        FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile != INVALID_HANDLE_VALUE)
    {
       /*
        *********************************************************************
        * attempt to set the file's security descriptor
        *********************************************************************
        */
		bool bResult = McbSetToFile(hFile, dwSecurityInfo);
        
        ::CloseHandle(hFile);

        return bResult;
    }

    return false;

}/* McbSecurityDescriptorImpl<n>::McbSetToFile */

/**
 ****************************************************************************
 * <P> Gets the security descriptor for a registry key. </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbGetFromRegistryKey
 *
 * @param       hKeyRoot		
 * @param       lpszSubKeyFile		
 * @param       dwSecurityInfo		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	3rd March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSecurityDescriptorImpl<n>::McbGetFromRegistryKey(
	HKEY hKeyRoot, LPCTSTR lpszSubKey, DWORD dwSecurityInfo)
{
   /*
    *************************************************************************
    * calculate required access to the file
    * Note:  To gain access to a security access control list (SACL), a 
    * process must have the SE_SECURITY_NAME privilege. When requesting 
    * access, the calling process must request ACCESS_SYSTEM_SECURITY in the 
    * desired access mask. ("Manage auditing and security log" under user 
    * rights in user manager).
    *************************************************************************
    */    
	DWORD dwAccess = KEY_QUERY_VALUE |
        ((dwSecurityInfo & (UpdateDacl | UpdateSacl | UpdateGroup))
            ? READ_CONTROL : 0) |             
        ((dwSecurityInfo & UpdateSacl) != 0 ? ACCESS_SYSTEM_SECURITY : 0);
    
   /*
    *************************************************************************
    * attempt to open the registry key
    *************************************************************************
    */
    HKEY hKey;
	if (ERROR_SUCCESS == ::RegOpenKeyEx(hKeyRoot, lpszSubKey, 0, dwAccess, 
        &hKey))
    {
       /*
        *********************************************************************
        * attempt to get registry hives security descriptor
        *********************************************************************
        */
		bool bResult = McbGetFromRegistryKey(hKey, dwSecurityInfo);

        ::RegCloseKey(hKey);

        return bResult;

    }

    return false;

}/* McbSecurityDescriptorImpl<n>::McbGetFromRegistryKey */

/**
 ****************************************************************************
 * <P> Sets the security descriptor for a registry key. </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbSetToRegistryKey
 *
 * @param       hKeyRoot		
 * @param       lpszSubKeyFile		
 * @param       dwSecurityInfo		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	3rd March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbSecurityDescriptorImpl<n>::McbSetToRegistryKey(
	HKEY hKeyRoot, LPCTSTR lpszSubKey, DWORD dwSecurityInfo)
{
   /*
    *************************************************************************
    * calculate required access to the file
    * Note:  To gain access to a security access control list (SACL), a 
    * process must have the SE_SECURITY_NAME privilege. When requesting 
    * access, the calling process must request ACCESS_SYSTEM_SECURITY in the 
    * desired access mask. ("Manage auditing and security log" under user 
    * rights in user manager).
    *************************************************************************
    */    
	DWORD dwAccess = KEY_QUERY_VALUE |
        ((dwSecurityInfo & (UpdateDacl | UpdateSacl | UpdateGroup))
            ? READ_CONTROL : 0) |             
        ((dwSecurityInfo & UpdateSacl) != 0 ? ACCESS_SYSTEM_SECURITY : 0);
    
   /*
    *************************************************************************
    * attempt to open the registry key
    *************************************************************************
    */
    HKEY hKey;
	if (ERROR_SUCCESS == ::RegOpenKeyEx(hKeyRoot, lpszSubKey, 0, dwAccess, 
        &hKey))
    {
       /*
        *********************************************************************
        * attempt to get registry hives security descriptor
        *********************************************************************
        */
		bool bResult = McbSetToRegistyKey(hKey, dwSecurityInfo);

        ::RegCloseKey(hKey);

        return bResult;

    }

    return false;

}/* McbSecurityDescriptorImpl<n>::McbSetToRegistryKey */

/**
 ****************************************************************************
 * <P> Privilege class (which encapsulates LUIDs).  See below for list of
 * NT privileges.  </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *	1st March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> class McbPrivilegeImpl
{
public:
   /*
    *************************************************************************
    * C'tion/D'tion
    *************************************************************************
    */
	McbPrivilegeImpl(const PLUID pLuid = NULL) { *this = pLuid; }

    McbPrivilegeImpl(const McbPrivilegeImpl &other) 
		{ *this = (const PLUID)&other.m_luid; }

    McbPrivilegeImpl(LPCTSTR lpszPrivilegeName, LPCTSTR lpszSystem = NULL)
		{ McbSetName(lpszSystem, lpszPrivilegeName); }

    ~McbPrivilegeImpl() {;}

   /*
    *************************************************************************
    * operator overloads
    *************************************************************************
    */
	PLUID operator=(const PLUID pLuid)
	{
	    if (!pLuid)
		{
			m_luid.LowPart = 0;
			m_luid.HighPart = 0;
		}
		else if (pLuid != &m_luid)
		{
			m_luid = *pLuid;
		}

		return &m_luid;
	}

    McbPrivilegeImpl & operator=(const McbPrivilegeImpl &other)
	{
	    *this = (const PLUID)&other.m_luid;

	    return *this;
	}

    operator PLUID() { return &m_luid; }    

   /*
    *************************************************************************
    * functionality
    *************************************************************************
    */
	inline bool McbCreateUnique() {
		return ::AllocateLocallyUniqueId(&m_luid) == TRUE; }

   /*
    *************************************************************************
    * NT defined Privileges - the following is an extract from the Windows 
    * NT 3.51 resource guide on user rights.
    *
    * SeTcbPrivilege
    *  Act as part of the operating system
    *  The user can use to perform as a secure, trusted part of the operating 
    *  system. Some subsystems are granted this privilege.
    * Granted by default: None
    *  
    * SeChangeNotifyPrivilege
    *  Bypass traverse checking
    *  The user can traverse directory trees. Deny access to users using 
    *  POSIX applications.
    * Granted by default: Everyone
    *  
    * SeCreatePagefilePrivilege
    *  Create a pagefile
    *  The user can create a page file (not available in this version of 
    * Windows NT). Security is determined by a users access to the 
    * ..\CurrentControlSet\Control\Session Management key. 
    * Granted by default: None
    *  
    * SeCreateTokenPrivilege
    *  Create a token object
    *  Required to create access tokens. Only the Local Security Authority 
    * can do this.
    * Granted by default: None
    *  
    * SeCreatePermanentPrivilege
    *  Create permanent shared objects
    *  Required to create special permanent objects, such as \\Device, 
    *  which are used within Windows NT. 
    * Granted by default: None
    *  
    * SeDebugPrivilege
    *  Debug programs
    *  The user can debug various low-level objects such as threads.
    * Granted by default: Administrators
    *  
    * SeAuditPrivilege
    *  Generate security audits
    *  Required to generate security audit log entries.
    * Granted by default: None
    * 
    * SeIncreaseQuotaPrivilege
    *  Increase quotas
    *  Required to increase object quotas (not available in this version of
    *  Windows NT). 
    * Granted by default: None
    *  
    * SeIncreaseBasePriorityPrivilege
    *  Increase scheduling priority
    *  The user can boost the priority of a process.
    * Granted by default: Administrators and Power Users
    *  
    * SeLoadDriverPrivilege
    *  Load and unload device drivers
    *  The user can load an unload device drivers.
    * Granted by default: Administrators
    *  
    * SeLockMemoryPrivilege
    *  Lock pages in memory
    *  The user can lock pages in memory so they cannot be paged out to a 
    *  backing store such as PAGEFILE.SYS. As physical memory is a limited 
    *  resource, locking pages can lead to greater disk thrashing as 
    *  essentiallythe amount of physical pages available to other 
	*  applications is  reduced.
    * Granted by default: None
    *  
    * No Name
    *  Log on as a batch job
    *  The user can log on using a batch queue facility (not available in 
	*  this version of Windows NT). 
    * Granted by default: None
    *  
    * No Name
    *  Log on as a service
    *  The user can perform security services.
    * Granted by default: None
    * 
    * SeSystemEnvironmentPrivilege
    *  Modify Firmware environment variables
    *  The user can modify system environment variables (not user environment
    *  variables).
    * Granted by default: Administrators
    *  
    * SeProfileSingleProcessPrivilege
    *  Profile single process
    *  The user can use the profiling (performance sampling) capabilities of 
    *  Windows NT on a process.
    * Granted by default: Administrators and Power Users
    *  
    * SeSystemProfilePrivilege
    *  Profile system performance
    *  The user can use the profiling capabilities of Windows NT on the 
    *  system. (This can slow the system down.)
    * Granted by default: Administrators
    *  
    * SeAssignPrimaryTokenPrivilege
    *  Replace a process level token 
    *  Required to modify a process's security access token. This is a 
    *  powerful privilege used only by the system.
    * Granted by default: None
    *  
    *************************************************************************
    */


   /*
    *************************************************************************
    * sets the privilege by name.  This must be one of the following strings
    * (or constants) as defined in winnt.h.
    *
    * Define                            String equivalent
    *************************************************************************
    * SE_CREATE_TOKEN_NAME              "SeCreateTokenPrivilege"
    * SE_ASSIGNPRIMARYTOKEN_NAME        "SeAssignPrimaryTokenPrivilege"
    * SE_LOCK_MEMORY_NAME               "SeLockMemoryPrivilege"
    * SE_INCREASE_QUOTA_NAME            "SeIncreaseQuotaPrivilege"
    * SE_UNSOLICITED_INPUT_NAME         "SeUnsolicitedInputPrivilege"
    * SE_MACHINE_ACCOUNT_NAME           "SeMachineAccountPrivilege"
    * SE_TCB_NAME                       "SeTcbPrivilege"
    * SE_SECURITY_NAME                  "SeSecurityPrivilege"
    * SE_TAKE_OWNERSHIP_NAME            "SeTakeOwnershipPrivilege"
    * SE_LOAD_DRIVER_NAME               "SeLoadDriverPrivilege"
    * SE_SYSTEM_PROFILE_NAME            "SeSystemProfilePrivilege"
    * SE_SYSTEMTIME_NAME                "SeSystemtimePrivilege"
    * SE_PROF_SINGLE_PROCESS_NAME       "SeProfileSingleProcessPrivilege"
    * SE_INC_BASE_PRIORITY_NAME         "SeIncreaseBasePriorityPrivilege"
    * SE_CREATE_PAGEFILE_NAME           "SeCreatePagefilePrivilege"
    * SE_CREATE_PERMANENT_NAME          "SeCreatePermanentPrivilege"
    * SE_BACKUP_NAME                    "SeBackupPrivilege"
    * SE_RESTORE_NAME                   "SeRestorePrivilege"
    * SE_SHUTDOWN_NAME                  "SeShutdownPrivilege"
    * SE_DEBUG_NAME                     "SeDebugPrivilege"
    * SE_AUDIT_NAME                     "SeAuditPrivilege"
    * SE_SYSTEM_ENVIRONMENT_NAME        "SeSystemEnvironmentPrivilege"
    * SE_CHANGE_NOTIFY_NAME             "SeChangeNotifyPrivilege"
    * SE_REMOTE_SHUTDOWN_NAME           "SeRemoteShutdownPrivilege"
    *
    *************************************************************************
    */
	bool McbSetName(LPCTSTR lpszSystem, LPCTSTR lpszName)
	{
	#ifdef Mcb_VERIFY_NAME
		if (_tcsicmp(lpszName, SE_CREATE_TOKEN_NAME) == 0)
		{
			lpszName = SE_CREATE_TOKEN_NAME;
		}
		else if (_tcsicmp(lpszName, SE_ASSIGNPRIMARYTOKEN_NAME) == 0)
		{
			lpszName = SE_ASSIGNPRIMARYTOKEN_NAME;
		}
		else if (_tcsicmp(lpszName, SE_LOCK_MEMORY_NAME) == 0)
		{
			lpszName = SE_LOCK_MEMORY_NAME;
		}
		else if (_tcsicmp(lpszName, SE_INCREASE_QUOTA_NAME) == 0)
		{
			lpszName = SE_INCREASE_QUOTA_NAME;
		}
		else if (_tcsicmp(lpszName, SE_UNSOLICITED_INPUT_NAME) == 0)
		{
			lpszName = SE_UNSOLICITED_INPUT_NAME;
		}
		else if (_tcsicmp(lpszName, SE_MACHINE_ACCOUNT_NAME) == 0)
		{
			lpszName = SE_MACHINE_ACCOUNT_NAME;
		}
		else if (_tcsicmp(lpszName, SE_TCB_NAME) == 0)
		{
			lpszName = SE_TCB_NAME;
		}
		else if (_tcsicmp(lpszName, SE_SECURITY_NAME) == 0)
		{
			lpszName = SE_SECURITY_NAME;
		}
		else if (_tcsicmp(lpszName, SE_TAKE_OWNERSHIP_NAME) == 0)
		{
			lpszName = SE_TAKE_OWNERSHIP_NAME;
		}
		else if (_tcsicmp(lpszName, SE_LOAD_DRIVER_NAME) == 0)
		{
			lpszName = SE_LOAD_DRIVER_NAME;
		}
		else if (_tcsicmp(lpszName, SE_SYSTEM_PROFILE_NAME) == 0)
		{
			lpszName = SE_SYSTEM_PROFILE_NAME;
		}
		else if (_tcsicmp(lpszName, SE_SYSTEMTIME_NAME) == 0)
		{
			lpszName = SE_SYSTEMTIME_NAME;
		}
		else if (_tcsicmp(lpszName, SE_PROF_SINGLE_PROCESS_NAME) == 0)
		{
			lpszName = SE_PROF_SINGLE_PROCESS_NAME;
		}
		else if (_tcsicmp(lpszName, SE_INC_BASE_PRIORITY_NAME) == 0)
		{
			lpszName = SE_INC_BASE_PRIORITY_NAME;
		}
		else if (_tcsicmp(lpszName, SE_CREATE_PAGEFILE_NAME) == 0)
		{
			lpszName = SE_CREATE_PAGEFILE_NAME;
		}
		else if (_tcsicmp(lpszName, SE_CREATE_PERMANENT_NAME) == 0)
		{
			lpszName = SE_CREATE_PERMANENT_NAME;
		}
		else if (_tcsicmp(lpszName, SE_BACKUP_NAME) == 0)
		{
			lpszName = SE_BACKUP_NAME;
		}
		else if (_tcsicmp(lpszName, SE_RESTORE_NAME) == 0)
		{
			lpszName = SE_RESTORE_NAME;
		}
		else if (_tcsicmp(lpszName, SE_SHUTDOWN_NAME) == 0)
		{
			lpszName = SE_SHUTDOWN_NAME;
		}
        else if (_tcsicmp(lpszName, SE_DEBUG_NAME) == 0)
        {
            lpszName = SE_DEBUG_NAME;
        }
        else if (_tcsicmp(lpszName, SE_AUDIT_NAME) == 0)
        {
            lpszName = SE_AUDIT_NAME;
        }
        else if (_tcsicmp(lpszName, SE_SYSTEM_ENVIRONMENT_NAME) == 0)
        {
            lpszName = SE_SYSTEM_ENVIRONMENT_NAME;
        }
        else if (_tcsicmp(lpszName, SE_CHANGE_NOTIFY_NAME) == 0)
        {
            lpszName = SE_CHANGE_NOTIFY_NAME;
        }
        else if (_tcsicmp(lpszName, SE_REMOTE_SHUTDOWN_NAME) == 0)
        {
            lpszName = SE_REMOTE_SHUTDOWN_NAME;
        }
    #endif //Mcb_VERIFY_NAME

       /*
        *********************************************************************
        * attempt to obtain luid from name of privilege
        *********************************************************************
        */
        LUID luid;
        if (::LookupPrivilegeValue(lpszSystem, lpszName, &luid))
        {
            m_luid = luid;
            return true;
        }
  
		return false;
	}

   /*
    *************************************************************************
    * obtain privilege name 
    *************************************************************************
    */
	bool McbGetName(LPCTSTR lpszSystem, std::basic_string<TCHAR> &strName) 
		const
    {
       /*
        *********************************************************************
        * obtain size required for the buffer
        *********************************************************************
        */
        DWORD cbName = 0;   
        ::LookupPrivilegeName(lpszSystem, (PLUID)&m_luid, NULL, &cbName);

        if (cbName)
        {
           /*
            *****************************************************************
            * resize buffer if required
            *****************************************************************
            */
            if (strName.size() < cbName)
            {
                strName.resize(cbName);
            }

           /*
            *****************************************************************
            * attempt to find the privilege name from the luid
            *****************************************************************
            */
            if (::LookupPrivilegeName(lpszSystem, (PLUID)&m_luid, 
                (LPTSTR)strName.data(), &cbName))
            {
               /*
                *************************************************************
                * remove NULL terminator from end of name and return
                *************************************************************
                */
                strName.resize(cbName, 1);
                return true;
            }
        }

        return false;
	}

	std::basic_string<TCHAR> McbDump() const;
	std::basic_string<TCHAR> McbDumpXML() const;

protected:
    LUID m_luid;
};

/**
 ****************************************************************************
 * <P> Access Token 
 * An access token is an object that describes the security context of a 
 * process or thread. The information in a token includes the identity and 
 * privileges of the user account associated with the process or thread. When
 * a user logs on, the system verifies the user's password by comparing it 
 * with information stored in a security database. If the password is 
 * authenticated, the system produces an access token. Every process executed
 * on behalf of this user has a copy of this access token.
 * 
 * The system uses an access token to identify the user when a thread 
 * interacts with a securable object or tries to perform a system task that 
 * requires privileges. Access tokens contain the following information: 
 * 
 *  - The security identifier (SID) for the user's account,
 *  - SIDs for the groups of which the user is a member,
 *  - A logon SID that identifies the current logon session,
 *  - A list of the privileges held by either the user or the user's groups 
 *  - An owner SID 
 *  - The SID for the primary group 
 *  - The default DACL that the system uses when the user creates a 
 *    securable object without specifying a security descriptor 
 *  - The source of the access token 
 *  - Whether the token is a primary or impersonation token 
 *  - An optional list of restricting SIDs 
 *  - Current impersonation levels 
 *  - Other statistics 
 * 
 * Every process has a primary token that describes the security context of 
 * the user account associated with the process. By default, the system uses 
 * the primary token when a thread of the process interacts with a securable 
 * object. However, a thread can impersonate a client account. This allows 
 * the thread to interact with securable objects using the client's security 
 * context. A thread that is impersonating a client has both a primary token 
 * and an impersonation token. Use the OpenProcessToken function to retrieve 
 * a handle to the primary token of a process. Use the OpenThreadToken 
 * function to retrieve a handle to the impersonation token of a thread. 
 * For more information, see Impersonation in the MSDN. 
 * </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *	1st March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> class McbAccessTokenImpl
{
public:
   /**
    *************************************************************************
    * <P> Nested class for token groups </P>
    *
    * @version     V1.0
    *
    * @author      Martyn C Brown 
    *
    * @changeHistory  
    *	1st March     	2000	 - 	(V1.0) Creation (MCB)
    *************************************************************************
    */
	class McbGroups
    {
        friend class McbAccessTokenImpl;

    public:
       /*
        *********************************************************************
        * C'tion/D'tion
        *********************************************************************
        */
		McbGroups(const PTOKEN_GROUPS pGroups = NULL) 
			: m_pGroups(NULL), m_pSids(NULL) { *this = pGroups; }

        ~McbGroups() { McbFree(); }

       /*
        *********************************************************************
        * operator overloads
        *********************************************************************
        */
		PTOKEN_GROUPS operator=(const PTOKEN_GROUPS pOther)
        {
            if ((PTOKEN_GROUPS)pOther != m_pGroups)
            {
                McbFree();

                if (pOther)
                {
                   /*
                    *********************************************************
                    * dereference other group pointer
                    *********************************************************
                    */
                    TOKEN_GROUPS &otherGroup = *(TOKEN_GROUPS*)pOther;            
                    DWORD dwGroups = otherGroup.GroupCount;

                   /*
                    *********************************************************
                    * allocate memory for the new group
                    *********************************************************
                    */
                    DWORD cbGroups = sizeof(TOKEN_GROUPS) + 
                        ((dwGroups-1) * sizeof(SID_AND_ATTRIBUTES));

                    m_pGroups = (PTOKEN_GROUPS)McbHEAPALLOC(cbGroups);

           
                   /*
                    *********************************************************
                    * dereference new group pointer and set the group count
                    *********************************************************
                    */
                    TOKEN_GROUPS &newGroup = *m_pGroups;

                    newGroup.GroupCount = otherGroup.GroupCount;

                   /*
                    *********************************************************
                    * create copy of sids and assign to new groups
                    *********************************************************
                    */
                    m_pSids = new McbSID[dwGroups];

                    for (DWORD dwSid = 0; dwSid<dwGroups; dwSid++)
                    {
                        m_pSids[dwSid] = otherGroup.Groups[dwSid].Sid;

                        newGroup.Groups[dwSid].Sid = (PSID)m_pSids[dwSid];
                        newGroup.Groups[dwSid].Attributes = 
                            otherGroup.Groups[dwSid].Attributes;

                    }
                }
            }

            return m_pGroups;
        }

        operator PTOKEN_GROUPS() { return m_pGroups; }
        operator const PTOKEN_GROUPS() const { return m_pGroups; }

       /*
        *********************************************************************
        * functionality
        *********************************************************************
        */
		inline DWORD McbGetSIDCount() const
		{
			if (!m_pGroups) { return 0; }
			return ((TOKEN_GROUPS*)m_pGroups)->GroupCount;
		}

       /*
        *********************************************************************
        * Obtain a SID from the group
        *********************************************************************
        */
		PSID McbGetSID(DWORD dwIndex, DWORD &attributes) const
        {
            DWORD dwSids = McbGetSIDCount();
            if (dwSids == 0 || dwIndex >= dwSids)
            {
                return NULL;
            }

            attributes = ((TOKEN_GROUPS*)m_pGroups)->
				Groups[dwIndex].Attributes;

            return ((TOKEN_GROUPS*)m_pGroups)->Groups[dwIndex].Sid;
        }

       /*
        *********************************************************************
        * Obtain the logged on sid (See "mk:@MSITStore:d:\MSDN98\98VSa\1033\
		* winbase.chm::/devdoc/live/pdwbase/accclsrv_1pk4.htm" in the MSDN).
        *********************************************************************
        */
		PSID McbGetLogonSID(DWORD &dwIndex, DWORD &dwAttributes) const
		{   
			PSID pResult = NULL;

			DWORD dwSids = McbGetSIDCount();
            
			for (dwIndex = 0; dwIndex < dwSids; dwIndex++)
			{
				PSID pSid = McbGetSID(dwIndex, dwAttributes);
            
                if (pSid && ((dwAttributes & SE_GROUP_LOGON_ID) == 
					SE_GROUP_LOGON_ID))
                {
                    pResult = pSid;
                    break;
                }
            }
					
			return pResult;
		}

       /*
        *********************************************************************
        * Delete a SID from the group.
        *********************************************************************
        */
		bool McbDeleteSID(DWORD dwIndex)
        {
            DWORD dwSids = McbGetSIDCount();
            if (dwSids == 0 || dwIndex >= dwSids)
            {
                return false;
            }

            TOKEN_GROUPS &groups = *(TOKEN_GROUPS*)m_pGroups;

           /*
            *****************************************************************
            * move sids up the list
            *****************************************************************
            */
            for (DWORD dwSid = dwIndex; dwSid < dwSids-2; dwSid++)
            {
                groups.Groups[dwSid].Sid = groups.Groups[dwSid+1].Sid;
                groups.Groups[dwSid].Attributes = 
					groups.Groups[dwSid+1].Attributes;
            }

           /*
            *****************************************************************
            * decrement the group count
            *****************************************************************
            */
            groups.GroupCount--;

            return true;
        }

       /*
        *********************************************************************
        * Insert a SID into the group
        *********************************************************************
        */
		bool McbInsertSID(const PSID pSid, DWORD attributes, DWORD dwIndex)
        {        
            DWORD dwGroups = McbGetSIDCount();
    
           /*
            *****************************************************************
            * allocate memory for the new group (including room for new sid)
            *****************************************************************
            */
            DWORD cbGroups = sizeof(TOKEN_GROUPS) + 
                ((dwGroups) * sizeof(SID_AND_ATTRIBUTES));

            TOKEN_GROUPS* pGroups = (TOKEN_GROUPS*)McbHEAPALLOC(cbGroups);

           /*
            *****************************************************************
            * create reference to new group count then increment for new sid
            *****************************************************************
            */
            DWORD & dwNewGroups = pGroups->GroupCount;
            dwNewGroups++;

           /*
            *****************************************************************
            * update to the index to point to the last entry in the list if 
			* it is pointing past the end of the buffer
            *****************************************************************
            */
            if (dwIndex > dwGroups)
            {
                dwIndex = dwGroups;
            }

           /*
            *****************************************************************
            * allocate memory for new sids
            *****************************************************************
            */
            McbSID * pSids = new McbSID[dwNewGroups];

           /*
            *****************************************************************
            * if old groups exist
            *****************************************************************
            */
            if (m_pGroups)
            {
                TOKEN_GROUPS &oldGroups = *(TOKEN_GROUPS*)m_pGroups;

               /*
                *************************************************************
                * iterate through old sids and copy them to the new 
                *************************************************************
                */
                DWORD dwSourceSid = 0;
                for (DWORD dwDestSid = 0; dwDestSid<dwNewGroups; dwDestSid++)
                {
                    if (dwDestSid != dwIndex)
                    {
                       /*
                        *****************************************************
                        * copy sid and attributes
                        *****************************************************
                        */
                        pSids[dwDestSid] = oldGroups.Groups[dwSourceSid].Sid;

                        pGroups->Groups[dwDestSid].Sid = 
							(PSID)pSids[dwDestSid];

                        pGroups->Groups[dwDestSid].Attributes = 
                            oldGroups.Groups[dwSourceSid].Attributes;

                       /*
                        *****************************************************
                        * increase source sid index
                        *****************************************************
                        */
                        dwSourceSid++;

                    }
                }

               /*
                *************************************************************
                * free the old groups and sids
                *************************************************************
                */
                McbFree();

            }

           /*
            *****************************************************************
            * insert new sid and attributes into new slot
            *****************************************************************
            */
            pSids[dwIndex] = (PSID)pSid;
            pGroups->Groups[dwIndex].Attributes = attributes;

           /*
            *****************************************************************
            * point members to new groups and sids
            *****************************************************************
            */
            m_pGroups = pGroups;
            m_pSids = pSids;

            return true;
        }

        bool McbAppendSID(const PSID pSid, DWORD attributes)            
		    { return McbInsertSID(pSid, attributes, MAXDWORD); }

        DWORD McbGetSize() const { return McbGetSize(m_pGroups); }

       /*
        *********************************************************************
        * Search for specified sid within the group.  This search starts at 
        * the position based on a zero based index specified by the dwIndex 
        * parameter (for example call McbFindSID(pSid, 0) to start the search 
        * from start of the list.)
        * If the search is successful the index of the sid will be returned 
        * in dwIndex.  This can then be used in a call the 
        * McbAccessTokenImpl::McbGroups::McbGetSID(). 
        *********************************************************************
        */
		bool McbFindSID(const PSID pSid, DWORD &dwIndex) const
        {
            if (!m_pGroups || !pSid)
            {
                return false;
            }

           /*
            *****************************************************************
            * iterate through the sids
            *****************************************************************
            */
            McbSID sid;   
            DWORD dwAttribs;
            for (; dwIndex<McbGetSIDCount(); dwIndex++)
            {
               /*
                *************************************************************
                * take copy of sid from the group
                *************************************************************
                */
                sid = McbGetSID(dwIndex, dwAttribs);

               /*
                *************************************************************
                * use operator overload to compare sids
                *************************************************************
                */
                if (sid == pSid)
                {
                   /*
                    *********************************************************
                    * return true if the sid was found
                    *********************************************************
                    */          
                    return true;
                }
            }

            return false;
        }

       /*
        *********************************************************************
        * Determine whether a specified SID is enabled in the group
        *********************************************************************
        */
		bool McbIsSIDEnabled(const PSID pSid) const
        {
            if (!m_pGroups)
            {
                return false;
            }

           /*
            *****************************************************************
            * attempt to find sids within the index
            *****************************************************************
            */  
            DWORD dwAttribs;
            PSID pSidOther;
            for(DWORD dwIndex = 0; McbFindSID(pSid, dwIndex); dwIndex++)
            {
               /*
                *************************************************************
                * obtain the attributes for the sid
                *************************************************************
                */
                pSidOther = McbGetSID(dwIndex, dwAttribs);

               /*
                *************************************************************
                * ignore any NULL entries
                *************************************************************
                */
                if (pSidOther)
                {
                   /*
                    *********************************************************
                    * check the attributes to see if the sid is enabled
                    *********************************************************
                    */
                    if (dwAttribs & SE_GROUP_ENABLED) 
                    {
                        return true;
                    }
                }               
            }

            return false;
 
        }

        std::basic_string<TCHAR> McbDump() const
        {
            if (!m_pGroups)
            {
                return std::basic_string<TCHAR>(
					_T("TOKEN GROUPS - Unallocated"));
            }
            
            std::basic_string<TCHAR> strResults(
				_T("TOKEN GROUPS - Count: "));

            DWORD dwCount = McbGetSIDCount();

            TCHAR szSize[10];

            _ltot(dwCount, szSize, 10);
			strResults += szSize;

           /*
            *****************************************************************
            * iterate through the subcomponents to dump their output
            *****************************************************************
            */
            McbSID sid;
            DWORD dwAttributes;
            for(DWORD dwIndex=0; dwIndex < dwCount; dwIndex++)
            {
                sid = McbGetSID(dwIndex, dwAttributes);
                strResults += sid.McbDump();

                _ltot(dwAttributes, szSize, 16);
                strResults += _T(", attributes(0x0");
                strResults += szSize;
                strResults += _T("), ");
            }

            return strResults;
        }

		std::basic_string<TCHAR> McbDumpXML() const
        {
            if (!m_pGroups)
            {
                return std::basic_string<TCHAR>(
					_T("<TOKEN_GROUPS/>"));
            }
            
            std::basic_string<TCHAR> strResults(
				_T("<TOKEN_GROUPS GroupCount="));

            DWORD dwCount = McbGetSIDCount();

            TCHAR szSize[10];

            _ltot(dwCount, szSize, 10);
            strResults += szSize;

            strResults += _T(">");

           /*
            *****************************************************************
            * iterate through the subcomponents to dump their output
            *****************************************************************
            */
            McbSID sid;
            DWORD dwAttributes;
            for(DWORD dwIndex=0; dwIndex < dwCount; dwIndex++)
            {
                strResults += _T("<SID_AND_ATTRIBUTES Attributes=0x0");

                sid = McbGetSID(dwIndex, dwAttributes);

                _ltot(dwAttributes, szSize, 16);
                strResults += szSize;

                strResults += ">";
                strResults += sid.McbDumpXML();
                strResults += _T("</SID_AND_ATTRIBUTES>");
            }

            strResults += _T("</TOKEN_GROUPS>");

            return strResults;
        }

    protected:
       /*
        *********************************************************************
        * functionality
        *********************************************************************
        */
		inline void McbFree()
		{
			if (m_pGroups)
			{
				McbHEAPFREE(m_pGroups);
				m_pGroups = NULL;        
			}

			if (m_pSids)
			{
				delete [] m_pSids;
				m_pSids = NULL;
			}
		}

        static DWORD McbGetSize(PTOKEN_GROUPS pGroups)
        {
            if (!pGroups)
            {
                return 0;
            }
    
            DWORD dwGroups = ((TOKEN_GROUPS*)pGroups)->GroupCount;
           
           /*
            *****************************************************************
            * Return size of the group
            *****************************************************************
            */
            return sizeof(TOKEN_GROUPS) + ((dwGroups-1) * 
				sizeof(SID_AND_ATTRIBUTES));            
        }

       /*
        *********************************************************************
        * members
        *********************************************************************
        */
		TOKEN_GROUPS	*m_pGroups;
        McbSIDImpl<0>	*m_pSids;
    };

   /**
    *************************************************************************
    * <P> Nested class for token privileges </P>
    *
    * @version     V1.0
    *
    * @author      Martyn C Brown 
    *
    * @changeHistory  
    *	1st March     	2000	 - 	(V1.0) Creation (MCB)
    *************************************************************************
    */
	class McbPrivileges
    {
        friend class McbAccessTokenImpl;

    public:
       /*
        *********************************************************************
        * C'tion/D'tion
        *********************************************************************
        */
        McbPrivileges(const PTOKEN_PRIVILEGES pOther = NULL)
		  : m_pTokPrivs(NULL), m_pPrivs(NULL)
		{
			*this = pOther;
		}

        ~McbPrivileges() { McbFree(); }

       /*
        *********************************************************************
        * Assignment operator
        *********************************************************************
        */
		PTOKEN_PRIVILEGES operator=(const PTOKEN_PRIVILEGES pOther)
        {
            if ((PTOKEN_PRIVILEGES)pOther != m_pTokPrivs)
            {
                McbFree();

                if (pOther)
                {
                   /*
                    *********************************************************
                    * dereference other group pointer
                    *********************************************************
                    */                      
                    TOKEN_PRIVILEGES &otherPrivs = *(TOKEN_PRIVILEGES*)
						pOther;
                    DWORD dwPrivs = otherPrivs.PrivilegeCount;

                   /*
                    *********************************************************
                    * allocate memory for the new group
                    *********************************************************
                    */
                    DWORD cbPrivs = sizeof(TOKEN_PRIVILEGES) + 
                        ((dwPrivs-1) * sizeof(LUID_AND_ATTRIBUTES));

                    m_pTokPrivs = (PTOKEN_PRIVILEGES)McbHEAPALLOC(cbPrivs);

           
                   /*
                    *********************************************************
                    * dereference new group pointer and set the group count
                    *********************************************************
                    */
                    TOKEN_PRIVILEGES &newPrivs = *m_pTokPrivs;

                    newPrivs.PrivilegeCount = otherPrivs.PrivilegeCount;

                   /*
                    *********************************************************
                    * create copy of privileges and assign to new privileges
					* list
                    *********************************************************
                    */
                    m_pPrivs = new McbPrivilege[dwPrivs];

                    for (DWORD dwPriv = 0; dwPriv<dwPrivs; dwPriv++)
                    {
                        m_pPrivs[dwPriv] = 
							&otherPrivs.Privileges[dwPriv].Luid;

                        newPrivs.Privileges[dwPriv].Luid = 
							*(PLUID)m_pPrivs[dwPriv];

                        newPrivs.Privileges[dwPriv].Attributes = 
                            otherPrivs.Privileges[dwPriv].Attributes;
                    }
                }
            }

            return m_pTokPrivs;

        }

        operator PTOKEN_PRIVILEGES() { return m_pTokPrivs; }
        operator const PTOKEN_PRIVILEGES() const { return m_pTokPrivs; }

       /*
        *********************************************************************
        * functionality
        *********************************************************************
        */
		inline DWORD McbGetPrivilegeCount() const
		{
			if (!m_pTokPrivs) { return 0; }
			return ((TOKEN_PRIVILEGES*)m_pTokPrivs)->PrivilegeCount;
		}

        PLUID McbGetPrivilege(DWORD dwIndex, DWORD &attributes) const
		{
			DWORD dwPrivs = McbGetPrivilegeCount();
			if (dwPrivs == 0 || dwIndex >= dwPrivs)
			{
				return NULL;
			}

			attributes = ((TOKEN_PRIVILEGES*)m_pTokPrivs)->
				Privileges[dwIndex].Attributes;

			return &((TOKEN_PRIVILEGES*)m_pTokPrivs)->
				Privileges[dwIndex].Luid;
		}

       /*
        *********************************************************************
        * Delete a privilege from the list.
        *********************************************************************
        */
		bool McbDeletePrivilege(DWORD dwIndex)
        {
            DWORD dwPrivs = McbGetPrivilegeCount();
            if (dwPrivs == 0 || dwIndex >= dwPrivs)
            {
                return false;
            }

            TOKEN_PRIVILEGES &privs = *(TOKEN_PRIVILEGES*)m_pTokPrivs;

           /*
            *****************************************************************
            * move privileges up the list
            *****************************************************************
            */
            for (DWORD dwPriv = dwIndex; dwPriv < dwPrivs-2; dwPriv++)
            {
                privs.Privileges[dwPriv].Luid = 
					privs.Privileges[dwPriv+1].Luid;

                privs.Privileges[dwPriv].Attributes =
                    privs.Privileges[dwPriv+1].Attributes;
            }

           /*
            *****************************************************************
            * decrement the group count
            *****************************************************************
            */
            privs.PrivilegeCount--;

            return true;

        }

       /*
        *********************************************************************
        * Insert a privilege into the list
        *********************************************************************
        */
		bool McbInsertPrivilege(const PLUID pLuid, DWORD attributes, 
			DWORD dwIndex)
        {        
            DWORD dwPrivs = McbGetPrivilegeCount();
    
           /*
            *****************************************************************
            * allocate memory for the new group (including room for new 
			* privilege)
            *****************************************************************
            */
            DWORD cbPrivs = sizeof(TOKEN_PRIVILEGES) + 
                ((dwPrivs) * sizeof(LUID_AND_ATTRIBUTES));

            TOKEN_PRIVILEGES* pTokPrivs = (TOKEN_PRIVILEGES*)
				McbHEAPALLOC(cbPrivs);

           /*
            *****************************************************************
            * create reference to new privileges count then increment for new 
            * privilege
            *****************************************************************
            */
            DWORD & dwNewPrivs = pTokPrivs->PrivilegeCount;
            dwNewPrivs++;

           /*
            *****************************************************************
            * update to the index to point to the last entry in the list if 
			* it is pointing past the end of the buffer
            *****************************************************************
            */
            if (dwIndex > dwPrivs)
            {
                dwIndex = dwPrivs;
            }

           /*
            *****************************************************************
            * allocate memory for new privileges
            *****************************************************************
            */
            McbPrivilege * pPrivs = new McbPrivilege[dwNewPrivs];

           /*
            *****************************************************************
            * if old privileges list exist
            *****************************************************************
            */
            if (m_pTokPrivs)
            {
                TOKEN_PRIVILEGES &oldGroups = *(TOKEN_PRIVILEGES*)
					m_pTokPrivs;

               /*
                *************************************************************
                * iterate through old privileges list and copy them to the 
				* new list
                *************************************************************
                */
                DWORD dwSourcePriv = 0;
                for (DWORD dwDestPriv = 0; dwDestPriv<dwNewPrivs; 
				dwDestPriv++)
                {
                    if (dwDestPriv != dwIndex)
                    {
                       /*
                        *****************************************************
                        * copy sid and attributes
                        *****************************************************
                        */
                        pPrivs[dwDestPriv] = 
                            &oldGroups.Privileges[dwSourcePriv].Luid;

                        pTokPrivs->Privileges[dwDestPriv].Luid = 
                            *(PLUID)pPrivs[dwDestPriv];

                        pTokPrivs->Privileges[dwDestPriv].Attributes = 
                            oldGroups.Privileges[dwSourcePriv].Attributes;

                       /*
                        *****************************************************
                        * increase source privileges index
                        *****************************************************
                        */
                        dwSourcePriv++;

                    }
                }

               /*
                *************************************************************
                * free the old privileges list and privileges.
                *************************************************************
                */
                McbFree();

            }

           /*
            *****************************************************************
            * insert new privileges and attributes into new slot
            *****************************************************************
            */
            pPrivs[dwIndex] = (PLUID)pLuid;
            pTokPrivs->Privileges[dwIndex].Attributes = attributes;

           /*
            *****************************************************************
            * point members to new privileges list and privileges
            *****************************************************************
            */
            m_pTokPrivs = pTokPrivs;
            m_pPrivs = pPrivs;

            return true;

        }

        bool McbAppendPrivilege(const PLUID pLuid, DWORD attributes)            
		   { return McbInsertPrivilege(pLuid, attributes, MAXDWORD); }

        std::basic_string<TCHAR> McbDump() const
		{
			if (!m_pTokPrivs)
            {
                return std::basic_string<TCHAR>(
					_T("TOKEN GROUPS - Unallocated"));
            }
            
            std::basic_string<TCHAR> strResults(
				_T("TOKEN GROUPS - Count: "));

            DWORD dwCount = McbGetPrivilegeCount();

            TCHAR szSize[10];

            _ltot(dwCount, szSize, 10);
            strResults += szSize;
            strResults += _T(" ");

           /*
            *****************************************************************
            * iterate through the subcomponents to dump their output
            *****************************************************************
            */
            McbPrivilege priv;
            DWORD dwAttributes;
            for(DWORD dwIndex=0; dwIndex < dwCount; dwIndex++)
            {
                priv = McbGetPrivilege(dwIndex, dwAttributes);
                strResults += priv.McbDump();

                _ltot(dwAttributes, szSize, 16);
                strResults += _T(", attributes(0x0");
                strResults += szSize;
                strResults += _T("), ");
            }

            return strResults;
		}

		std::basic_string<TCHAR> McbDumpXML() const
        {
            if (!m_pTokPrivs)
            {
                return std::basic_string<TCHAR>(_T("<TOKEN_PRIVILEGES/>"));
            }
            
            std::basic_string<TCHAR> strResults(
                _T("<TOKEN_PRIVILEGES PrivilegeCount="));

            DWORD dwCount = McbGetPrivilegeCount();

            TCHAR szSize[10];

            _ltot(dwCount, szSize, 10);
            strResults += szSize;

            strResults += _T(">");

           /*
            *****************************************************************
            * iterate through the subcomponents to dump their output
            *****************************************************************
            */
            McbPrivilege priv;
            DWORD dwAttributes;
            for(DWORD dwIndex=0; dwIndex < dwCount; dwIndex++)
            {
                strResults += _T("<LUID_AND_ATTRIBUTES Attributes=0x0");

                priv = McbGetPrivilege(dwIndex, dwAttributes);

                _ltot(dwAttributes, szSize, 16);
                strResults += szSize;

                strResults += ">";

                strResults += priv.McbDumpXML();
                strResults += _T("</LUID_AND_ATTRIBUTES>");
            }

            strResults += _T("</TOKEN_PRIVILEGES>");

            return strResults;
        }

    protected:
       /*
        *********************************************************************
        * functionality
        *********************************************************************
        */
		inline void McbFree()
		{
		    if (m_pTokPrivs)
			{
				McbHEAPFREE(m_pTokPrivs);
				m_pTokPrivs = NULL;        
			}

			if (m_pPrivs)
			{
				delete [] m_pPrivs;
				m_pPrivs = NULL;
			}
		}

       /*
        *********************************************************************
        * Obtain the size
        *********************************************************************
        */
		static DWORD McbGetSize(const PTOKEN_PRIVILEGES pPrivs)
        {
            if (!pPrivs)
            {
                return 0;
            }
    
            DWORD dwPrivs = ((TOKEN_PRIVILEGES*)pPrivs)->PrivilegeCount;
           
           /*
            *****************************************************************
            * Return size of the group
            *****************************************************************
            */
            return sizeof(PTOKEN_PRIVILEGES) + ((dwPrivs-1) * 
                sizeof(LUID_AND_ATTRIBUTES));            
        }

       /*
        *********************************************************************
        * members
        *********************************************************************
        */
		PTOKEN_PRIVILEGES   m_pTokPrivs;
        McbPrivilegeImpl<0>	*m_pPrivs;
    };

   /*
    *************************************************************************
    * C'tion/D'tion
    *************************************************************************
    */
	McbAccessTokenImpl(const HANDLE hToken = NULL);
    ~McbAccessTokenImpl();

   /*
    *************************************************************************
    * operator overloads
    *************************************************************************
    */
    HANDLE operator=(HANDLE hToken);

    operator HANDLE() { return m_hToken; }
    operator const HANDLE() const { return m_hToken; }

   /*
    *************************************************************************
    * functionality
    *************************************************************************
    */
	
   /*
    *************************************************************************
    * Obtain the default DACL for newly created objects. 
    * TOKEN_QUERY access required on access token for this function.
    *************************************************************************
    */
	PACL McbGetDefaultDACL() const;

   /*
    *************************************************************************
    * Obtains pointer to a TOKEN_GROUPS structure containing the group 
    * accounts associated with the token.  This can be passed into a
    * McbAccessTokenImpl::McbGroups object for manipulation.
    * TOKEN_QUERY access required on access token for this function.
    *************************************************************************
    */
	PTOKEN_GROUPS McbGetGroups() const;

   /*
    *************************************************************************
    * typedefs to simplify
    *************************************************************************
    */
	typedef SECURITY_IMPERSONATION_LEVEL	impersonation;
    typedef TOKEN_TYPE                      type;

   /*
    *************************************************************************
    * obtain type which indicate whether the token is a primary or 
    * impersonation token. 
    * TOKEN_QUERY access required on access token for this function.
    *************************************************************************
    */
	type McbGetType() const;

    bool McbIsImpersonationType() const 
        { return McbGetType() == TokenImpersonation; }

    bool McbIsPrimaryType() const
        { return McbGetType() == TokenPrimary; }

   /*
    *************************************************************************
    * Obtain enum indicating the impersonation level of the token
    *
    * This will be one of the following:
    *
    * Constant                  Meaning
    *************************************************************************
    * SecurityAnonymous         The server process cannot obtain 
    *                           identification information about the client 
    *                           and it cannot impersonate the client. It is 
    *                           defined with no value given, and thus, by 
    *                           ANSI C rules, defaults to a value of 0. 
    * SecurityIdentification    The server process can obtain information 
    *                           about the client, such as security 
    *                           identifiers and privileges, but it cannot 
    *                           impersonate the client. This is useful for 
    *                           servers that export their own objects...for 
    *                           example, database products that export tables 
    *                           and views. Using the retrieved 
    *                           client-security information, the server can 
    *                           make access-validation decisions without 
	*							being able to utilize other services using 
    *                           the client's security context. 
    * SecurityImpersonation     The server process can impersonate the 
    *                           client's security context on its local system. 
    *                           The server cannot impersonate the client on 
    *                           remote systems. 
    * SecurityDelegation        Windows NT/Windows 2000 security does not 
    *                           support this impersonation level. 
    *
    * TOKEN_QUERY access required on access token for this function.
    *************************************************************************
    */
	impersonation McbGetImpersonationLevel() const;

   /*
    *************************************************************************
    * Obtain default owner SID that will be applied to newly created objects. 
    * TOKEN_QUERY access required on access token for this function.
    *************************************************************************
    */
	PSID McbGetOwner() const;

   /*
    *************************************************************************
    * Obtain the SID which identifies the user associated with the access 
    * token.
    * TOKEN_QUERY access required on access token for this function.
    *************************************************************************
    */
	PSID McbGetUser() const;

   /*
    *************************************************************************
    * obtain group security identifier (SID) for an access token. 
    * TOKEN_QUERY access required on access token for this function.
    *************************************************************************
    */
	PSID McbGetPrimaryGroup() const;

   /*
    *************************************************************************
    * Obtain token privileges for the access token.  This can be passed into
    * a McbAccessTokenImpl::McbPrivileges object for manipluation.
    * TOKEN_QUERY access required on access token for this function.
    *************************************************************************
    */
	PTOKEN_PRIVILEGES McbGetPrivileges() const;

   /*
    *************************************************************************
    * Obtains pointer to a TOKEN_GROUPS structure containing the restricting
    * accounts (sids) associated with the token.  This can be passed into a
    * McbAccessTokenImpl::McbGroups object for manipulation.
    * TOKEN_QUERY access required on access token for this function.
    *************************************************************************
    */
	PTOKEN_GROUPS McbGetRestrictingSids() const;

   /*
    *************************************************************************
    * Returns a DWORD value that indicates the Terminal Services session 
    * identifier associated with the token. If the token is associated with 
    * the Terminal Server console session, the session identifier is zero. 
    * A nonzero session identifier indicates a Terminal Services client 
    * session. In a non-Terminal Services environment, the session identifier
    * is zero.
    * TOKEN_QUERY access required on access token for this function.
    *************************************************************************
    */
	DWORD McbGetSessionId() const;

   /*
    *************************************************************************
    * Obtains pointer to the TOKEN_SOURCE structure.  This structure 
    * identifies the source of an access token.  The structure contains the
    * following:
    *   SourceName - Specifies an 8-byte character string used to identify 
    *       the source of an access token. This is used to distinguish 
    *       between such sources as Session Manager, LAN Manager, and RPC 
    *       Server. A string, rather than a constant, is used to identify 
    *       the source so users and developers can make extensions to the 
    *       system, such as by adding other networks, that act as the source 
    *       of access tokens. 
    *   SourceIdentifier - Specifies a locally unique identifier (LUID) 
    *       provided by the source component named by the SourceName member. 
    *       This value aids the source component in relating context blocks, 
    *       such as session-control structures, to the token. This value is 
    *       typically, but not necessarily, an LUID. 
    *
    * TOKEN_QUERY_SOURCE access required on access token for this function.
    *************************************************************************
    */
	PTOKEN_SOURCE McbGetSource() const;

   /*
    *************************************************************************
    * Obtain general information about an access token. 
    * TOKEN_QUERY access required on access token for this function.
    *************************************************************************
    */
	PTOKEN_STATISTICS McbGetStatistics() const;

   /*
    *************************************************************************
    * Set default owner SID that will be applied to newly created objects. 
    * TOKEN_ADJUST_DEFAULT access required on access token for this function.
    *************************************************************************
    */
	bool McbSetOwner(const PSID pSid);

   /*
    *************************************************************************
    * Set the primary group sid for the access token.  The PSID parameter 
    * represents a group that will become the primary group of any objects 
    * created by a process using this access token. The security identifier 
    * (SID) must be one of the group SIDs already in the token. 
    * TOKEN_ADJUST_DEFAULT access required on access token for this function.
    *************************************************************************
    */
	bool McbSetPrimaryGroup(const PSID pSid);

   /*
    *************************************************************************
    * Set the default discretionay access control list for the access token,
    * The ACL structure provided as a new default discretionary ACL is not 
    * validated for correctness or consistency. If the access control list 
    * parameter is NULL, the current default discretionary ACL is removed and 
    * no replacement is established.
    *************************************************************************
    */
	bool McbSetDefaultDACL(const PACL pAcl);

   /*
    *************************************************************************
    * Adjusts groups in the access token. 
    * Mandatory groups cannot be disabled. They are identified by the 
    * SE_GROUP_MANDATORY attribute in the TOKEN_GROUPS structure. If an 
    * attempt is made to disable any mandatory groups, AdjustTokenGroups 
    * fails and leaves the state of all groups unchanged.
    *
    * TOKEN_ADJUST_GROUPS access is required to enable or disable groups in 
    * an access token. 
    *************************************************************************
    */
	bool McbSetGroups(const PTOKEN_GROUPS pGroups);

   /*
    *************************************************************************
    * Resets groups for the access token to their default enabled and 
    * disabled states. 
    * 
    * The McbAccessTokenImpl::McbGroups class can be used to manipulate the 
    * TOKEN_GROUPS structure. </P>
    *************************************************************************
    */
	bool McbResetGroups();

   /*
    *************************************************************************
    * Enables or disables privileges in the access token. 
    *
    * New privileges CANNOT be added to the access token. The access tokens 
    * existing privileges can only be enabled or disabled.
    *
    * The McbAccessTokenImpl::McbPrivileges class can be used to manipulate the 
    * TOKEN_PRIVILEGES structure.
    *
    * Enabling or disabling privileges in an access token requires 
    * TOKEN_ADJUST_PRIVILEGES access. 
    *************************************************************************
    */
	bool McbAdjustPrivileges(const PTOKEN_PRIVILEGES pPrivs);

   /*
    *************************************************************************
    * Disable ALL privileges within an access token. 
    *
    * Enabling or disabling privileges in an access token requires 
    * TOKEN_ADJUST_PRIVILEGES access.
    *************************************************************************
    */
	bool McbDisableAllPrivileges();

   /*
    *************************************************************************
    * Methods for enabling or disabling privileges - see notes in 
    * McbPrivilege class for names of privileges and their meanings.
    *************************************************************************
    */
	bool McbEnablePrivilege(const PLUID pLuid) 
        { return McbSetPrivilege(pLuid, true); }

    bool McbDisablePrivilege(const PLUID pLuid)
        { return McbSetPrivilege(pLuid, false); }

    bool McbEnablePrivilege(LPCTSTR lpszPrivilege)
    {
        McbPrivilege priv(lpszPrivilege); 
        return McbSetPrivilege((PLUID)priv, true); 
    }

    bool McbDisablePrivilege(LPCTSTR lpszPrivilege)
    {
        McbPrivilege priv(lpszPrivilege);

        return McbSetPrivilege((PLUID)priv, false);
    }

   /*
    *************************************************************************
    * Does the privilege exist within the access token
    *************************************************************************
    */
    bool McbIsPrivilegeInToken(LPCTSTR lpszPrivilege) const
    {
        McbPrivilege priv(lpszPrivilege);

        LUID_AND_ATTRIBUTES* pPrivilege;
        return McbFindPrivilege((PLUID)priv, pPrivilege);
    }

	bool McbIsPrivilegeInToken(const PLUID pLuid) const
    {
        LUID_AND_ATTRIBUTES* pPrivilege;
        return McbFindPrivilege(pLuid, pPrivilege);
    }

   /*
    *************************************************************************
    * Is the privilege enabled within the access token
    *************************************************************************
    */
	bool McbIsPrivilegeEnabled(LPCTSTR lpszPrivilege) const
    {
        McbPrivilege priv(lpszPrivilege);

        return McbIsPrivilegeEnabled((PLUID)priv);
    }

    bool McbIsPrivilegeEnabled(const PLUID pLuid) const
    {
        LUID_AND_ATTRIBUTES* pPrivilege;
        if (McbFindPrivilege(pLuid, pPrivilege))
        {
            return pPrivilege->Attributes & SE_PRIVILEGE_ENABLED != 0;
        }

        return false;
    }

   /*
    *************************************************************************
    * Determine whether a specified SID is enabled in an access token.
    *************************************************************************
    */
	bool McbIsSIDEnabled(const PSID pSid) const;

   /*
    *************************************************************************
    * Create the access token from a specific user - the access token can 
    * then be passed to ::ImpersonateLoggedOnUser() for impersonation
    *************************************************************************
    */
	bool McbCreateFromUser(LPCTSTR lpszDomain, LPCTSTR lpszUser, 
        LPCTSTR lpszPwd);

    std::basic_string<TCHAR> McbDump() const;
	std::basic_string<TCHAR> McbDumpXML() const;

protected:
   /*
    *************************************************************************
    * functionality
    *************************************************************************
    */
	inline void McbFreeGroups() const;
    inline void McbFreePrivileges() const;
    inline void McbFreeRestrictingSids() const;

   /*
    *************************************************************************
    *  Enables or disables a privilege (which must exist in the access 
    * token).  
    * Enabling or disabling privileges in an access token requires 
    * TOKEN_ADJUST_PRIVILEGES access. 
    *************************************************************************
    */
	bool McbSetPrivilege(const PLUID pLuid, bool bEnablePrivilege);

   /*
    *************************************************************************
    * find a privilege within an access token
    *************************************************************************
    */
	bool McbFindPrivilege(const PLUID pLuid, 
        LUID_AND_ATTRIBUTES* &pPrivilege) const;

   /*
    *************************************************************************
    * members
    *************************************************************************
    */
	HANDLE m_hToken;

    mutable McbACLImpl<0>		m_defDacl;
    mutable PTOKEN_GROUPS       m_pGroups;    
    mutable McbSIDImpl<0>        m_sidOwner;
    mutable McbSIDImpl<0>        m_sidUser;
    mutable McbSIDImpl<0>		m_sidPrimaryGroup;
    mutable PTOKEN_PRIVILEGES   m_pPrivs;
    mutable PTOKEN_GROUPS       m_pRestrictSids;
    mutable TOKEN_SOURCE        m_tokenSource;
    mutable TOKEN_STATISTICS    m_tokenStats;
};

/**
 ****************************************************************************
 * <P> Free the resource </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbFreeGroups
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
 *	1st March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbAccessTokenImpl<n>::McbFreeGroups() const
{
    if (m_pGroups)
    {
        McbHEAPFREE(m_pGroups);
        m_pGroups = NULL;
    }

}/* McbAccessTokenImpl<n>::McbFreeGroups */

/**
 ****************************************************************************
 * <P> Free the resource </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbFreePrivileges
 *
 * @param       none
 *
 * @return      void
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	2nd March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbAccessTokenImpl<n>::McbFreePrivileges() const
{
    if (m_pPrivs)
    {
        McbHEAPFREE(m_pPrivs);
        m_pPrivs = NULL;
    }

}/* McbAccessTokenImpl<n>::McbFreePrivileges */

/**
 ****************************************************************************
 * <P> Free the resource </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbFreeRestrictingSids
 *
 * @param       none
 *
 * @return      void
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	2nd March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> void McbAccessTokenImpl<n>::McbFreeRestrictingSids() const
{
    if (m_pRestrictSids)
    {
        McbHEAPFREE(m_pRestrictSids);
        m_pRestrictSids = NULL;
    }
}/* McbAccessTokenImpl<n>::McbFreeRestrictingSids */

/**
 ****************************************************************************
 * <P> C'tor </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbAccessTokenImpl
 *
 * @param       hToken		
 *
 * @return      none
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	1st March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> McbAccessTokenImpl<n>::McbAccessTokenImpl(const HANDLE hToken)
 : m_hToken(hToken), m_pGroups(NULL), m_pPrivs(NULL), m_pRestrictSids(NULL)
{

}/* McbAccessTokenImpl<n>::McbAccessTokenImpl */

/**
 ****************************************************************************
 * <P> D'tor </P>
 *
 * @methodName  McbAccessTokenImpl<n>::~McbAccessTokenImpl
 *
 * @param       none
 *
 * @return      none
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	1st March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> McbAccessTokenImpl<n>::~McbAccessTokenImpl()
{
    McbFreeGroups();
    McbFreePrivileges();
    McbFreeRestrictingSids();

}/* McbAccessTokenImpl<n>::~McbAccessTokenImpl */

/**
 ****************************************************************************
 * <P> Assignment operator </P>
 *
 * @methodName  McbAccessTokenImpl<n>::operator=
 *
 * @param       hToken		
 *
 * @return      HANDLE
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	1st March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> HANDLE McbAccessTokenImpl<n>::operator=(HANDLE hToken)
{
    m_hToken = hToken;

    return m_hToken;

}/* McbAccessTokenImpl<n>::operator= */

/**
 ****************************************************************************
 * <P> Obtain the default dacl for the access token (TOKEN_QUERY access 
 * required on the access token handle). </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbGetDefaultDACL
 *
 * @param       none
 *
 * @return      PACL
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	1st March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> PACL McbAccessTokenImpl<n>::McbGetDefaultDACL() const 
{  
    if (!m_hToken)
    {
        return NULL;
    }

    PACL pResult = NULL;

   /*
    *****************************************************************
    * obtain size of buffer
    *****************************************************************
    */
    DWORD cbInfo = 0;

    ::GetTokenInformation(m_hToken, TokenDefaultDacl, NULL, NULL, 
        &cbInfo);

    if (cbInfo)
    {
        TOKEN_DEFAULT_DACL * pInfo = (TOKEN_DEFAULT_DACL *)
            McbHEAPALLOC(cbInfo);
    
       /*
        *********************************************************************
        * obtain token information for real
        *********************************************************************
        */
		if (::GetTokenInformation(m_hToken, TokenDefaultDacl, pInfo, 
            cbInfo, &cbInfo))
        {
           /*
            *****************************************************************
            * cache the results and set the return value
            *****************************************************************
            */
			m_defDacl = pInfo->DefaultDacl;
            pResult = (PACL)m_defDacl;
        }
        
        McbHEAPFREE(pInfo);
    }

    return pResult;

}/* McbAccessTokenImpl<n>::McbGetDefaultDACL */

/**
 ****************************************************************************
 * <P> Obtains pointer to a TOKEN_GROUPS structure containing the group 
 * accounts associated with the token.  This can be passed into a
 * McbAccessTokenImpl<n>::McbGroups object for manipulation. </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbGetGroups
 *
 * @param       none
 *
 * @return      PTOKEN_GROUPS
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	1st March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> PTOKEN_GROUPS McbAccessTokenImpl<n>::McbGetGroups() const
{
    if (!m_hToken)
    {
        return NULL;
    }
  
   /*
    *****************************************************************
    * obtain information for token groups
    *****************************************************************
    */
    DWORD cbInfo = 0;
	::GetTokenInformation(m_hToken, TokenGroups, NULL, NULL, 
        &cbInfo);

    if (cbInfo)
    {              
       /*
        *********************************************************************
        * free previous group information
        *********************************************************************
        */
		McbFreeGroups();

       /*
        *********************************************************************
        * allocate memory for new group information
        *********************************************************************
        */
		m_pGroups = (PTOKEN_GROUPS)McbHEAPALLOC(cbInfo); 

        if (::GetTokenInformation(m_hToken, TokenGroups, 
            m_pGroups, cbInfo, &cbInfo))
        {
            return m_pGroups;
        }
        
    }

    return NULL;

}/* McbAccessTokenImpl<n>::McbGetGroups */

/**
 ****************************************************************************
 * <P> Returns type of token (as dicated by TOKEN_TYPE enumeration). If
 * the access token is NULL or an invalid handle, then the return value is
 * undefined. </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbGetType
 *
 * @param       none
 *
 * @return      type
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	1st March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> typename McbAccessTokenImpl<n>::type 
  McbAccessTokenImpl<n>::McbGetType() const 
{
    type tokenType;

    if (m_hToken)
    {        
       /*
        *********************************************************************
        * obtain token type information
        *********************************************************************
        */
		DWORD cbInfo = sizeof(type);

        ::GetTokenInformation(m_hToken, TokenType, &tokenType, cbInfo, 
            &cbInfo);
    }
                
    return tokenType;

}/* McbAccessTokenImpl<n>::McbGetType */

/**
 ****************************************************************************
 * <P> Obtain impersonation level of the access token.  If the access token  
 * is NULL or the token is not an impersonation type (see 
 * McbIsImpersonationToken()) then the return value will be undefined.</P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbGetImpersonationLevel
 *
 * @param       none
 *
 * @return      impersonation
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	1st March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> typename McbAccessTokenImpl<n>::impersonation 
  McbAccessTokenImpl<n>::McbGetImpersonationLevel() const 
{
    impersonation tokenImpersonate;

    if (m_hToken && McbIsImpersonationType())
    {        
       /*
        *********************************************************************
        * obtain token impersonation information
        *********************************************************************
        */
		DWORD cbInfo = sizeof(impersonation);

        ::GetTokenInformation(m_hToken, TokenImpersonationLevel, 
            &tokenImpersonate, cbInfo, &cbInfo);
    }
                
    return tokenImpersonate;

}/* McbAccessTokenImpl<n>::McbGetImpersonationLevel */

/**
 ****************************************************************************
 * <P> Obtain default owner SID that will be applied to newly created 
 * objects. NULL will be returned if the access token is NULL. </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbGetOwner
 *
 * @param       none
 *
 * @return      PSID
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	1st March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> PSID McbAccessTokenImpl<n>::McbGetOwner() const
{    
    PSID pResult = NULL;

    if (m_hToken)
    {        		
       /*
        *********************************************************************
        * calculate size of buffer
        *********************************************************************
        */
        DWORD cbInfo = 0;
		::GetTokenInformation(m_hToken, TokenOwner, NULL, NULL, 
            &cbInfo);

        if (cbInfo)
        {
            TOKEN_OWNER * pInfo = (TOKEN_OWNER*)
                McbHEAPALLOC(cbInfo);

           /*
            *****************************************************************
            * obtain token information
            *****************************************************************
            */
			if (::GetTokenInformation(m_hToken, TokenOwner, pInfo, 
                cbInfo, &cbInfo))
            {
               /*
                *************************************************************
                * if we managed to obtain token infomation, cache the sid and
                * set the return value
                *************************************************************
                */
				m_sidOwner = (PSID)pInfo->Owner;
                pResult = (PSID)m_sidOwner;

            }

            McbHEAPFREE(pInfo);
        }
    }
                
    return pResult;

}/* McbAccessTokenImpl<n>::McbGetOwner */

/**
 ****************************************************************************
 * <P> Obtain the SID which identifies the user associated with the access 
 * token. </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbGetUser
 *
 * @param       none
 *
 * @return      PSID
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	1st March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> PSID McbAccessTokenImpl<n>::McbGetUser() const
{    
    PSID pResult = NULL;

    if (m_hToken)
    {        		
       /*
        *********************************************************************
        * calculate size of buffer
        *********************************************************************
        */
        DWORD cbInfo = 0;
		::GetTokenInformation(m_hToken, TokenUser, NULL, NULL, 
            &cbInfo);

        if (cbInfo)
        {
            TOKEN_USER * pInfo = (TOKEN_USER*)
                McbHEAPALLOC(cbInfo);

           /*
            *****************************************************************
            * obtain token information
            *****************************************************************
            */
			if (::GetTokenInformation(m_hToken, TokenUser, pInfo, 
                cbInfo, &cbInfo))
            {
               /*
                *************************************************************
                * if we managed to obtain token infomation, cache the sid and
                * set the return value
                *************************************************************
                */
				m_sidUser = (PSID)pInfo->User.Sid;
                pResult = (PSID)m_sidUser;

            }

            McbHEAPFREE(pInfo);
        }
    }
                
    return pResult;

}/* McbAccessTokenImpl<n>::McbGetUser */

/**
 ****************************************************************************
 * <P> Obtain default owner SID that will be applied to newly created 
 * objects. </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbGetPrimaryGroup
 *
 * @param       none
 *
 * @return      PSID
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	1st March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> PSID McbAccessTokenImpl<n>::McbGetPrimaryGroup() const 
{
    PSID pResult = NULL;

    if (m_hToken)
    {        		
       /*
        *********************************************************************
        * calculate size of buffer
        *********************************************************************
        */
        DWORD cbInfo = 0;
		::GetTokenInformation(m_hToken, TokenPrimaryGroup, NULL, NULL, 
            &cbInfo);

        if (cbInfo)
        {
            TOKEN_PRIMARY_GROUP * pInfo = (TOKEN_PRIMARY_GROUP*)
                McbHEAPALLOC(cbInfo);

           /*
            *****************************************************************
            * obtain token information
            *****************************************************************
            */
			if (::GetTokenInformation(m_hToken, TokenPrimaryGroup, pInfo, 
                cbInfo, &cbInfo))
            {
               /*
                *************************************************************
                * if we managed to obtain token infomation, cache the sid and
                * set the return value
                *************************************************************
                */
				m_sidPrimaryGroup = (PSID)pInfo->PrimaryGroup;
                pResult = (PSID)m_sidPrimaryGroup;

            }

            McbHEAPFREE(pInfo);
        }
    }
                
    return pResult;

}/* McbAccessTokenImpl<n>::McbGetPrimaryGroup */

/**
 ****************************************************************************
 * <P> Obtains pointer to a PTOKEN_PRIVILEGES structure containing the 
 * privileges associated with the token.  This can be passed into a
 * McbAccessTokenImpl<n>::McbPrivileges object for manipulation. </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbGetPrivileges
 *
 * @param       none
 *
 * @return      PTOKEN_PRIVILEGES 
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	1st March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> PTOKEN_PRIVILEGES McbAccessTokenImpl<n>::McbGetPrivileges() 
	const
{
    if (!m_hToken)
    {
        return NULL;
    }
  
   /*
    *************************************************************************
    * obtain information for token groups
    *************************************************************************
    */
    DWORD cbInfo = 0;
	::GetTokenInformation(m_hToken, TokenPrivileges, NULL, NULL, 
        &cbInfo);

    if (cbInfo)
    {              
       /*
        *********************************************************************
        * free previous privilege information
        *********************************************************************
        */
		McbFreePrivileges();

       /*
        *********************************************************************
        * allocate memory for new privilege information
        *********************************************************************
        */
		m_pPrivs = (PTOKEN_PRIVILEGES)McbHEAPALLOC(cbInfo); 

        if (::GetTokenInformation(m_hToken, TokenPrivileges, 
            m_pPrivs, cbInfo, &cbInfo))
        {            
            return m_pPrivs;
        }
        
    }

    return NULL;

}/* McbAccessTokenImpl<n>::McbGetPrivileges */

/**
 ****************************************************************************
 * <P> Obtains pointer to a TOKEN_GROUPS structure containing the restricting
 * accounts (sids) associated with the token.  This can be passed into a
 * McbAccessTokenImpl<n>::McbGroups object for manipulation. </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbGetRestrictingSids
 *
 * @param       none
 *
 * @return      PTOKEN_GROUPS
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	1st March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> PTOKEN_GROUPS McbAccessTokenImpl<n>::McbGetRestrictingSids() 
	const
{
    if (!m_hToken)
    {
        return NULL;
    }
  
   /*
    *************************************************************************
    * obtain information for restricting sids
    *************************************************************************
    */
    DWORD cbInfo = 0;
	::GetTokenInformation(m_hToken, TokenRestrictedSids, NULL, NULL, 
        &cbInfo);

    if (cbInfo)
    {              
       /*
        *********************************************************************
        * free previous restricting sids
        *********************************************************************
        */
		McbFreeRestrictingSids();

       /*
        *********************************************************************
        * allocate memory for new restricting sids
        *********************************************************************
        */
		m_pRestrictSids = (PTOKEN_GROUPS)McbHEAPALLOC(cbInfo); 

        if (::GetTokenInformation(m_hToken, TokenRestrictedSids, 
            m_pGroups, cbInfo, &cbInfo))
        {
            return m_pRestrictSids;
        }
        
    }

    return NULL;

}/* McbAccessTokenImpl<n>::McbGetRestrictingSids */

/**
 ****************************************************************************
 * <P> Returns a DWORD value that indicates the Terminal Services session 
 * identifier associated with the token. If the token is associated with the
 * Terminal Server console session, the session identifier is zero. 
 * A nonzero session identifier indicates a Terminal Services client session. 
 * In a non-Terminal Services environment, the session identifier is zero. 
 * </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbGetSessionId
 *
 * @param       none
 *
 * @return      DWORD
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	2nd March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> DWORD McbAccessTokenImpl<n>::McbGetSessionId() const
{
    if (!m_hToken)
    {
        return 0;
    }   

    DWORD dwResult = 0;
    DWORD cbInfo = sizeof(DWORD);

    ::GetTokenInformation(m_hToken, TokenSessionId, &dwResult, cbInfo, 
        &cbInfo);

    return dwResult;

}/* McbAccessTokenImpl<n>::McbGetSessionId */

/**
 ****************************************************************************
 * <P> Obtains pointer to the TOKEN_SOURCE structure.  This structure 
 * identifies the source of an access token.  The structure contains the
 * following:
 *   SourceName - Specifies an 8-byte character string used to identify 
 *      the source of an access token. This is used to distinguish between 
 *      such sources as Session Manager, LAN Manager, and RPC Server. A 
 *      string, rather than a constant, is used to identify the source so 
 *      users and developers can make extensions to the system, such as by 
 *      adding other networks, that act as the source of access tokens. 
 *   SourceIdentifier - Specifies a locally unique identifier (LUID) 
 *      provided by the source component named by the SourceName member. 
 *      This value aids the source component in relating context blocks, 
 *      such as session-control structures, to the token. This value is 
 *      typically, but not necessarily, an LUID. 
 *
 * TOKEN_QUERY_SOURCE access required on access token for this function.
 * </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbGetSource
 *
 * @param       none
 *
 * @return      PTOKEN_SOURCE
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	2nd March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> PTOKEN_SOURCE McbAccessTokenImpl<n>::McbGetSource() const
{
    if (!m_hToken)
    {
        return 0;
    }   
    
    DWORD cbInfo = sizeof(TOKEN_SOURCE);

    if (::GetTokenInformation(m_hToken, TokenSource, &m_tokenSource, 
        cbInfo, &cbInfo))
    {
        return &m_tokenSource;
    }

    return NULL;

}/* McbAccessTokenImpl<n>::McbGetSource */

/**
 ****************************************************************************
 * <P> Obtain general information about an access token. 
 * TOKEN_QUERY access required on access token for this function.</P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbGetStatistics
 *
 * @param       none
 *
 * @return      PTOKEN_STATISTICS
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	2nd March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> PTOKEN_STATISTICS McbAccessTokenImpl<n>::McbGetStatistics() 
	const
{
    if (!m_hToken)
    {
        return 0;
    }   
    
    DWORD cbInfo = sizeof(TOKEN_STATISTICS);    

    if (::GetTokenInformation(m_hToken, TokenStatistics, &m_tokenStats, 
        cbInfo, &cbInfo))
    {
        return &m_tokenStats;
    }

    return NULL;

}/* McbAccessTokenImpl<n>::McbGetStatistics */

/**
 ****************************************************************************
 * <P> Set default owner SID that will be applied to newly created objects. 
 * TOKEN_ADJUST_DEFAULT access required on access token for this function.</P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbSetOwner
 *
 * @param       PSID pSid		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	2nd March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbAccessTokenImpl<n>::McbSetOwner(const PSID pSid)
{
    if (!pSid || !m_hToken)
    {
        return false;
    }
    
   /*
    *************************************************************************
    * attempt to set the owner sid
    *************************************************************************
    */
    TOKEN_OWNER tok = { pSid };
    return ::SetTokenInformation(m_hToken, TokenOwner, &tok, sizeof(tok)) 
        == TRUE;
 
}/* McbAccessTokenImpl<n>::McbSetOwner */

/**
 ****************************************************************************
 * <P> Set the primary group sid for the access token.  The PSID parameter 
 * represents a group that will become the primary group of any objects 
 * created by a process using this access token. The security identifier 
 * (SID) must be one of the group SIDs already in the token. 
 * TOKEN_ADJUST_DEFAULT access required on access token for this function.
 * </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbSetPrimaryGroup
 *
 * @param       PSID pSid		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	3rd March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbAccessTokenImpl<n>::McbSetPrimaryGroup(
	const PSID pSid)
{
    if (!pSid || !m_hToken)
    {
        return false;
    }
   /*
    *************************************************************************
    * attempt to set the primary group sid
    *************************************************************************
    */
    TOKEN_PRIMARY_GROUP tok = { pSid };
    return ::SetTokenInformation(m_hToken, TokenPrimaryGroup, 
        &tok, sizeof(tok)) == TRUE;

}/* McbAccessTokenImpl<n>::McbSetPrimaryGroup */

/**
 ****************************************************************************
 * <P> Set the default discretionay access control list for the access token,
 * The ACL structure provided as a new default discretionary ACL is not 
 * validated for correctness or consistency. If the access control list 
 * parameter is NULL, the current default discretionary ACL is removed and 
 * no replacement is established.
 * TOKEN_ADJUST_DEFAULT access required on access token for this function.
 * </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbSetDefaultDACL
 *
 * @param       PACL pAcl		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	3rd March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbAccessTokenImpl<n>::McbSetDefaultDACL(const PACL pAcl)
{
    if (!m_hToken)
    {
        return false;
    }

   /*
    *************************************************************************
    * attempt to set the default dacl
    *************************************************************************
    */
    TOKEN_DEFAULT_DACL dacl = { pAcl };

    return ::SetTokenInformation(m_hToken, TokenDefaultDacl, 
        pAcl ? &dacl : NULL, pAcl ? sizeof(dacl) : NULL) == TRUE;

}/* McbAccessTokenImpl<n>::McbSetDefaultDACL */

/**
 ****************************************************************************
 * <P> Adjusts groups in the access token. 
 * Mandatory groups cannot be disabled. They are identified by the 
 * SE_GROUP_MANDATORY attribute in the TOKEN_GROUPS structure. If an attempt 
 * is made to disable any mandatory groups, AdjustTokenGroups fails and 
 * leaves the state of all groups unchanged.
 * The McbAccessTokenImpl<n>::McbGroups class can be used to manipulate the 
 * TOKEN_GROUPS structure.
 *
 * TOKEN_ADJUST_GROUPS access is required to enable or disable groups in an
 * access token. </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbSetGroups
 *
 * @param       PTOKEN_GROUPS pGroups		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	3rd March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbAccessTokenImpl<n>::McbSetGroups(
	const PTOKEN_GROUPS pGroups)
{
    if (!pGroups || !m_hToken)
    {
        return false;
    }

   /*
    *************************************************************************
    * obtain size of the token groups
    *************************************************************************
    */
    DWORD cbGroups = McbAccessTokenImpl<n>::McbGroups::McbGetSize(pGroups);
    
   /*
    *************************************************************************
    * attempt to adjust the token groups
    *************************************************************************
    */
	return ::AdjustTokenGroups(m_hToken, FALSE, pGroups, cbGroups, NULL, 
        NULL) == TRUE;

}/* McbAccessTokenImpl<n>::McbSetGroups */

/**
 ****************************************************************************
 * <P> Resets groups for the access token to their default enabled and 
 * disabled states. 
 * The McbAccessTokenImpl<n>::McbGroups class can be used to manipulate the 
 * TOKEN_GROUPS structure. </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbResetGroups
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
 *	3rd March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbAccessTokenImpl<n>::McbResetGroups()
{
    if (!m_hToken)
    {
        return false;
    }

   /*
    *************************************************************************
    * attempt to reset the token groups to default
    *************************************************************************
    */
	return ::AdjustTokenGroups(m_hToken, TRUE, NULL, 0, NULL, NULL) == TRUE;

}/* McbAccessTokenImpl<n>::McbResetGroups */

/**
 ****************************************************************************
 * <P> Adjusts groups in the access token. 
 * Mandatory groups cannot be disabled. They are identified by the 
 * SE_GROUP_MANDATORY attribute in the TOKEN_PRIVILEGES structure. If an 
 * attempt is made to disable any mandatory groups, AdjustTokenGroups fails 
 * and leaves the state of all groups unchanged.
 *
 * The McbAccessTokenImpl<n>::McbGroups class can be used to manipulate the 
 * TOKEN_PRIVILEGES structure.
 *
 * TOKEN_ADJUST_GROUPS access is required to enable or disable groups in an
 * access token. </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbAdjustPrivileges
 *
 * @param       PTOKEN_PRIVILEGES pGroups		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	3rd March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbAccessTokenImpl<n>::McbAdjustPrivileges(
	const PTOKEN_PRIVILEGES pPrivs)
{
    if (!pPrivs || !m_hToken)
    {
        return false;
    }

   /*
    *************************************************************************
    * obtain size of the token privileges
    *************************************************************************
    */
    DWORD cbPrivs = McbAccessTokenImpl<n>::McbPrivileges::McbGetSize(pPrivs);
    
   /*
    *************************************************************************
    * attempt to adjust the token privileges
    *************************************************************************
    */
	return ::AdjustTokenPrivileges(m_hToken, FALSE, pPrivs, cbPrivs, NULL, 
        NULL) == TRUE;

}/* McbAccessTokenImpl<n>::McbAdjustPrivileges */

/**
 ****************************************************************************
 * <P> Disable ALL privileges within an access token. 
 *
 * Enabling or disabling privileges in an access token requires 
 * TOKEN_ADJUST_PRIVILEGES access.
 * </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbDisableAllPrivileges
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
 *	3rd March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbAccessTokenImpl<n>::McbDisableAllPrivileges()
{
    if (!m_hToken)
    {
        return false;
    }

   /*
    *************************************************************************
    * attempt to disable the token privileges
    *************************************************************************
    */
	return ::AdjustTokenPrivileges(m_hToken, TRUE, NULL, 0, NULL, NULL) 
        == TRUE;

}/* McbAccessTokenImpl<n>::McbDisableAllPrivileges */


/**
 ****************************************************************************
 * <P> Determine whether a specified SID is enabled in an access token.</P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbIsSIDEnabled
 *
 * @param       PSID pSid		
 *
 * @return      bool
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	3rd March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbAccessTokenImpl<n>::McbIsSIDEnabled(const PSID pSid) 
	const
{
    if (!m_hToken)
    {
        return false;
    }

    McbSID sid(McbGetOwner());

   /*
    *************************************************************************
    * check the owner sid
    *************************************************************************
    */
	if (sid == McbSID(pSid))
    {
        return true;
    }

   /*
    *************************************************************************
    * obtain the token groups from the access token
    *************************************************************************
    */
	McbAccessTokenImpl<n>::McbGroups group(McbGetGroups());

   /*
    *************************************************************************
    * check the token groups to see if the sid is enabled
    *************************************************************************
    */
	if (group.McbIsSIDEnabled(pSid))
    {
        return true;
    }

    return false;


}/* McbAccessTokenImpl<n>::McbIsSIDEnabled */

/**
 ****************************************************************************
 * <P> Enables or disables a privilege (which must exist in the access 
 * token).  
 * Enabling or disabling privileges in an access token requires 
 * TOKEN_ADJUST_PRIVILEGES access.  </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbSetPrivilege
 *
 * @param       PLUID pLuid		
 * @param       bEnablePrivilege		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	3rd March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbAccessTokenImpl<n>::McbSetPrivilege(const PLUID pLuid, 
	bool bEnablePrivilege)
{
    if (!m_hToken)
    {
        return false;
    }

    TOKEN_PRIVILEGES tp;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = *pLuid;

   /*
    *************************************************************************
    * set the privilege to be enabled or disabled
    *************************************************************************
    */
	if (bEnablePrivilege)
    {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    }
    else
    {
        tp.Privileges[0].Attributes = 0;
    }

   /*
    *************************************************************************
    * Enable the privilege or disable all privileges
    *************************************************************************
    */
	return McbAdjustPrivileges(&tp);

}/* McbAccessTokenImpl<n>::McbSetPrivilege */

/**
 ****************************************************************************
 * <P> Search for a specified privilege within the access token. </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbFindPrivilege
 *
 * @param       PLUID pLuid		
 * @param       &pPrivilege		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	3rd March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbAccessTokenImpl<n>::McbFindPrivilege(
	const PLUID pLuid, LUID_AND_ATTRIBUTES* &pPrivilege) const
{
    if (!m_hToken || !pLuid)
    {
        return false;
    }

   /*
    *************************************************************************
    * obtian the tokens privileges
    *************************************************************************
    */
	TOKEN_PRIVILEGES * pPrivs = (TOKEN_PRIVILEGES*)McbGetPrivileges();

    if (!pPrivs)
    {
        return false;
    }

   /*
    *************************************************************************
    * iterate through privileges
    *************************************************************************
    */
    PLUID pLuidCompare;
	for(DWORD dwPriv = 0; dwPriv < pPrivs->PrivilegeCount; dwPriv++)
    {
       /*
        *********************************************************************
        * compare the luids and set pointer to the luid and attributes if 
        * there is a match
        *********************************************************************
        */
        pLuidCompare = &pPrivs->Privileges[dwPriv].Luid;

		if (pLuidCompare->HighPart == pLuid->HighPart && 
            pLuidCompare->LowPart == pLuid->LowPart)
        {
            pPrivilege = &pPrivs->Privileges[dwPriv];
            return true;
        }
    }

    return false;

}/* McbAccessTokenImpl<n>::McbFindPrivilege */

/**
 ****************************************************************************
 * <P> Create the access token from a specific user - the access token can 
 * then be passed to ::ImpersonateLoggedOnUser() for impersonation </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbCreateFromUser
 *
 * @param       lpszSystem		
 * @param       lpszDomain		
 * @param       lpszUser		
 *
 * @return      bool
 *
 * @exception   none
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	3rd March     	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> bool McbAccessTokenImpl<n>::McbCreateFromUser(
	LPCTSTR lpszDomain, LPCTSTR lpszUser, LPCTSTR lpszPwd)
{

    HANDLE hToken;
    if (::LogonUser((LPTSTR)lpszUser, (LPTSTR)lpszDomain, (LPTSTR)lpszPwd, 
        LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken))
    {
       /*
        *********************************************************************
        * use assignment operator to copy token
        *********************************************************************
        */
		*this = hToken;

        return true;
    }

    return false;
         
}/* McbAccessTokenImpl<n>::McbCreateFromUser */

/**
 ****************************************************************************
 * <P> **** overtype summary description **** </P>
 *
 * @methodName  McbSIDImpl<n>::McbDump
 *
 * @param       none
 *
 * @return      void
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	21st February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> std::basic_string<TCHAR> McbSIDImpl<n>::McbDump() const
{
	if (!m_pSid)
	{
		return std::basic_string<TCHAR>(_T("SID - Unallocated"));
	}

	SID_NAME_USE sidUse;

	std::basic_string<TCHAR> strResults = _T("SID");
    std::basic_string<TCHAR> strAccount, strDomain, strSid;

    if (McbGetString(strSid))
    {
        strResults += _T(" (");
        strResults += strSid;
        strResults += _T(")");
    }

   /*
    *************************************************************************
    * obtain account details for the sid
    *************************************************************************
    */
	if (McbGetAccount(NULL, strAccount, strDomain))
	{		
        McbGetSidUse(NULL, sidUse);

		strResults += _T(" - Account: ");
		strResults += strAccount.c_str();
		strResults += _T(", Domain: ");
		strResults += strDomain.c_str();
		strResults += _T(", Usage: ");

       /*
        *********************************************************************
        * lookup the usage
        *********************************************************************
        */
		switch(sidUse)
		{
		case SidTypeUser:
			strResults += _T("SidTypeUser");
			break;
			
		case SidTypeGroup: 
			strResults += _T("SidTypeGroup");
			break;

		case SidTypeDomain:
			strResults += _T("SidTypeDomain");
			break;

		case SidTypeAlias:
			strResults += _T("SidTypeAlias");
			break;

		case SidTypeWellKnownGroup:
			strResults += _T("SidTypeWellKnownGroup");
			break;

		case SidTypeDeletedAccount:
			strResults += _T("SidTypeDeletedAccount");
			break;

		case SidTypeInvalid:
			strResults += _T("SidTypeInvalid");
			break;

		case SidTypeUnknown:
			strResults += _T("SidTypeUnknown");
			break;

		case SidTypeComputer:
			strResults += _T("SidTypeComputer");
			break;

		default:
			strResults += _T("Undefined");
		}														
	}
   /*
    *************************************************************************
    * if we failed to obtain account details
    *************************************************************************
    */
    else 
    {
		strResults += _T(" - unable to obtain account details");
   		
    }/* end else */

	return strResults;

}/* McbSIDImpl<n>::McbDump */

/**
 ****************************************************************************
 * <P> **** overtype summary description **** </P>
 *
 * @methodName  McbSIDImpl<n>::McbDumpXML
 *
 * @param       none
 *
 * @return      void
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	21st February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> std::basic_string<TCHAR> McbSIDImpl<n>::McbDumpXML() const
{
	if (!m_pSid)
	{
		return std::basic_string<TCHAR>(_T("<SID/>"));
	}

	SID_NAME_USE sidUse;

	std::basic_string<TCHAR> strResults = _T("<SID Name=");
    std::basic_string<TCHAR> strAccount, strDomain, strSid;

    if (McbGetString(strSid))
    {        		
        strResults += strSid;     
    }
	else
	{
		strResults += _T("\"\"");
	}

   /*
    *************************************************************************
    * obtain account details for the sid
    *************************************************************************
    */
	if (McbGetAccount(NULL, strAccount, strDomain))
	{		
        McbGetSidUse(NULL, sidUse);

		strResults += _T(" Account=\"");
		strResults += strAccount.c_str();
		strResults += _T("\" Domain=\"");
		strResults += strDomain.c_str();
		strResults += _T("\" Usage=");

       /*
        *********************************************************************
        * lookup the usage
        *********************************************************************
        */
		switch(sidUse)
		{
		case SidTypeUser:
			strResults += _T("SidTypeUser");
			break;
			
		case SidTypeGroup: 
			strResults += _T("SidTypeGroup");
			break;

		case SidTypeDomain:
			strResults += _T("SidTypeDomain");
			break;

		case SidTypeAlias:
			strResults += _T("SidTypeAlias");
			break;

		case SidTypeWellKnownGroup:
			strResults += _T("SidTypeWellKnownGroup");
			break;

		case SidTypeDeletedAccount:
			strResults += _T("SidTypeDeletedAccount");
			break;

		case SidTypeInvalid:
			strResults += _T("SidTypeInvalid");
			break;

		case SidTypeUnknown:
			strResults += _T("SidTypeUnknown");
			break;

		case SidTypeComputer:
			strResults += _T("SidTypeComputer");
			break;

		default:
			strResults += _T("Undefined");
		}														
	}
   /*
    *************************************************************************
    * if we failed to obtain account details
    *************************************************************************
    */
    else 
    {
		strResults += _T(" Account=\"\" Domain=\"\" Usage=\"\"");   		
    }

	strResults += _T("/>");

	return strResults;

}/* McbSIDImpl<n>::McbDumpXML */

/**
 ****************************************************************************
 * <P> **** overtype summary description **** </P>
 *
 * @methodName  McbACEImpl<n>::McbDump
 *
 * @param       none
 *
 * @return      std::basic_string<TCHAR>
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	21st February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> std::basic_string<TCHAR> McbACEImpl<n>::McbDump() const
{
	if (!m_pAce)
	{
		return std::basic_string<TCHAR>(_T("ACE - Unallocated"));
	}

	std::basic_string<TCHAR> strResults(_T("ACE - type: "));

	switch(((ACE_HEADER *)m_pAce)->AceType)
	{
	case ACCESS_ALLOWED_ACE_TYPE:
		strResults += _T("ACCESS_ALLOWED_ACE");		
		break;

	case ACCESS_DENIED_ACE_TYPE:
		strResults += _T("ACCESS_DENIED_ACE");		
		break;

	case SYSTEM_AUDIT_ACE_TYPE:
		strResults += _T("SYSTEM_AUDIT_ACE");		
		break;
		
	default:
		strResults += _T("Unsupported");		
	}


	TCHAR szSize[10];

	_ltot(McbGetSize(), szSize, 10);
	strResults += _T(", Size: ");
	strResults += szSize;

	_ltot(McbGetAccessMask(), szSize, 16);
	strResults += _T(", Access Mask: 0x");
	strResults += szSize;


	_ltot(McbGetControlFlags(), szSize, 10);
	strResults += _T(", Control Flags: ");
	strResults += szSize;

	strResults += _T(", ");
	strResults += McbSID(McbGetSID()).McbDump();

	return strResults;

}/* McbACEImpl<n>::McbDump */

/**
 ****************************************************************************
 * <P> **** overtype summary description **** </P>
 *
 * @methodName  McbACEImpl<n>::McbDumpXML
 *
 * @param       none
 *
 * @return      std::basic_string<TCHAR>
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	21st February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> std::basic_string<TCHAR> McbACEImpl<n>::McbDumpXML() const
{
	if (!m_pAce)
	{
		return std::basic_string<TCHAR>(_T("<ACE/>"));
	}

	std::basic_string<TCHAR> strResults(_T("<ACE Type="));

	switch(((ACE_HEADER *)m_pAce)->AceType)
	{
	case ACCESS_ALLOWED_ACE_TYPE:
		strResults += _T("ACCESS_ALLOWED_ACE");		
		break;

	case ACCESS_DENIED_ACE_TYPE:
		strResults += _T("ACCESS_DENIED_ACE");		
		break;

	case SYSTEM_AUDIT_ACE_TYPE:
		strResults += _T("SYSTEM_AUDIT_ACE");		
		break;
		
	default:
		strResults += _T("Unsupported");		
	}

	TCHAR szSize[10];

	_ltot(McbGetSize(), szSize, 10);
	strResults += _T(" Size=");
	strResults += szSize;

	_ltot(McbGetAccessMask(), szSize, 16);
	strResults += _T(", AccessMask=0x");
	strResults += szSize;


	_ltot(McbGetControlFlags(), szSize, 10);
	strResults += _T(", ControlFlags=");
	strResults += szSize;

	strResults += _T(">");
	strResults += McbSID(McbGetSID()).McbDumpXML();

	strResults += _T("</ACE>");

	return strResults;

}/* McbACEImpl<n>::McbDumpXML */

/**
 ****************************************************************************
 * <P> Debug dumps the access control list </P>
 *
 * @methodName  McbACLImpl<n>::McbDump
 *
 * @param       none
 *
 * @return      std::basic_string<TCHAR>
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	22nd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> std::basic_string<TCHAR> McbACLImpl<n>::McbDump() const 
{
	if (!m_pAcl)
	{
		return std::basic_string<TCHAR>(_T("ACL - Unallocated"));
	}
	
	TCHAR szSize[10];
	
	std::basic_string<TCHAR> strResults(_T("ACL - Size: "));
	_ltot(McbGetSize(), szSize, 10);
	strResults += szSize;

	strResults += _T(", Aces: ");
	_ltot(McbGetACECount(), szSize, 10);
	strResults += szSize;

	strResults += _T(", Revision: ");
	_ltot(McbGetRevision(), szSize, 10);
	strResults += szSize;
	
	strResults += _T(", ");

   /*
    *************************************************************************
    * trace the aces
    *************************************************************************
    */
	DWORD dwAceCount = McbGetACECount();
	for (DWORD dwAce = 0; dwAce < dwAceCount; dwAce++)
	{
		PACE pAce = McbGetACE(dwAce);

		if (pAce)
		{
			McbACE ace(pAce);

			strResults += ace.McbDump();

			if (dwAce+1 != dwAceCount)
			{
				strResults += _T(" ");
			}
		}
	}

	return strResults;

}/* McbACLImpl<n>::McbDump */

/**
 ****************************************************************************
 * <P> Debug dumps the access control list </P>
 *
 * @methodName  McbACLImpl<n>::McbDumpXML
 *
 * @param       none
 *
 * @return      std::basic_string<TCHAR>
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	22nd February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> std::basic_string<TCHAR> McbACLImpl<n>::McbDumpXML() const 
{
	if (!m_pAcl)
	{
		return std::basic_string<TCHAR>(_T("<ACL/>"));
	}
	
	TCHAR szSize[10];
	
	std::basic_string<TCHAR> strResults(_T("<ACL Size="));
	_ltot(McbGetSize(), szSize, 10);
	strResults += szSize;

	strResults += _T(" Revision=");
	_ltot(McbGetRevision(), szSize, 10);
	strResults += szSize;

	strResults += _T(" Aces=");
	_ltot(McbGetACECount(), szSize, 10);
	strResults += szSize;

	strResults += _T(">");

   /*
    *************************************************************************
    * trace the aces
    *************************************************************************
    */
	DWORD dwAceCount = McbGetACECount();
	for (DWORD dwAce = 0; dwAce < dwAceCount; dwAce++)
	{
		PACE pAce = McbGetACE(dwAce);

		if (pAce)
		{
			McbACE ace(pAce);
			strResults += ace.McbDumpXML();
		}
	}

	strResults += _T("</ACL>");

	return strResults;

}/* McbACLImpl<n>::McbDumpXML */

/**
 ****************************************************************************
 * <P> Trace the output </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbDump
 *
 * @param       none
 *
 * @return      std::basic_string<TCHAR>
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	24th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> std::basic_string<TCHAR> 
	McbSecurityDescriptorImpl<n>::McbDump() const
{
	if (!m_pSD)
	{
		return std::basic_string<TCHAR>(
			_T("SECURITY DESCRIPTOR - Unallocated"));
	}

	std::basic_string<TCHAR> strDefault(_T("default"));
	std::basic_string<TCHAR> strResult(_T("SECURITY DESCRIPTOR - Owner "));

	McbSID sid;
	McbACL acl;

	if (McbIsDefaultSIDOwner())
	{
		strResult += strDefault;
	}
	else
	{
		sid = McbGetSIDOwner();
		strResult += sid.McbDump().c_str();
	}

	strResult += _T(", Group ");
	
	if (McbIsDefaultSIDGroup())
	{
		strResult += strDefault;
	}
	else
	{
		sid = McbGetSIDGroup();
		strResult += sid.McbDump().c_str();
	}

	strResult += _T(", Descretionary ");

	if (McbIsDefaultDACL())
	{
		strResult += strDefault;
	}
	else
	{
		acl = McbGetDACL();
		strResult += acl.McbDump().c_str();
	}
	
	strResult += _T(", Audit ");

	if (McbIsDefaultSACL())
	{
		strResult += strDefault;
	}
	else
	{
		acl = McbGetSACL();
		strResult += acl.McbDump().c_str();
	}

	return strResult;

}/* McbSecurityDescriptorImpl<n>::McbDump */

/**
 ****************************************************************************
 * <P> Trace the output </P>
 *
 * @methodName  McbSecurityDescriptorImpl<n>::McbDumpXML
 *
 * @param       none
 *
 * @return      std::basic_string<TCHAR>
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	24th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> std::basic_string<TCHAR> 
	McbSecurityDescriptorImpl<n>::McbDumpXML() const
{
	if (!m_pSD)
	{
		return std::basic_string<TCHAR>(_T("<SECURITY_DESCRIPTOR/>"));
	}

	std::basic_string<TCHAR> strDefault(_T("default"));
	std::basic_string<TCHAR> strResult(_T("<SECURITY_DESCRIPTOR>"));

	McbSID sid;
	McbACL acl;

	strResult += _T("<OwnerSID>");

	if (McbIsDefaultSIDOwner())
	{
		strResult += strDefault;
	}
	else
	{
		sid = McbGetSIDOwner();
		strResult += sid.McbDumpXML().c_str();
	}

	strResult += _T("</OwnerSID>");


	strResult += _T("<GroupSID>");
	
	if (McbIsDefaultSIDGroup())
	{
		strResult += strDefault;
	}
	else
	{
		sid = McbGetSIDGroup();
		strResult += sid.McbDumpXML().c_str();
	}

	strResult += _T("</GroupSID>");


	strResult += _T("<DACL>");	

	if (McbIsDefaultDACL())
	{
		strResult += strDefault;
	}
	else
	{
		acl = McbGetDACL();
		strResult += acl.McbDumpXML().c_str();
	}

	strResult += _T("</DACL>");
	

	strResult += _T("<SACL>");

	if (McbIsDefaultSACL())
	{
		strResult += strDefault;
	}
	else
	{
		acl = McbGetSACL();
		strResult += acl.McbDumpXML().c_str();
	}

	strResult += _T("</SACL>");

	strResult += _T("</SECURITY_DESCRIPTOR>");

	return strResult;

}/* McbSecurityDescriptorImpl<n>::McbDumpXML */

/**
 ****************************************************************************
 * <P> Dump the output </P>
 *
 * @methodName  McbPrivilegeImpl<n>::McbDump
 *
 * @param       none
 *
 * @return      void
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	21st February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> std::basic_string<TCHAR> McbPrivilegeImpl<n>::McbDump() const
{
	std::basic_string<TCHAR> strResults = _T("Luid - LowPart: 0x0");

	TCHAR szSize[10];

	_ltot(m_luid.LowPart, szSize, 16);
	strResults += szSize;
    strResults += _T(", HighPart: 0x0");
    _ltot(m_luid.HighPart, szSize, 16);
	strResults += szSize;

    std::basic_string<TCHAR> strName;

   /*
    *************************************************************************
    * attempt to obtain name of the privilege
    *************************************************************************
    */
	if (McbGetName(NULL, strName))
    {
        strResults += _T(" (");
        strResults += strName;
        strResults += _T(")");
    }

	return strResults;

}/* McbPrivilegeImpl<n>::McbDump */

/**
 ****************************************************************************
 * <P> Dump the output </P>
 *
 * @methodName  McbPrivilegeImpl<n>::McbDumpXML
 *
 * @param       none
 *
 * @return      void
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	21st February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> std::basic_string<TCHAR> McbPrivilegeImpl<n>::McbDumpXML() 
	const
{
	std::basic_string<TCHAR> strResults = _T("<LUID LowPart=0x0");

	TCHAR szSize[10];

	_ltot(m_luid.LowPart, szSize, 16);
	strResults += szSize;
    strResults += _T(" HighPart=0x0");
    _ltot(m_luid.HighPart, szSize, 16);
	strResults += szSize;

	strResults += _T(" Name=");

    std::basic_string<TCHAR> strName;

   /*
    *************************************************************************
    * attempt to obtain name of the privilege
    *************************************************************************
    */
	if (McbGetName(NULL, strName))
    {        
        strResults += strName;     
    }
	else
    {        
        strResults += _T("\"\"");     
    }

	strResults += _T(">");     

	return strResults;

}/* McbPrivilegeImpl<n>::McbDumpXML */

/**
 ****************************************************************************
 * <P> Trace the output </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbDump
 *
 * @param       none
 *
 * @return      std::basic_string<TCHAR>
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	24th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> std::basic_string<TCHAR> McbAccessTokenImpl<n>::McbDump() 
	const
{
	if (!m_hToken)
	{
		return std::basic_string<TCHAR>(_T("ACCESS TOKEN - Null Handle"));
	}
	
	std::basic_string<TCHAR> strResults(_T("ACCESS TOKEN - "));


   /*
    *************************************************************************
    * obtain type of privilege
    *************************************************************************
    */
	if (McbIsPrimaryType())
    {
        strResults += _T("Primary Type, ");
    }
    else
    {
        strResults += _T("Impersonation Type(");

        switch(McbGetImpersonationLevel())
        {
        case SecurityAnonymous:
            strResults += _T("Anonymous), ");
            break;
        case SecurityIdentification:
            strResults += _T("Identification), ");
            break;
        case SecurityImpersonation:
            strResults += _T("Impersonation), ");
            break;
        case SecurityDelegation:
            strResults += _T("Delegation), ");
            break;
        default:
            strResults += _T("Unknown), ");
        }
    }

	TCHAR szSize[10];

   /*
    *************************************************************************
    * dump the session id
    *************************************************************************
    */
	_ltot(McbGetSessionId(), szSize, 10);
    strResults += _T("SessionId: ");
	strResults += szSize;
    strResults += _T(", ");

   /*
    *************************************************************************
    * obtain the token source
    *************************************************************************
    */
	strResults += _T("Token Source: \"");

    PTOKEN_SOURCE pSource = McbGetSource();

    std::basic_string<TCHAR> strSource(_T("Unknown"));
    
    if (pSource)
    {

#ifdef _UNICODE

        LPCSTR lpszConvert = pSource->SourceName;
        TCHAR szBuffer[9];

       /*
        *********************************************************************
        * convert ascii to unicode
        *********************************************************************
        */
		::MultiByteToWideChar(CP_ACP,	// code page
            0,                          // character-type options
            lpszConvert,                // string to map
            8,                          // number of bytes in string
            szBuffer,                   // wide-character buffer 
            10);                        // size of buffer

        strSource.erase();
        strSource.append(szBuffer, 8);        

#else   // _UNICODE

        strSource.erase();
        strSource.append(pSource->SourceName, 8);

#endif  // _UNICODE

    }

    strResults += strSource;
	strResults += _T("\"");

   /*
    *************************************************************************
    * obtain luid from the token source
    *************************************************************************
    */
	McbPrivilege priv(pSource ? &pSource->SourceIdentifier : NULL);

	strResults += priv.McbDump();
        
   /*
    *************************************************************************
    * dump the owner
    *************************************************************************
    */
	McbSID sid(McbGetOwner());

    strResults += _T(", Owner ");
    strResults += sid.McbDump();

   /*
    *************************************************************************
    * dump the user
    *************************************************************************
    */
	sid = McbGetUser();

    strResults += _T(", User ");
    strResults += sid.McbDump();


   /*
    *************************************************************************
    * dump the primary group
    *************************************************************************
    */
	sid = McbGetPrimaryGroup();

    strResults += _T(", Primary Group ");
    strResults += sid.McbDump();

    McbACL acl;

   /*
    *************************************************************************
    * dump the default dacl
    *************************************************************************
    */
	acl = McbGetDefaultDACL();

    strResults += _T(", Default DACL ");
    strResults += acl.McbDump();
   
   /*
    *************************************************************************
    * dump the groups
    *************************************************************************
    */
	McbAccessTokenImpl::McbGroups groups(McbGetGroups());

    strResults += _T(", Groups ");
    strResults += groups.McbDump();

   /*
    *************************************************************************
    * dump the restricting sids
    *************************************************************************
    */
	groups = McbGetRestrictingSids();

    strResults += _T(", Restricting Sids ");
    strResults += groups.McbDump();

   /*
    *************************************************************************
    * dump the privileges
    *************************************************************************
    */    
	McbAccessTokenImpl<n>::McbPrivileges privs(McbGetPrivileges());
    
    strResults += _T(", Privileges ");
    strResults += privs.McbDump();

    return strResults;
    
}/* McbAccessTokenImpl<n>::McbDump */

/**
 ****************************************************************************
 * <P> Trace the output </P>
 *
 * @methodName  McbAccessTokenImpl<n>::McbDumpXML
 *
 * @param       none
 *
 * @return      std::basic_string<TCHAR>
 *
 * @exception   
 *
 * @author      Martyn C Brown
 *
 * @changeHistory  
 *	24th February  	2000	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> std::basic_string<TCHAR> McbAccessTokenImpl<n>::McbDumpXML() 
	const
{
	if (!m_hToken)
	{
		return std::basic_string<TCHAR>(_T("<ACCESS_TOKEN/>"));
	}
	
	std::basic_string<TCHAR> strResults(_T("<ACCESS_TOKEN TOKEN_TYPE="));

   /*
    *************************************************************************
    * obtain type of privilege
    *************************************************************************
    */
	if (McbIsPrimaryType())
    {
        strResults += _T("TokenPrimary");
    }
    else
    {
        strResults += _T("TokenImpersonation");
	}

	strResults += _T(" SECURITY_IMPERSONATION_LEVEL=");

    switch(McbGetImpersonationLevel())
    {
    case SecurityAnonymous:
        strResults += _T("SecurityAnonymous");
        break;
    case SecurityIdentification:
        strResults += _T("SecurityIdentification");
        break;
    case SecurityImpersonation:
        strResults += _T("SecurityImpersonation");
        break;
    case SecurityDelegation:
        strResults += _T("SecurityDelegation");
        break;
    default:
        strResults += _T("Unknown");
    }

	TCHAR szSize[10];

   /*
    *************************************************************************
    * dump the session id
    *************************************************************************
    */
	_ltot(McbGetSessionId(), szSize, 10);
    strResults += _T(" SessionId=");
	strResults += szSize;

    strResults += _T(">");

   /*
    *************************************************************************
    * obtain the token source
    *************************************************************************
    */
	strResults += _T("<TOKEN_SOURCE Name=");

    PTOKEN_SOURCE pSource = McbGetSource();

    std::basic_string<TCHAR> strSource(_T("\"\""));
    
    if (pSource)
    {

#ifdef _UNICODE

        LPCSTR lpszConvert = pSource->SourceName;
        TCHAR szBuffer[9];

       /*
        *********************************************************************
        * convert ascii to unicode
        *********************************************************************
        */
		::MultiByteToWideChar(CP_ACP,	// code page
            0,                          // character-type options
            lpszConvert,                // string to map
            8,                          // number of bytes in string
            szBuffer,                   // wide-character buffer 
            10);                        // size of buffer

        strSource.erase();
        strSource.append(szBuffer, 8);        

#else   // _UNICODE

        strSource.erase();
        strSource.append(pSource->SourceName, 8);

#endif  // _UNICODE

    }

    strResults += strSource;
	strResults += _T("><SourceIdentifier>");

   /*
    *************************************************************************
    * obtain luid from the token source
    *************************************************************************
    */
	McbPrivilege priv(pSource ? &pSource->SourceIdentifier : NULL);

	strResults += priv.McbDumpXML();
	strResults += _T("</SourceIdentifier></TOKEN_SOURCE>");
        
   /*
    *************************************************************************
    * dump the owner
    *************************************************************************
    */
	McbSID sid(McbGetOwner());
    
	strResults += _T("<OWNER>");
    strResults += sid.McbDumpXML();
	strResults += _T("</OWNER>");

   /*
    *************************************************************************
    * dump the user
    *************************************************************************
    */
	sid = McbGetUser();

    strResults += _T("<USER>");
    strResults += sid.McbDumpXML();
	strResults += _T("</USER>");


   /*
    *************************************************************************
    * dump the primary group
    *************************************************************************
    */
	sid = McbGetPrimaryGroup();

    strResults += _T("<PRIMARYGROUP>");
    strResults += sid.McbDumpXML();
	strResults += _T("</PRIMARYGROUP>");

    McbACL acl;

   /*
    *************************************************************************
    * dump the default dacl
    *************************************************************************
    */
	acl = McbGetDefaultDACL();

    strResults += _T("<DefaultDACL>");
    strResults += acl.McbDumpXML();
	strResults += _T("</DefaultDACL>");
   
   /*
    *************************************************************************
    * dump the groups
    *************************************************************************
    */
	McbAccessTokenImpl<n>::McbGroups groups(McbGetGroups());

    strResults += _T("<GROUPS>");
    strResults += groups.McbDumpXML();
	strResults += _T("</GROUPS>");

   /*
    *************************************************************************
    * dump the restricting sids
    *************************************************************************
    */
	groups = McbGetRestrictingSids();

    strResults += _T("<RestrictingSids>");
    strResults += groups.McbDumpXML();
	strResults += _T("</RestrictingSids>");

   /*
    *************************************************************************
    * dump the privileges
    *************************************************************************
    */    
	McbAccessTokenImpl<n>::McbPrivileges privs(McbGetPrivileges());
    
    strResults += _T("<Privileges>");
    strResults += privs.McbDumpXML();
	strResults += _T("</Privileges>");

	strResults += _T("</ACCESS_TOKEN>");

    return strResults;
    
}/* McbAccessTokenImpl<n>::McbDumpXML */

/**
 ****************************************************************************
 * <P> Security utilities.  </P>
 *
 * @version     V1.0
 *
 * @author      Martyn C Brown 
 *
 * @changeHistory  
 *	6th November  	2001	 - 	(V1.0) Creation (MCB)
 ****************************************************************************
 */
template <int n> class McbSecurityUtilsImpl
{
public:
   /*
    *************************************************************************
    * Wrap access token for a thread 
    *************************************************************************
    */
	class McbThreadToken
	{
	public:
       /*
        *********************************************************************
        * Constructor attempts to open thread token
        *********************************************************************
        */
		McbThreadToken(bool bProcessContext = false, 		
			DWORD dwAccess = TOKEN_QUERY,
			HANDLE hThread = GetCurrentThread()) 
		  :	m_hToken(NULL)
		{
			if (!::OpenThreadToken(hThread, dwAccess, 
				bProcessContext == FALSE, &m_hToken))
			{
				m_hToken = NULL;
			}
		}

       /*
        *********************************************************************
        * Destructor
        *********************************************************************
        */
		~McbThreadToken() { if (m_hToken) ::CloseHandle(m_hToken); }

       /*
        *********************************************************************
        * Access the contained handle
        *********************************************************************
        */
		operator HANDLE() { return McbGetHANDLE(); }
		operator const HANDLE() { return McbGetHANDLE(); }

       /*
        *********************************************************************
        * Other accessors
        *********************************************************************
        */
		const HANDLE McbGetHANDLE() const { return m_hToken; }
		HANDLE McbGetHANDLE() { return m_hToken; }

	protected:
		HANDLE m_hToken;
	};

   /*
    *************************************************************************
    * Wrap access token for a process 
    *************************************************************************
    */
	class McbProcessToken
	{
	public:
       /*
        *********************************************************************
        * Constructor attempts to open Process token
        *********************************************************************
        */
		McbProcessToken(DWORD dwAccess = TOKEN_QUERY, 
			HANDLE hProcess = GetCurrentProcess()) : m_hToken(NULL)
		{
			if (!::OpenProcessToken(hProcess, dwAccess, &m_hToken))
			{
				m_hToken = NULL;
			}
		}

       /*
        *********************************************************************
        * Destructor
        *********************************************************************
        */
		~McbProcessToken() { if (m_hToken) ::CloseHandle(m_hToken); }

       /*
        *********************************************************************
        * Access the contained handle
        *********************************************************************
        */
		operator HANDLE() { return McbGetHANDLE(); }
		operator const HANDLE() { return McbGetHANDLE(); }

       /*
        *********************************************************************
        * Other accessors
        *********************************************************************
        */
		const HANDLE McbGetHANDLE() const { return m_hToken; }
		HANDLE McbGetHANDLE() { return m_hToken; }

	protected:
		HANDLE m_hToken;
	};

   /*
    *************************************************************************
    * Class to obtain the process sid (use McbGetProcessSID() below).
    *************************************************************************
    */
	class McbProcessSid
	{
	public:
		McbProcessSid()	: m_pSID(NULL)
		{
			McbSecurityUtils::McbProcessToken procToken;

			McbAccessToken accessToken(procToken.McbGetHANDLE());

			m_sid = accessToken.McbGetUser();

			if (m_sid.McbIsValid())
			{
				m_pSID = m_sid;
			}
		}

       /*
        *********************************************************************
        * Operator overloads for convenience
        *********************************************************************
        */
		operator PSID() { return McbGetSID(); }
		operator const PSID() const { return McbGetSID(); }

       /*
        *********************************************************************
        * Other accessors
        *********************************************************************
        */
		const PSID McbGetSID() const { return m_pSID; }
		PSID McbGetSID() { return m_pSID; }

	protected:
       /*
        *********************************************************************
        * Members
        *********************************************************************
        */
		McbSIDImpl<0>	m_sid;		
		PSID			m_pSID;
	};

   /*
    *************************************************************************
    * Static method to obtain the SID for the process.
    *************************************************************************
    */
	static PSID McbGetProcessSID()
	{
		static McbProcessSid sid;
		return sid.McbGetSID();
	}
};

/*
 ****************************************************************************
 * Typedefs for ease of use.
 ****************************************************************************
 */
typedef McbSIDImpl<0>					McbSID;
typedef McbACEImpl<0>					McbACE;
typedef McbACLImpl<0>					McbACL;
typedef McbSecurityDescriptorImpl<0>		McbSecurityDescriptor;
typedef McbSecurityDescriptorImpl<0>		McbSD;
typedef McbPrivilegeImpl<0>				McbPrivilege;
typedef McbAccessTokenImpl<0>			McbAccessToken;
typedef McbSecurityUtilsImpl<0>			McbSecurityUtils;

//} // namespace McbAccessControl2

#endif //McbAccessControl2_Included
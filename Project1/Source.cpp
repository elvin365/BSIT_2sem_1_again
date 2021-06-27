#pragma once

#include <iostream>
#include <iomanip>
#include <windows.h>
#include <lm.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <Scesvc.h>
#include <ntstatus.h>

using std::cin;
using std::wcin;
using std::cout;
using std::wcout;


#define LSA_LOOKUP_ISOLATED_AS_LOCAL 0x80000000

typedef NTSTATUS
(NTAPI *_LsaOpenPolicy)(
	_In_opt_ PLSA_UNICODE_STRING SystemName,
	_In_ PLSA_OBJECT_ATTRIBUTES ObjectAttributes,
	_In_ ACCESS_MASK DesiredAccess,
	_Out_ PLSA_HANDLE PolicyHandle
	);

typedef NET_API_STATUS(NET_API_FUNCTION
	*_NetLocalGroupAddMembers)(
		_In_opt_  LPCWSTR     servername OPTIONAL,
		_In_      LPCWSTR     groupname,
		_In_      DWORD      level,
		_In_reads_(_Inexpressible_("varies"))  LPBYTE     buf,
		_In_      DWORD      totalentries
		);

typedef NTSTATUS
(NTAPI
	*_LsaLookupNames2)(
		_In_ LSA_HANDLE PolicyHandle,
		_In_ ULONG Flags, // Reserved
		_In_ ULONG Count,
		_In_ PLSA_UNICODE_STRING Names,
		_Out_ PLSA_REFERENCED_DOMAIN_LIST *ReferencedDomains,
		_Out_ PLSA_TRANSLATED_SID2 *Sids
		);

typedef ULONG
(NTAPI
	*_LsaNtStatusToWinError)(
		_In_ NTSTATUS Status
		);

typedef NTSTATUS
(NTAPI
	*_LsaFreeMemory)(
		_In_opt_ PVOID Buffer
		);

typedef NTSTATUS
(NTAPI
	*_LsaClose)(
		_In_ LSA_HANDLE ObjectHandle
		);

typedef NET_API_STATUS(NET_API_FUNCTION
	*_NetUserAdd)(
		_In_opt_  LPCWSTR    servername OPTIONAL,
		_In_      DWORD      level,
		_In_      LPBYTE     buf,
		_Out_opt_ LPDWORD    parm_err OPTIONAL
		);

typedef NET_API_STATUS(NET_API_FUNCTION
	*_NetUserDel)(
		_In_opt_  LPCWSTR    servername OPTIONAL,
		_In_      LPCWSTR    username
		);

typedef
NTSTATUS
(NTAPI
	*_LsaAddAccountRights)(
		_In_ LSA_HANDLE PolicyHandle,
		_In_ PSID AccountSid,
		_In_reads_(CountOfRights) PLSA_UNICODE_STRING UserRights,
		_In_ ULONG CountOfRights
		);

typedef NTSTATUS
(NTAPI
	*_LsaRemoveAccountRights)(
		_In_ LSA_HANDLE PolicyHandle,
		_In_ PSID AccountSid,
		_In_ BOOLEAN AllRights,
		_In_reads_opt_(CountOfRights) PLSA_UNICODE_STRING UserRights,
		_In_ ULONG CountOfRights
		);

typedef NET_API_STATUS(NET_API_FUNCTION
	*_NetUserEnum)(
		_In_opt_    LPCWSTR     servername OPTIONAL,
		_In_        DWORD      level,
		_In_        DWORD      filter,
		_Outptr_result_buffer_(_Inexpressible_("varies")) LPBYTE     *bufptr,
		_In_        DWORD      prefmaxlen,
		_Out_       LPDWORD    entriesread,
		_Out_       LPDWORD    totalentries,
		_Inout_opt_ PDWORD resume_handle OPTIONAL
		);

typedef BOOL
(WINAPI
	*_ConvertSidToStringSidA)(
		_In_  PSID     Sid,
		_Outptr_ LPSTR  *StringSid
		);

typedef NTSTATUS
(NTAPI
	*_LsaEnumerateAccountRights)(
		_In_ LSA_HANDLE PolicyHandle,
		_In_ PSID AccountSid,
		_Outptr_result_buffer_(*CountOfRights) PLSA_UNICODE_STRING *UserRights,
		_Out_ PULONG CountOfRights
		);

typedef NET_API_STATUS(NET_API_FUNCTION
	*_NetApiBufferFree)(
		_Frees_ptr_opt_ LPVOID Buffer
		);

typedef NET_API_STATUS(NET_API_FUNCTION
	*_NetLocalGroupEnum)(
		_In_opt_    LPCWSTR      servername OPTIONAL,
		_In_        DWORD       level,
		_Outptr_result_buffer_(_Inexpressible_("varies")) LPBYTE      *bufptr,
		_In_        DWORD       prefmaxlen,
		_Out_       LPDWORD     entriesread,
		_Out_       LPDWORD     totalentries,
		_Inout_opt_ PDWORD_PTR resumehandle OPTIONAL
		);

typedef HLOCAL
(WINAPI
	*_LocalFree)(
		_Frees_ptr_opt_ HLOCAL hMem
		);

typedef UINT
(WINAPI
	*_GetConsoleCP)(
		VOID
		);

typedef BOOL
(WINAPI
	*_SetConsoleCP)(
		_In_ UINT wCodePageID
		);

typedef DWORD
(WINAPI
	*_GetLastError)(
		VOID
		);

typedef NET_API_STATUS(NET_API_FUNCTION
	*_NetLocalGroupDelMembers)(
		_In_opt_  LPCWSTR     servername OPTIONAL,
		_In_      LPCWSTR     groupname,
		_In_      DWORD      level,
		_In_reads_(_Inexpressible_("varies"))  LPBYTE     buf,
		_In_      DWORD      totalentries
		);

typedef NET_API_STATUS(NET_API_FUNCTION
	*_NetUserSetInfo)(
		_In_opt_  LPCWSTR    servername OPTIONAL,
		_In_      LPCWSTR    username,
		_In_      DWORD     level,
		_In_reads_(_Inexpressible_("varies"))  LPBYTE    buf,
		_Out_opt_ LPDWORD   parm_err OPTIONAL
		);

typedef NET_API_STATUS(NET_API_FUNCTION
	*_NetLocalGroupAdd)(
		_In_opt_  LPCWSTR   servername OPTIONAL,
		_In_      DWORD    level,
		_In_reads_(_Inexpressible_("varies"))  LPBYTE   buf,
		_Out_opt_ LPDWORD  parm_err OPTIONAL
		);


typedef NET_API_STATUS(NET_API_FUNCTION
	*_NetLocalGroupDel)(
		_In_opt_  LPCWSTR   servername OPTIONAL,
		_In_      LPCWSTR   groupname
		);


typedef NET_API_STATUS(NET_API_FUNCTION
	*_NetLocalGroupSetInfo)(
		_In_opt_  LPCWSTR   servername OPTIONAL,
		_In_      LPCWSTR   groupname,
		_In_      DWORD    level,
		_In_reads_(_Inexpressible_("varies"))  LPBYTE   buf,
		_Out_opt_ LPDWORD  parm_err OPTIONAL
		);

_LsaOpenPolicy __LsaOpenPolicy;
_NetLocalGroupAddMembers __NetLocalGroupAddMembers;
_LsaLookupNames2 __LsaLookupNames2;
_LsaNtStatusToWinError __LsaNtStatusToWinError;
_LsaFreeMemory __LsaFreeMemory;
_LsaClose __LsaClose;
_NetUserAdd __NetUserAdd;
_NetUserDel __NetUserDel;
_LsaAddAccountRights __LsaAddAccountRights;
_LsaRemoveAccountRights __LsaRemoveAccountRights;
_NetUserEnum __NetUserEnum;
_ConvertSidToStringSidA __ConvertSidToStringSidA;
_LsaEnumerateAccountRights __LsaEnumerateAccountRights;
_NetApiBufferFree __NetApiBufferFree;
_NetLocalGroupEnum __NetLocalGroupEnum;
_LocalFree __LocalFree;
_GetConsoleCP __GetConsoleCP;
_SetConsoleCP __SetConsoleCP;
_GetLastError __GetLastError;
_NetLocalGroupDelMembers __NetLocalGroupDelMembers;
_NetUserSetInfo __NetUserSetInfo;
_NetLocalGroupSetInfo  __NetLocalGroupSetInfo;
_NetLocalGroupAdd __NetLocalGroupAdd;
_NetLocalGroupDel __NetLocalGroupDel;

bool InitLsaString(PLSA_UNICODE_STRING pLsaString, LPCWSTR pwszString);
PSID GetSIDInformation(LPWSTR AccountName);
LPCWSTR GetPrivilegeByNumber(int n);
void PrintPrivilegeList();
PLSA_UNICODE_STRING ChoosePrivilege(DWORD &cnt);
int AddUser();
int DeleteUser();
int AddPrivileges();
int DeletePrivileges();
int ListOfUsers();
int ListOfGroups();
int AddUserToGroup();
int DelUserFromGroup();
int init();
void PrintOptions();
int Process();






LSA_HANDLE ghPolicy;

bool InitLsaString(PLSA_UNICODE_STRING pLsaString, LPCWSTR pwszString)
{
	DWORD dwLen = 0;

	if (NULL == pLsaString)
		return FALSE;

	if (NULL != pwszString)
	{
		dwLen = wcslen(pwszString);
		if (dwLen > 0x7ffe)   // String is too large
			return FALSE;
	}

	// Store the string.
	pLsaString->Buffer = (WCHAR *)pwszString;
	pLsaString->Length = (USHORT)dwLen * sizeof(WCHAR);
	pLsaString->MaximumLength = (USHORT)(dwLen + 1) * sizeof(WCHAR);

	return TRUE;
}

PSID GetSIDInformation(LPWSTR AccountName)
{
	LSA_UNICODE_STRING lucName;
	PLSA_TRANSLATED_SID2 ltsTranslatedSID;
	PLSA_REFERENCED_DOMAIN_LIST lrdlDomainList;
	LSA_TRUST_INFORMATION myDomain;
	NTSTATUS ntsResult;
	PWCHAR DomainString = NULL;

	// Initialize an LSA_UNICODE_STRING with the name.
	if (!InitLsaString(&lucName, AccountName))
	{
		wprintf(L"Failed InitLsaString\n");
		return NULL;
	}

	ntsResult = __LsaLookupNames2(
		ghPolicy,     // handle to a Policy object
		LSA_LOOKUP_ISOLATED_AS_LOCAL,
		1,                // number of names to look up
		&lucName,         // pointer to an array of names
		&lrdlDomainList,  // receives domain information
		&ltsTranslatedSID // receives relative SIDs
	);
	if (STATUS_SUCCESS != ntsResult)
	{
		wprintf(L"Failed LsaLookupNames - %lu \n",
			__LsaNtStatusToWinError(ntsResult));
		return NULL;
	}

	// Get the domain the account resides in.
	myDomain = lrdlDomainList->Domains[ltsTranslatedSID->DomainIndex];
	__LsaFreeMemory(lrdlDomainList);
	return ltsTranslatedSID->Sid;
}

LPCWSTR GetPrivilegeByNumber(int n)
{
	switch (n)
	{
	//case 1:  return SE_ASSIGNPRIMARYTOKEN_NAME;
	case 1: return L"SeAssignPrimaryTokenPrivilege";
	case 2:	 return L"SeAuditPrivilege";
	case 3:	 return L"SeRestorePrivilege";
	case 4:	 return L"SeChangeNotifyPrivilege";
	case 5:	 return L"SeCreateGlobalPrivilege";
	case 6:	 return L"SeCreatePagefilePrivilege";
	case 7:	 return L"SeCreatePermanentPrivilege";
	case 8:	 return L"SeCreateSymbolicLinkPrivilege";
	case 9:	 return L"SeCreateTokenPrivilege";
	case 10: return L"SeDebugPrivilege";
	case 11: return L"SeDelegateSessionUserImpersonatePrivilege";
	case 12: return L"SeEnableDelegationPrivilege";
	case 13: return L"SeImpersonatePrivilege";
	case 14: return L"SeIncreaseBasePriorityPrivilege";
	case 15: return L"SeIncreaseQuotaPrivilege";
	case 16: return L"SeIncreaseWorkingSetPrivilege";
	case 17: return L"SeLoadDriverPrivilege";
	case 18: return L"SeLockMemoryPrivilege";
	case 19: return L"SeMachineAccountPrivilege";
	case 20: return L"SeManageVolumePrivilege";
	case 21: return L"SeProfileSingleProcessPrivilege";
	case 22: return L"SeRelabelPrivilege";
	case 23: return L"SeRemoteShutdownPrivilege";
	case 24: return L"SeRestorePrivilege";
	case 25: return L"SeSecurityPrivilege";
	case 26: return L"SeShutdownPrivilege";
	case 27: return L"SeSyncAgentPrivilege";
	case 28: return L"SeSystemEnvironmentPrivilege";
	case 29: return L"SeSystemProfilePrivilege";
	case 30: return L"SeSystemtimePrivilege";
	case 31: return L"SeTakeOwnershipPrivilege";
	case 32: return L"SeTcbPrivilege";
	case 33: return L"SeTimeZonePrivilege";
	case 34: return L"SeTrustedCredManAccessPrivilege";
	case 35: return L"SeUndockPrivilege";
	case 36: return L"SeBatchLogonRight";
	case 37: return L"SeDenyBatchLogonRight";
	case 38: return L"SeDenyInteractiveLogonRight";
	case 39: return L"SeDenyNetworkLogonRight";
	case 40: return L"SeDenyRemoteInteractiveLogonRight";
	case 41: return L"SeDenyServiceLogonRight";
	case 42: return L"SeInteractiveLogonRight";
	case 43: return L"SeNetworkLogonRight";
	case 44: return L"SeRemoteInteractiveLogonRight";
	case 45: return L"SeServiceLogonRight";
	default: return 0;
	}
}

void PrintPrivilegeList()
{
	cout << "    List of Privileges\n";
	cout << "1  " << "SE_ASSIGNPRIMARYTOKEN_NAME\n";
	cout << "2  " << "SE_AUDIT_NAME\n";
	cout << "3  " << "SE_BACKUP_NAME\n";
	cout << "4  " << "SE_CHANGE_NOTIFY_NAME\n";
	cout << "5  " << "SE_CREATE_GLOBAL_NAME\n";
	cout << "6  " << "SE_CREATE_PAGEFILE_NAME\n";
	cout << "7  " << "SE_CREATE_PERMANENT_NAME\n";
	cout << "8  " << "SE_CREATE_SYMBOLIC_LINK_NAME\n";
	cout << "9  " << "SE_CREATE_TOKEN_NAME\n";
	cout << "10 " << "SE_DEBUG_NAME\n";
	cout << "11 " << "SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME\n";
	cout << "12 " << "SE_ENABLE_DELEGATION_NAME\n";
	cout << "13 " << "SE_IMPERSONATE_NAME\n";
	cout << "14 " << "SE_INC_BASE_PRIORITY_NAME\n";
	cout << "15 " << "SE_INCREASE_QUOTA_NAME\n";
	cout << "16 " << "SE_INC_WORKING_SET_NAME\n";
	cout << "17 " << "SE_LOAD_DRIVER_NAME\n";
	cout << "18 " << "SE_LOCK_MEMORY_NAME\n";
	cout << "19 " << "SE_MACHINE_ACCOUNT_NAME\n";
	cout << "20 " << "SE_MANAGE_VOLUME_NAME\n";
	cout << "21 " << "SE_PROF_SINGLE_PROCESS_NAME\n";
	cout << "22 " << "SE_RELABEL_NAME\n";
	cout << "23 " << "SE_REMOTE_SHUTDOWN_NAME\n";
	cout << "24 " << "SE_RESTORE_NAME\n";
	cout << "25 " << "SE_SECURITY_NAME\n";
	cout << "26 " << "SE_SHUTDOWN_NAME\n";
	cout << "27 " << "SE_SYNC_AGENT_NAME\n";
	cout << "28 " << "SE_SYSTEM_ENVIRONMENT_NAME\n";
	cout << "29 " << "SE_SYSTEM_PROFILE_NAME\n";
	cout << "30 " << "SE_SYSTEMTIME_NAME\n";
	cout << "31 " << "SE_TAKE_OWNERSHIP_NAME\n";
	cout << "32 " << "SE_TCB_NAME\n";
	cout << "33 " << "SE_TIME_ZONE_NAME\n";
	cout << "34 " << "SE_TRUSTED_CREDMAN_ACCESS_NAME\n";
	cout << "35 " << "SE_UNDOCK_NAME\n";
	cout << "36 " << "SE_BATCH_LOGON_NAME\n";
	cout << "37 " << "SE_DENY_BATCH_LOGON_NAME\n";
	cout << "38 " << "SE_DENY_INTERACTIVE_LOGON_NAME\n";
	cout << "39 " << "SE_DENY_NETWORK_LOGON_NAME\n";
	cout << "40 " << "SE_DENY_REMOTE_INTERACTIVE_LOGON_NAME\n";
	cout << "41 " << "SE_DENY_SERVICE_LOGON_NAME\n";
	cout << "42 " << "SE_INTERACTIVE_LOGON_NAME\n";
	cout << "43 " << "SE_NETWORK_LOGON_NAME\n";
	cout << "44 " << "SE_REMOTE_INTERACTIVE_LOGON_NAME\n";
	cout << "45 " << "SE_SERVICE_LOGON_NAME\n";
	cout << "46 " << "-->> Prints full list again\n";
	cout << "Enter numbers deparated by spaces, enter 0 to end operation\n";
}

PLSA_UNICODE_STRING ChoosePrivilege(DWORD &cnt)
{
	cnt = 0;
	PLSA_UNICODE_STRING privs = new LSA_UNICODE_STRING[100];
	PrintPrivilegeList();
	int num = 0;
	do
	{
		cin >> num;
		cin.ignore();
		if (num == 0)
		{
			break;
		}
		else if (num == 46)
		{
			PrintPrivilegeList();
		}
		else
		{

			LPCWSTR str = GetPrivilegeByNumber(num);
			if (str != NULL && InitLsaString(&privs[cnt], str))
			{
				cnt++;
			}
		}
	} while (cnt < 99);
	if (cnt == 0)
	{
		delete privs;
		privs = NULL;
	}
	return privs;
}

int AddUser()
{
	int cp = __GetConsoleCP();
	__SetConsoleCP(1251);
	USER_INFO_1 info = { 0 };
	cout << "Enter Username: ";
	info.usri1_name = new wchar_t[MAX_PATH];
	wcin.getline(info.usri1_name, MAX_PATH - 1);
	cout << "Enter password: ";
	info.usri1_password = new wchar_t[PWLEN];
	wcin.getline(info.usri1_password, PWLEN - 1);
	info.usri1_flags = UF_NORMAL_ACCOUNT;
	info.usri1_priv = USER_PRIV_USER;

	DWORD res, error;
	res = __NetUserAdd(NULL, 1, (LPBYTE)&info, &error);
	__SetConsoleCP(cp);
	if (res != NERR_Success)
	{
		cout << "Error while creating user! " << __LsaNtStatusToWinError(res) << "\n";
		return -1;
	}
	return 0;
}

int DeleteUser()
{
	int cp = __GetConsoleCP();
	__SetConsoleCP(1251);
	cout << "Enter username: ";
	LPWSTR username = new wchar_t[MAX_PATH];
	wcin.getline(username, MAX_PATH - 1);
	DWORD res = __NetUserDel(NULL, username);
	__SetConsoleCP(cp);
	if (res != NERR_Success)
	{
		cout << "Error while deleting user! " << __LsaNtStatusToWinError(res) << "\n";
		return -1;
	}
	return 0;
}

int AddGroup()
{
	int cp = __GetConsoleCP();
	__SetConsoleCP(1251);
	LOCALGROUP_INFO_0 info = { 0 };
	cout << "Enter group name: ";
	info.lgrpi0_name = new wchar_t[MAX_PATH];
	wcin.getline(info.lgrpi0_name, MAX_PATH - 1);
	DWORD res, error;
	res = __NetLocalGroupAdd(NULL, 0, (LPBYTE)&info, &error);
	__SetConsoleCP(cp);
	if (res != NERR_Success)
	{
		cout << "Error while creating group! " << __LsaNtStatusToWinError(res) << "\n";
		return -1;
	}
	return 0;
}

int DeleteGroup()
{
	int cp = __GetConsoleCP();
	__SetConsoleCP(1251);
	cout << "Enter group name: ";
	LPWSTR groupname = new wchar_t[MAX_PATH];
	wcin.getline(groupname, MAX_PATH - 1);
	DWORD res = __NetLocalGroupDel(NULL, groupname);
	__SetConsoleCP(cp);
	if (res != NERR_Success)
	{
		cout << "Error while deleting user! " << __LsaNtStatusToWinError(res) << "\n";
		return -1;
	}
	return 0;
}



int AddPrivileges()
{
	int cp = __GetConsoleCP();
	__SetConsoleCP(1251);
	// Get Username
	wchar_t username[MAX_PATH];
	cout << "Enter Username: ";
	wcin.getline(username, MAX_PATH - 1);
	__SetConsoleCP(cp);
	// Get username's SID
	PSID sid = GetSIDInformation(username);
	if (!sid)
	{
		cout << "Error while getting account's SID.\n";
		return -1;
	}
	// Get privileges from user input
	DWORD cntPrivs = 0;
	PLSA_UNICODE_STRING privs = ChoosePrivilege(cntPrivs);
	if (!privs)
	{
		cout << "No privileges!\n";
		return -1;
	}
	// Add privileges to user's account
	NTSTATUS res;
	res = __LsaAddAccountRights(ghPolicy, sid, privs, cntPrivs);
	delete privs;
	if (res != STATUS_SUCCESS)
	{
		cout << "Error while adding privileges to account! " << __LsaNtStatusToWinError(res) << "\n";
		return -1;
	}
	return 0;
}

int DeletePrivileges()
{
	int cp = __GetConsoleCP();
	__SetConsoleCP(1251);
	cout << "Enter Username: ";
	LPWSTR username = new wchar_t[MAX_PATH];
	wcin.getline(username, MAX_PATH - 1);
	__SetConsoleCP(cp);
	PSID sid = GetSIDInformation(username);
	if (!sid)
	{
		cout << "Error while getting account's SID.\n";
		return -1;
	}
	DWORD cntPrivs = 0;
	PLSA_UNICODE_STRING privs = ChoosePrivilege(cntPrivs);
	if (!privs)
	{
		cout << "No privileges!\n";
		return -1;
	}
	NTSTATUS res;
	res = __LsaRemoveAccountRights(ghPolicy, sid, FALSE, privs, cntPrivs);
	delete privs;
	if (res != STATUS_SUCCESS)
	{
		cout << "Error while deleting privileges from account! " << __LsaNtStatusToWinError(res) << "\n";
		return -1;
	}
	return 0;
}

int ListOfUsers()
{
	LPUSER_INFO_0 pBuf = NULL;
	LPUSER_INFO_0 pTmpBuf;
	DWORD dwLevel = 0;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;
	DWORD i;
	DWORD dwTotalCount = 0;
	NET_API_STATUS nStatus;
	NTSTATUS res;

	//
	// Call the NetUserEnum function, specifying level 0; 
	//   enumerate global user account types only.
	//
	do
	{
		nStatus = __NetUserEnum(NULL,
			dwLevel,
			FILTER_NORMAL_ACCOUNT, // global users
			(LPBYTE*)&pBuf,
			dwPrefMaxLen,
			&dwEntriesRead,
			&dwTotalEntries,
			&dwResumeHandle);
		//
		// If the call succeeds,
		//
		if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
		{
			if ((pTmpBuf = pBuf) != NULL)
			{
				//
				// Loop through the entries.
				//
				for (i = 0; (i < dwEntriesRead); i++)
				{

					if (pTmpBuf == NULL)
					{
						fprintf(stderr, "An access violation has occurred\n");
						break;
					}
					//
					//  Print the name of the user account.
					//
					PSID sid = GetSIDInformation(pTmpBuf->usri0_name);
					if (!sid)
					{
						cout << "Error while getting account's SID.\n";
						break;
					}
					LPSTR SIDstr;
					if (!__ConvertSidToStringSidA(sid, &SIDstr))
					{
						cout << "Error while converting SID to string! " << __GetLastError() << "\n";
						break;
					}
					wcout << std::left << std::setw(20) << pTmpBuf->usri0_name << " SID: " << SIDstr << "\n";
					__LocalFree(SIDstr);

					PLSA_UNICODE_STRING privs = NULL;
					ULONG cntPrivs = 0;
					res = __LsaEnumerateAccountRights(ghPolicy, sid, &privs, &cntPrivs);
					if (res == STATUS_OBJECT_NAME_NOT_FOUND)
					{
						wcout << std::string(21, ' ').c_str() << "No rights available! \n\n";
					}
					else if (res != STATUS_SUCCESS)
					{
						cout << "Error while enumerating account privileges! " << __LsaNtStatusToWinError(res) << "\n";
						break;
					}
					else
					{
						for (int j = 0; j < cntPrivs; j++)
						{
							wcout << std::string(21, ' ').c_str() << privs[j].Buffer << "\n";
						}
						wcout << "\n";
					}
					__LsaFreeMemory(privs);
					pTmpBuf++;
					dwTotalCount++;
				}
			}
		}
		//
		// Otherwise, print the system error.
		//
		else
			fprintf(stderr, "A system error has occurred: %d\n", nStatus);
		//
		// Free the allocated buffer.
		//
		if (pBuf != NULL)
		{
			__NetApiBufferFree(pBuf);
			pBuf = NULL;
		}
	} while (nStatus == ERROR_MORE_DATA); // end do


	if (pBuf != NULL)
		__NetApiBufferFree(pBuf);


	fprintf(stderr, "\nTotal of %d entries enumerated\n", dwTotalCount);

	return 0;
}

int ListOfGroups()
{
	PLOCALGROUP_INFO_1  pBuff = NULL, pTmpBuf;
	DWORD nStatus;
	DWORD i = 0;
	DWORD dwEntriesRead = 0;
	DWORD_PTR dwResumeHandle = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwTotalCount = 0;
	NTSTATUS res;

	do
	{
		nStatus = __NetLocalGroupEnum(NULL, 1, (LPBYTE*)&pBuff, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);
		if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
		{
			if ((pTmpBuf = pBuff) != NULL)
			{
				//
				// Loop through the entries.
				//
				for (i = 0; (i < dwEntriesRead); i++)
				{

					if (pTmpBuf == NULL)
					{
						fprintf(stderr, "An access violation has occurred\n");
						break;
					}


					PSID sid = GetSIDInformation(pTmpBuf->lgrpi1_name);
					if (!sid)
					{
						cout << "Error while getting account's SID.\n";
						break;
					}
					LPSTR SIDstr;
					if (!__ConvertSidToStringSidA(sid, &SIDstr))
					{
						cout << "Error while converting SID to string! " << GetLastError() << "\n";
						break;
					}

					wcout << std::left << std::setw(50) << pTmpBuf->lgrpi1_name << "SID: " << SIDstr << "\n";

					__LocalFree(SIDstr);
					PLSA_UNICODE_STRING privs = NULL;
					ULONG cntPrivs = 0;
					res = __LsaEnumerateAccountRights(ghPolicy, sid, &privs, &cntPrivs);
					if (res == STATUS_OBJECT_NAME_NOT_FOUND)
					{
						wcout << std::string(50, ' ').c_str() << "No rights available! \n\n";
					}
					else if (res != STATUS_SUCCESS)
					{
						cout << "Error while enumerating account privileges! " << __LsaNtStatusToWinError(res) << "\n";
						break;
					}
					else
					{
						for (int j = 0; j < cntPrivs; j++)
						{
							wcout << std::string(50, ' ').c_str() << privs[j].Buffer << "\n";
						}
						wcout << "\n";
					}
					__LsaFreeMemory(privs);
					pTmpBuf++;
					dwTotalCount++;
				}
			}
		}
		else
		{
			cout << "Error while enumerating groups! " << nStatus << "\n";
		}
	} while (nStatus == ERROR_MORE_DATA);

	if (pBuff != NULL)
		__NetApiBufferFree(pBuff);

	fprintf(stderr, "\nTotal of %d entries enumerated\n", dwTotalCount);
	return 0;
}

int AddUserToGroup()
{
	cout << "Enter Username: ";
	int cp = __GetConsoleCP();
	__SetConsoleCP(1251);
	wchar_t username[MAX_PATH];
	wcin.getline(username, MAX_PATH - 1);
	cout << "Enter Group: ";
	wchar_t groupname[MAX_PATH];
	wcin.getline(groupname, MAX_PATH - 1);
	__SetConsoleCP(cp);
	PSID sid = GetSIDInformation(username);
	LOCALGROUP_MEMBERS_INFO_0 user;
	user.lgrmi0_sid = sid;
	DWORD NtStatus;
	NtStatus = __NetLocalGroupAddMembers(NULL, groupname, 0, (LPBYTE)&user, 1);
	if (NtStatus != NERR_Success)
	{
		cout << "Error while adding user to group! " << NtStatus << "\n";
		return -1;
	}
	return 0;
}

int DelUserFromGroup()
{
	cout << "Enter Username: ";
	int cp = __GetConsoleCP();
	__SetConsoleCP(1251);
	wchar_t username[MAX_PATH];
	wcin.getline(username, MAX_PATH - 1);
	cout << "Enter Group: ";
	wchar_t groupname[MAX_PATH];
	wcin.getline(groupname, MAX_PATH - 1);
	__SetConsoleCP(cp);
	PSID sid = GetSIDInformation(username);
	LOCALGROUP_MEMBERS_INFO_0 user;
	user.lgrmi0_sid = sid;
	DWORD NtStatus;
	NtStatus = __NetLocalGroupDelMembers(NULL, groupname, 0, (LPBYTE)&user, 1);
	if (NtStatus != NERR_Success)
	{
		cout << "Error while deleting user from group! " << NtStatus << "\n";
		return -1;
	}
	return 0;
}

int RenameUser()
{
	cout << "Enter Username: ";
	int cp = __GetConsoleCP();
	__SetConsoleCP(1251);
	wchar_t username[MAX_PATH];
	wcin.getline(username, MAX_PATH - 1);
	cout << "Enter new Username: ";
	wchar_t Newusername[MAX_PATH];
	wcin.getline(Newusername, MAX_PATH - 1);
	__SetConsoleCP(cp);
	USER_INFO_0 info = { 0 };
	info.usri0_name = Newusername;
	DWORD res = __NetUserSetInfo(NULL, username, 0, (LPBYTE)&info, NULL);
	if (res != NERR_Success)
	{
		cout << "Error while renaming user! " << res << "\n";
		return -1;
	}
	return 0;
}

int RenameGroup()
{
	cout << "Enter Group name: ";
	int cp = __GetConsoleCP();
	__SetConsoleCP(1251);
	wchar_t groupname[MAX_PATH];
	wcin.getline(groupname, MAX_PATH - 1);
	cout << "Enter new Group name: ";
	wchar_t Newgroupname[MAX_PATH];
	wcin.getline(Newgroupname, MAX_PATH - 1);
	__SetConsoleCP(cp);
	GROUP_INFO_0 info = { 0 };
	info.grpi0_name = Newgroupname;
	DWORD res = __NetLocalGroupSetInfo(NULL, groupname, 0, (LPBYTE)&info, NULL);
	if (res != NERR_Success)
	{
		cout << "Error while renaming group! " << res << "\n";
		return -1;
	}
	return 0;
}

int init()
{
	HMODULE Kernel32DLL = LoadLibraryA("Kernel32.dll");
	HMODULE Netapi32DLL = LoadLibraryA("Netapi32.dll");
	HMODULE Advapi32DLL = LoadLibraryA("Advapi32.dll");
	if (!Netapi32DLL || !Advapi32DLL)
	{
		cout << "Error while loading dynamic libraries! \n";
		return -1;
	}
	__LsaOpenPolicy = (_LsaOpenPolicy)GetProcAddress(Advapi32DLL, "LsaOpenPolicy");
	__LsaOpenPolicy = (_LsaOpenPolicy)GetProcAddress(Advapi32DLL, "LsaOpenPolicy");
	__NetLocalGroupAddMembers = (_NetLocalGroupAddMembers)GetProcAddress(Netapi32DLL, "NetLocalGroupAddMembers");
	__LsaLookupNames2 = (_LsaLookupNames2)GetProcAddress(Advapi32DLL, "LsaLookupNames2");
	__LsaNtStatusToWinError = (_LsaNtStatusToWinError)GetProcAddress(Advapi32DLL, "LsaNtStatusToWinError");
	__LsaFreeMemory = (_LsaFreeMemory)GetProcAddress(Advapi32DLL, "LsaFreeMemory");
	__LsaClose = (_LsaClose)GetProcAddress(Advapi32DLL, "LsaClose");
	__NetUserAdd = (_NetUserAdd)GetProcAddress(Netapi32DLL, "NetUserAdd");
	__NetUserDel = (_NetUserDel)GetProcAddress(Netapi32DLL, "NetUserDel");
	__LsaAddAccountRights = (_LsaAddAccountRights)GetProcAddress(Advapi32DLL, "LsaAddAccountRights");
	__LsaRemoveAccountRights = (_LsaRemoveAccountRights)GetProcAddress(Advapi32DLL, "LsaRemoveAccountRights");
	__NetUserEnum = (_NetUserEnum)GetProcAddress(Netapi32DLL, "NetUserEnum");
	__ConvertSidToStringSidA = (_ConvertSidToStringSidA)GetProcAddress(Advapi32DLL, "ConvertSidToStringSidA");
	__LsaEnumerateAccountRights = (_LsaEnumerateAccountRights)GetProcAddress(Advapi32DLL, "LsaEnumerateAccountRights");
	__NetApiBufferFree = (_NetApiBufferFree)GetProcAddress(Netapi32DLL, "NetApiBufferFree");
	__NetLocalGroupEnum = (_NetLocalGroupEnum)GetProcAddress(Netapi32DLL, "NetLocalGroupEnum");
	__LocalFree = (_LocalFree)GetProcAddress(Kernel32DLL, "LocalFree");
	__GetConsoleCP = (_GetConsoleCP)GetProcAddress(Kernel32DLL, "GetConsoleCP");
	__SetConsoleCP = (_SetConsoleCP)GetProcAddress(Kernel32DLL, "SetConsoleCP");
	__NetLocalGroupAddMembers = (_NetLocalGroupAddMembers)GetProcAddress(Netapi32DLL, "NetLocalGroupAddMembers");
	__GetLastError = (_GetLastError)GetProcAddress(Kernel32DLL, "GetLastError");
	__NetLocalGroupDelMembers = (_NetLocalGroupDelMembers)GetProcAddress(Netapi32DLL, "NetLocalGroupDelMembers");
	__NetUserSetInfo = (_NetUserSetInfo)GetProcAddress(Netapi32DLL, "NetUserSetInfo");
	__NetLocalGroupSetInfo = (_NetLocalGroupSetInfo)GetProcAddress(Netapi32DLL, "NetLocalGroupSetInfo");
	__NetLocalGroupAdd = (_NetLocalGroupAdd)GetProcAddress(Netapi32DLL, "NetLocalGroupAdd");
	__NetLocalGroupDel = (_NetLocalGroupDel)GetProcAddress(Netapi32DLL, "NetLocalGroupDel");
	setlocale(LC_ALL, "Russian");


	LSA_OBJECT_ATTRIBUTES attr = { 0 };
	NTSTATUS res;
	res = __LsaOpenPolicy(NULL, &attr, POLICY_ALL_ACCESS, &ghPolicy);
	if (res != STATUS_SUCCESS)
	{
		cout << "Error while opening policy handle! " << __LsaNtStatusToWinError(res) << "\n";
		return -1;
	}

	return 0;
}

void PrintOptions()
{
	cout << "    OPTIONS\n";
	cout << "1 " << "Add User\n";
	cout << "2 " << "Delete User\n";
	cout << "3 " << "Add Group\n";
	cout << "4 " << "Delete Group\n";
	cout << "5 " << "Add Privileges\n";
	cout << "6 " << "Delete Privileges\n";
	cout << "7 " << "List Of Users\n";
	cout << "8 " << "List Of Groups\n";
	cout << "9 " << "Add User to Group\n";
	cout << "10 " << "Delete User from Group\n";
	cout << "11 " << "Rename User\n";
	cout << "12 " << "Rename Group\n";
	cout << "13 " << "Print options again\n";
}

int Process()
{
	PrintOptions();
	int n = 0;
	while (1)
	{
		cout << "Enter number of option: ";
		cin >> n;
		cin.ignore();
		switch (n)
		{
		case 1: cout << "Add User\n"; AddUser(); break;
		case 2: cout << "Delete User\n"; DeleteUser(); break;
		case 3: cout << "Add Group\n"; AddGroup(); break;
		case 4: cout << "Delete Group\n"; DeleteGroup(); break;
		case 5: cout << "Add Privileges\n"; AddPrivileges(); break;
		case 6: cout << "Delete Privileges\n"; DeletePrivileges(); break;
		case 7: cout << "List Of Users\n"; ListOfUsers(); break;
		case 8: cout << "List Of Groups\n"; ListOfGroups(); break;
		case 9: cout << "Add User to Group\n"; AddUserToGroup(); break;
		case 10: cout << "Delete User from Group\n"; DelUserFromGroup(); break;
		case 11: cout << "Rename User\n"; RenameUser(); break;
		case 12: cout << "Rename Group\n"; RenameGroup(); break;
		case 13: cout << "Print options again\n\n"; PrintOptions(); break;
			//case 10: cout << "Exit\n"; __LsaClose(ghPolicy); return 0;
		}
	}
}

int main()
{
	if (init() != 0)
	{
		cout << "Error while initializing!\n";
		return 0;
	}

	Process();

}


/*
  Dokan : user-mode file system library for Windows

  Copyright (C) 2015 - 2017 Adrien J. <liryna.stark@gmail.com> and Maxime C. <maxime@islog.com>
  Copyright (C) 2007 - 2011 Hiroki Asakawa <info@dokan-dev.net>

  http://dokan-dev.github.io

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include "mirror.h"
#include "../../dokany/dokan/dokan.h"
#include "../../dokany/dokan/fileinfo.h"
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <winbase.h>
#include <process.h>

//=====================================
// UTILITY STUFF - FOR RECORDING EVENTS
class EventSubmitter
{
	CDokanyEvent* pEvent;
public:
	EventSubmitter(CDokanyEvent* pE) : pEvent(pE)
	{
		SetLastError(0);
	}
	~EventSubmitter()
	{
		// add GetLastError()
		DWORD dw = GetLastError();
		if (dw != 0)
		{
			wchar_t buf[256];
			swprintf_s(buf, L"GetLastError() %d", dw);
			pEvent->AddComment(buf);
		}

		// finally submit the event to the queue
		g_Mirror()->AddEvent(pEvent,false);
	}
};

//============================================
class MirrorEvent : public CDokanyEvent
{
public:
	MirrorEvent(LPCWSTR CommandName, LPCWSTR FileName, PDOKAN_FILE_INFO info, __int64 ThreadId )
		: CDokanyEvent(CommandName, FileName, info->Context, info->ProcessId, ThreadId) 
	{
		AddDokanyFlag(info->IsDirectory, L'F');
		AddDokanyFlag(info->DeleteOnClose, L'D');
		AddDokanyFlag(info->Nocache, L'N');
		AddDokanyFlag(info->PagingIo, L'P');
		AddDokanyFlag(info->SynchronousIo, L'S');
	}
};
#define DEFINE_EVENT(cmd,fn,dkinfo)  MirrorEvent* pEvent = new MirrorEvent( cmd, fn, dkinfo, GetCurrentThreadId() ); EventSubmitter __e(pEvent);

//==========================================================
// UTILITY STUFF - ANNOTATING EVENTS
static std::wstring QI(const std::wstring& p, __int64 v)
{
	wchar_t buf[255];
	swprintf_s(buf, L"%s=%lld", p.c_str(), v);
	return buf;
}
static std::wstring FI(FILETIME ft)
{
	return L"FILETIME";
}
static std::wstring FS(DWORD fileSizeHigh, DWORD fileSizeLow)
{
	UINT64 fileSize = ((UINT64)fileSizeHigh << 32) | fileSizeLow;

	wchar_t buf[255];
	swprintf_s(buf, L"%lld", fileSize);
	return buf;
}
static std::wstring FH(HANDLE h)
{
	wchar_t buf[255];
	swprintf_s(buf, L"%lld", (unsigned __int64)h);
	return buf;
}

#define ADD_QI(v)						{ pEvent->AddComment(QI(L#v,v)); }
#define ADD_RETURN(b)					{ pEvent->AddComment(std::wstring(L"return") + L"=" + (b?L"TRUE":L"FALSE"); }
#define ADD_COMMENT_IF_FLAG(val,flag)	{ if ( val & flag ) pEvent->AddComment(L#flag);			}
#define ADD_COMMENT_IF(val,en)			{ if ( val == en ) pEvent->AddComment(L#en);			}
#define ADD_COMMENT_FILETIME(n,val)		{ pEvent->AddComment(std::wstring(n) + L"=" + FI(val)); }
#define ADD_COMMENT_FILESIZE(h,l)		{ pEvent->AddComment(std::wstring(L"size=") + FS(h,l)); }
#define ADD_HANDLE(h)					{ pEvent->SetContext((__int64)h);						}
#define ADD_COMMENT(a,b)				{ pEvent->AddComment(std::wstring(a) + L"=" + b );		}
#define ADD_STRINGVAL(a)				{ pEvent->AddComment(std::wstring(L#a) + L"=" + a );	}

//=========== END UTILITY CODE ======================================

//#define WIN10_ENABLE_LONG_PATH
#ifdef WIN10_ENABLE_LONG_PATH
//dirty but should be enough
#define DOKAN_MAX_PATH 32768
#else
#define DOKAN_MAX_PATH MAX_PATH
#endif // DEBUG

BOOL g_DebugMode;
BOOL g_HasSeSecurityPrivilege;
BOOL g_ImpersonateCallerUser;
CDokanyMirror* CDokanyMirror::m_pSingleton = NULL;

static WCHAR RootDirectory[DOKAN_MAX_PATH] = L"C:";
static WCHAR MountPoint[DOKAN_MAX_PATH] = L"M:\\";
static WCHAR UNCName[DOKAN_MAX_PATH] = L"";

__inline static DWORD AdditionalAttributeFlags( const DOKAN_FILE_INFO* fi )
{
	if (g_Mirror()->FileAttributeRecallOnDataAccessActive())
	{
		if (fi->IsDirectory)
		{
			return FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_COMPRESSED;
		}
		else
		{
			return FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_SPARSE_FILE | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_UNPINNED;
		}

	}
	return 0;
}

static void GetFilePath(PWCHAR filePath, ULONG numberOfElements, LPCWSTR FileName)
{
	wchar_t inPath[DOKAN_MAX_PATH];
	wcsncpy_s(inPath, FileName, DOKAN_MAX_PATH - 1);
	g_Mirror()->StripAdornment(inPath);

	wcsncpy_s(filePath, numberOfElements, RootDirectory, wcslen(RootDirectory));

	size_t unclen = wcslen(UNCName);
	if (unclen > 0 && _wcsnicmp(inPath, UNCName, unclen) == 0)
	{
		if (_wcsnicmp(inPath + unclen, L".", 1) != 0)
		{
			wcsncat_s(filePath, numberOfElements, inPath + unclen, wcslen(inPath) - unclen);
		}
	}
	else 
	{
		wcsncat_s(filePath, numberOfElements, inPath, wcslen(inPath));
	}
}

static BOOL AddSeSecurityNamePrivilege() {
	HANDLE token = 0;
	DWORD err;
	LUID luid;
	if (!LookupPrivilegeValue(0, SE_SECURITY_NAME, &luid)) {
		err = GetLastError();
		if (err != ERROR_SUCCESS) {
			return FALSE;
		}
	}

	LUID_AND_ATTRIBUTES attr;
	attr.Attributes = SE_PRIVILEGE_ENABLED;
	attr.Luid = luid;

	TOKEN_PRIVILEGES priv;
	priv.PrivilegeCount = 1;
	priv.Privileges[0] = attr;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
		err = GetLastError();
		if (err != ERROR_SUCCESS) {
			return FALSE;
		}
	}

	TOKEN_PRIVILEGES oldPriv;
	DWORD retSize;
	AdjustTokenPrivileges(token, FALSE, &priv, sizeof(TOKEN_PRIVILEGES), &oldPriv,
		&retSize);
	err = GetLastError();
	if (err != ERROR_SUCCESS) {
		CloseHandle(token);
		return FALSE;
	}

	BOOL privAlreadyPresent = FALSE;
	for (unsigned int i = 0; i < oldPriv.PrivilegeCount; i++) {
		if (oldPriv.Privileges[i].Luid.HighPart == luid.HighPart &&
			oldPriv.Privileges[i].Luid.LowPart == luid.LowPart) {
			privAlreadyPresent = TRUE;
			break;
		}
	}
	if (token)
		CloseHandle(token);
	return TRUE;
}


static NTSTATUS DOKAN_CALLBACK
MirrorCreateFile(LPCWSTR FileName, PDOKAN_IO_SECURITY_CONTEXT SecurityContext,
	ACCESS_MASK DesiredAccess, ULONG FileAttributes,
	ULONG ShareAccess, ULONG CreateDisposition,
	ULONG CreateOptions, PDOKAN_FILE_INFO DokanFileInfo) 
{
	DEFINE_EVENT( L"CreateFile", FileName, DokanFileInfo );

	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle;
	DWORD fileAttr;
	NTSTATUS status = STATUS_SUCCESS;
	DWORD creationDisposition;
	DWORD fileAttributesAndFlags;
	DWORD error = 0;
	SECURITY_ATTRIBUTES securityAttrib;
	ACCESS_MASK genericDesiredAccess;
	// userTokenHandle is for Impersonate Caller User Option
	HANDLE userTokenHandle = INVALID_HANDLE_VALUE;

	securityAttrib.nLength = sizeof(securityAttrib);
	securityAttrib.lpSecurityDescriptor =
		SecurityContext->AccessState.SecurityDescriptor;
	securityAttrib.bInheritHandle = FALSE;

	DokanMapKernelToUserCreateFileFlags(
		DesiredAccess, FileAttributes, CreateOptions, CreateDisposition,
		&genericDesiredAccess, &fileAttributesAndFlags, &creationDisposition);

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);



	/*
	if (ShareMode == 0 && AccessMode & FILE_WRITE_DATA)
			ShareMode = FILE_SHARE_WRITE;
	else if (ShareMode == 0)
			ShareMode = FILE_SHARE_READ;
	*/


	ADD_COMMENT_IF(creationDisposition, CREATE_NEW);
	ADD_COMMENT_IF(creationDisposition, OPEN_ALWAYS);
	ADD_COMMENT_IF(creationDisposition, CREATE_ALWAYS);
	ADD_COMMENT_IF(creationDisposition, OPEN_EXISTING);
	ADD_COMMENT_IF(creationDisposition, TRUNCATE_EXISTING);

	ADD_COMMENT_IF_FLAG(ShareAccess, FILE_SHARE_READ);
	ADD_COMMENT_IF_FLAG(ShareAccess, FILE_SHARE_WRITE);
	ADD_COMMENT_IF_FLAG(ShareAccess, FILE_SHARE_DELETE);

	ADD_COMMENT_IF_FLAG(DesiredAccess, GENERIC_READ);
	ADD_COMMENT_IF_FLAG(DesiredAccess, GENERIC_WRITE);
	ADD_COMMENT_IF_FLAG(DesiredAccess, GENERIC_EXECUTE);

	ADD_COMMENT_IF_FLAG(DesiredAccess, DELETE);
	ADD_COMMENT_IF_FLAG(DesiredAccess, FILE_READ_DATA);
	ADD_COMMENT_IF_FLAG(DesiredAccess, FILE_READ_ATTRIBUTES);
	ADD_COMMENT_IF_FLAG(DesiredAccess, FILE_READ_EA);
	ADD_COMMENT_IF_FLAG(DesiredAccess, READ_CONTROL);
	ADD_COMMENT_IF_FLAG(DesiredAccess, FILE_WRITE_DATA);
	ADD_COMMENT_IF_FLAG(DesiredAccess, FILE_WRITE_ATTRIBUTES);
	ADD_COMMENT_IF_FLAG(DesiredAccess, FILE_WRITE_EA);
	ADD_COMMENT_IF_FLAG(DesiredAccess, FILE_APPEND_DATA);
	ADD_COMMENT_IF_FLAG(DesiredAccess, WRITE_DAC);
	ADD_COMMENT_IF_FLAG(DesiredAccess, WRITE_OWNER);
	ADD_COMMENT_IF_FLAG(DesiredAccess, SYNCHRONIZE);
	ADD_COMMENT_IF_FLAG(DesiredAccess, FILE_EXECUTE);
	ADD_COMMENT_IF_FLAG(DesiredAccess, STANDARD_RIGHTS_READ);
	ADD_COMMENT_IF_FLAG(DesiredAccess, STANDARD_RIGHTS_WRITE);
	ADD_COMMENT_IF_FLAG(DesiredAccess, STANDARD_RIGHTS_EXECUTE);

	// When filePath is a directory, needs to change the flag so that the file can
	// be opened.
	fileAttr = GetFileAttributes(filePath);

	if (fileAttr != INVALID_FILE_ATTRIBUTES) 
	{
		if (fileAttr & FILE_ATTRIBUTE_DIRECTORY) 
		{
			if (!(CreateOptions & FILE_NON_DIRECTORY_FILE)) 
			{
				DokanFileInfo->IsDirectory = TRUE;
				// Needed by FindFirstFile to list files in it
				// TODO: use ReOpenFile in MirrorFindFiles to set share read temporary
				ShareAccess |= FILE_SHARE_READ;
			}
			else 
			{ // FILE_NON_DIRECTORY_FILE - Cannot open a dir as a file
				return STATUS_FILE_IS_A_DIRECTORY;
			}
		}
	}

	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_ATTRIBUTE_ARCHIVE);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_ATTRIBUTE_COMPRESSED);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_ATTRIBUTE_DEVICE);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_ATTRIBUTE_DIRECTORY);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_ATTRIBUTE_ENCRYPTED);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_ATTRIBUTE_HIDDEN);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_ATTRIBUTE_INTEGRITY_STREAM);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_ATTRIBUTE_NORMAL);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_ATTRIBUTE_NO_SCRUB_DATA);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_ATTRIBUTE_OFFLINE);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_ATTRIBUTE_READONLY);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_ATTRIBUTE_REPARSE_POINT);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_ATTRIBUTE_SPARSE_FILE);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_ATTRIBUTE_SYSTEM);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_ATTRIBUTE_TEMPORARY);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_ATTRIBUTE_VIRTUAL);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_FLAG_WRITE_THROUGH);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_FLAG_OVERLAPPED);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_FLAG_NO_BUFFERING);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_FLAG_RANDOM_ACCESS);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_FLAG_SEQUENTIAL_SCAN);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_FLAG_DELETE_ON_CLOSE);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_FLAG_BACKUP_SEMANTICS);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_FLAG_POSIX_SEMANTICS);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_FLAG_OPEN_REPARSE_POINT);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, FILE_FLAG_OPEN_NO_RECALL);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, SECURITY_ANONYMOUS);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, SECURITY_IDENTIFICATION);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, SECURITY_IMPERSONATION);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, SECURITY_DELEGATION);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, SECURITY_CONTEXT_TRACKING);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, SECURITY_EFFECTIVE_ONLY);
	ADD_COMMENT_IF_FLAG(fileAttributesAndFlags, SECURITY_SQOS_PRESENT);


	if (g_ImpersonateCallerUser) 
	{
		userTokenHandle = DokanOpenRequestorToken(DokanFileInfo);
	}

	if (DokanFileInfo->IsDirectory) 
	{
		// It is a create directory request

		if (creationDisposition == CREATE_NEW || creationDisposition == OPEN_ALWAYS) 
		{
			//We create folder
			if (!CreateDirectory(filePath, &securityAttrib)) 
			{
				error = GetLastError();
				// Fail to create folder for OPEN_ALWAYS is not an error
				if (error != ERROR_ALREADY_EXISTS || creationDisposition == CREATE_NEW) 
				{
					status = DokanNtStatusFromWin32(error);
				}
			}

			if (g_ImpersonateCallerUser) 
			{
				// Clean Up operation for impersonate
				RevertToSelf();
			}
		}

		if (status == STATUS_SUCCESS) 
		{
			//Check first if we're trying to open a file as a directory.
			if (fileAttr != INVALID_FILE_ATTRIBUTES &&
				!(fileAttr & FILE_ATTRIBUTE_DIRECTORY) &&
				(CreateOptions & FILE_DIRECTORY_FILE)) {
				return STATUS_NOT_A_DIRECTORY;
			}

			if (g_ImpersonateCallerUser) 
			{
				// if g_ImpersonateCallerUser option is on, call the ImpersonateLoggedOnUser function.
				if (!ImpersonateLoggedOnUser(userTokenHandle)) {
					// handle the error if failed to impersonate
				}
			}

			// FILE_FLAG_BACKUP_SEMANTICS is required for opening directory handles
			handle = CreateFile(filePath, genericDesiredAccess, ShareAccess,
					&securityAttrib, OPEN_EXISTING,
					fileAttributesAndFlags | FILE_FLAG_BACKUP_SEMANTICS, NULL);
			ADD_HANDLE(handle);

			if (g_ImpersonateCallerUser) 
			{
				// Clean Up operation for impersonate
				RevertToSelf();
			}

			if (handle == INVALID_HANDLE_VALUE) 
			{
				error = GetLastError();
				status = DokanNtStatusFromWin32(error);
			}
			else 
			{
				DokanFileInfo->Context = (ULONG64)handle; // save the file handle in Context
				ADD_HANDLE(handle);

				// Open succeed but we need to inform the driver
				// that the dir open and not created by returning STATUS_OBJECT_NAME_COLLISION
				if (creationDisposition == OPEN_ALWAYS && fileAttr != INVALID_FILE_ATTRIBUTES)
				{
					return STATUS_OBJECT_NAME_COLLISION;
				}
			}
		}
	}
	else 
	{
		// It is a create file request

		// Cannot overwrite a hidden or system file if flag not set
		if (fileAttr != INVALID_FILE_ATTRIBUTES &&
			((!(fileAttributesAndFlags & FILE_ATTRIBUTE_HIDDEN) &&
			(fileAttr & FILE_ATTRIBUTE_HIDDEN)) ||
				(!(fileAttributesAndFlags & FILE_ATTRIBUTE_SYSTEM) &&
				(fileAttr & FILE_ATTRIBUTE_SYSTEM))) &&
					(creationDisposition == TRUNCATE_EXISTING ||
						creationDisposition == CREATE_ALWAYS))
		{
			return STATUS_ACCESS_DENIED;
		}

		// Cannot delete a read only file
		if ((fileAttr != INVALID_FILE_ATTRIBUTES &&
			(fileAttr & FILE_ATTRIBUTE_READONLY) ||
			(fileAttributesAndFlags & FILE_ATTRIBUTE_READONLY)) &&
			(fileAttributesAndFlags & FILE_FLAG_DELETE_ON_CLOSE))
		{
			return STATUS_CANNOT_DELETE;
		}

		// Truncate should always be used with write access
		if (creationDisposition == TRUNCATE_EXISTING)
		{
			genericDesiredAccess |= GENERIC_WRITE;
		}

		if (g_ImpersonateCallerUser) 
		{
			// if g_ImpersonateCallerUser option is on, call the ImpersonateLoggedOnUser function.
			if (!ImpersonateLoggedOnUser(userTokenHandle)) 
			{
				// handle the error if failed to impersonate
			}
		}

		handle = CreateFile(
			filePath,
			genericDesiredAccess, // GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE,
			ShareAccess,
			&securityAttrib, // security attribute
			creationDisposition,
			fileAttributesAndFlags, // |FILE_FLAG_NO_BUFFERING,
			NULL);                  // template file handle

		ADD_HANDLE(handle);
		if (g_ImpersonateCallerUser) 
		{
			// Clean Up operation for impersonate
			RevertToSelf();
		}

		if (handle == INVALID_HANDLE_VALUE) 
		{
			error = GetLastError();
			status = DokanNtStatusFromWin32(error);
		}
		else 
		{
			//Need to update FileAttributes with previous when Overwrite file
			if (fileAttr != INVALID_FILE_ATTRIBUTES &&
				creationDisposition == TRUNCATE_EXISTING) {
				SetFileAttributes(filePath, fileAttributesAndFlags | fileAttr);
			}

			DokanFileInfo->Context = (ULONG64)handle; // save the file handle in Context
			ADD_HANDLE(handle);

			if (creationDisposition == OPEN_ALWAYS ||
				creationDisposition == CREATE_ALWAYS) {
				error = GetLastError();
				if (error == ERROR_ALREADY_EXISTS) 
{
					// Open succeed but we need to inform the driver
					// that the file open and not created by returning STATUS_OBJECT_NAME_COLLISION
					status = STATUS_OBJECT_NAME_COLLISION;
				}
			}
		}
	}

	return status;
}

#pragma warning(push)
#pragma warning(disable : 4305)

static void DOKAN_CALLBACK MirrorCloseFile(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo) 
{
	DEFINE_EVENT(L"CloseFile", FileName, DokanFileInfo);

	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	if (DokanFileInfo->Context) 
	{
		CloseHandle((HANDLE)DokanFileInfo->Context);
		DokanFileInfo->Context = 0;
	}
}

static void DOKAN_CALLBACK MirrorCleanup(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo) 
{
	DEFINE_EVENT(L"CleanupFile", FileName, DokanFileInfo);

	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	if (DokanFileInfo->Context) 
	{
		try 
		{
			CloseHandle((HANDLE)(DokanFileInfo->Context));
		}
		catch (...) {}
		DokanFileInfo->Context = 0;
	}

	if (DokanFileInfo->DeleteOnClose) 
	{
		// Should already be deleted by CloseHandle
		// if open with FILE_FLAG_DELETE_ON_CLOSE
		if (!DokanFileInfo->IsDirectory) 
		{
			DeleteFile(filePath);
		}
	}
}

static NTSTATUS DOKAN_CALLBACK MirrorReadFile(LPCWSTR FileName, LPVOID Buffer,
	DWORD BufferLength,
	LPDWORD ReadLength,
	LONGLONG Offset,
	PDOKAN_FILE_INFO DokanFileInfo) 
{
	DEFINE_EVENT(L"ReadFile", FileName, DokanFileInfo);
	ADD_QI(BufferLength);
	ADD_QI(Offset)

	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle = (HANDLE)DokanFileInfo->Context;
	ULONG offset = (ULONG)Offset;
	BOOL opened = FALSE;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	if (!handle || handle == INVALID_HANDLE_VALUE) 
	{
		handle = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (handle == INVALID_HANDLE_VALUE) 
		{
			DWORD error = GetLastError();
			return DokanNtStatusFromWin32(error);
		}
		opened = TRUE;
		pEvent->AddComment(L"REOPEN");
	}

	LARGE_INTEGER distanceToMove;
	distanceToMove.QuadPart = Offset;
	if (!SetFilePointerEx(handle, distanceToMove, NULL, FILE_BEGIN)) {
		DWORD error = GetLastError();
		if (opened)
		{
			CloseHandle(handle);
		}
		return DokanNtStatusFromWin32(error);
	}


	if (!ReadFile(handle, Buffer, BufferLength, ReadLength, NULL)) 
	{
		DWORD error = GetLastError();
		if (opened)
		{
			CloseHandle(handle);
		}
		return DokanNtStatusFromWin32(error);

	}
	else 
	{
		ADD_QI(*ReadLength)
	}

	if (opened)
	{
		CloseHandle(handle);
	}

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorWriteFile(LPCWSTR FileName, LPCVOID Buffer,
	DWORD NumberOfBytesToWrite,
	LPDWORD NumberOfBytesWritten,
	LONGLONG Offset,
	PDOKAN_FILE_INFO DokanFileInfo) 
{
	DEFINE_EVENT(L"WriteFile", FileName, DokanFileInfo);
	ADD_QI(NumberOfBytesToWrite);
	ADD_QI(Offset);

	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle = (HANDLE)DokanFileInfo->Context;
	BOOL opened = FALSE;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	// reopen the file
	if (!handle || handle == INVALID_HANDLE_VALUE) 
	{
		handle = CreateFile(filePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (handle == INVALID_HANDLE_VALUE) 
		{
			DWORD error = GetLastError();
			return DokanNtStatusFromWin32(error);
		}
		opened = TRUE;
	}

	UINT64 fileSize = 0;
	DWORD fileSizeLow = 0;
	DWORD fileSizeHigh = 0;
	fileSizeLow = GetFileSize(handle, &fileSizeHigh);
	if (fileSizeLow == INVALID_FILE_SIZE)
	{
		DWORD error = GetLastError();
		if (opened)
		{
			CloseHandle(handle);
		}
		return DokanNtStatusFromWin32(error);
	}

	fileSize = ((UINT64)fileSizeHigh << 32) | fileSizeLow;

	LARGE_INTEGER distanceToMove;
	if (DokanFileInfo->WriteToEndOfFile) 
	{
		LARGE_INTEGER z;
		z.QuadPart = 0;
		if (!SetFilePointerEx(handle, z, NULL, FILE_END)) 
		{
			DWORD error = GetLastError();
			if (opened)
			{
				CloseHandle(handle);
			}
			return DokanNtStatusFromWin32(error);
		}
	}
	else 
	{
		// Paging IO cannot write after allocate file size.
		if (DokanFileInfo->PagingIo) 
		{
			if ((UINT64)Offset >= fileSize) 
			{
				*NumberOfBytesWritten = 0;
				if (opened)
				{
					CloseHandle(handle);
				}
				return STATUS_SUCCESS;
			}

			if (((UINT64)Offset + NumberOfBytesToWrite) > fileSize) 
			{
				UINT64 bytes = fileSize - Offset;
				if (bytes >> 32) 
				{
					NumberOfBytesToWrite = (DWORD)(bytes & 0xFFFFFFFFUL);
				}
				else 
				{
					NumberOfBytesToWrite = (DWORD)bytes;
				}
			}
		}

		if ((UINT64)Offset > fileSize) 
		{
			// In the mirror sample helperZeroFileData is not necessary. NTFS will
			// zero a hole.
			// But if user's file system is different from NTFS( or other Windows's
			// file systems ) then  users will have to zero the hole themselves.
		}

		distanceToMove.QuadPart = Offset;
		if (!SetFilePointerEx(handle, distanceToMove, NULL, FILE_BEGIN)) 
		{
			DWORD error = GetLastError();
			if (opened)
			{
				CloseHandle(handle);
			}
			return DokanNtStatusFromWin32(error);
		}
	}

	if (!WriteFile(handle, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten, NULL)) 
	{
		DWORD error = GetLastError();
		if (opened)
		{
			CloseHandle(handle);
		}
		return DokanNtStatusFromWin32(error);

	}
	else
	{
		ADD_QI(*NumberOfBytesWritten);
	}

	// close the file when it is reopened
	if (opened)
	{
		CloseHandle(handle);
	}

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
MirrorFlushFileBuffers(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo) 
{
	DEFINE_EVENT(L"FlushFileBuffers", FileName, DokanFileInfo);

	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle = (HANDLE)DokanFileInfo->Context;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		return STATUS_SUCCESS;
	}

	if (FlushFileBuffers(handle)) {
		return STATUS_SUCCESS;
	}
	else {
		DWORD error = GetLastError();
		return DokanNtStatusFromWin32(error);
	}
}

static NTSTATUS DOKAN_CALLBACK MirrorGetFileInformation(
	LPCWSTR FileName, LPBY_HANDLE_FILE_INFORMATION HandleFileInformation,
	PDOKAN_FILE_INFO DokanFileInfo) 
{
	DEFINE_EVENT(L"GetFileInformation", FileName, DokanFileInfo);

	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle = (HANDLE)DokanFileInfo->Context;
	BOOL opened = FALSE;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		handle = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
			OPEN_EXISTING, 0, NULL);
		if (handle == INVALID_HANDLE_VALUE) {
			DWORD error = GetLastError();
			return DokanNtStatusFromWin32(error);
		}
		opened = TRUE;
	}

	if (!GetFileInformationByHandle(handle, HandleFileInformation)) {

		// FileName is a root directory
		// in this case, FindFirstFile can't get directory information
		if (wcslen(FileName) == 1) 
		{
			HandleFileInformation->dwFileAttributes = (GetFileAttributes(filePath) | AdditionalAttributeFlags(DokanFileInfo));
		}
		else {
			WIN32_FIND_DATAW find;
			ZeroMemory(&find, sizeof(WIN32_FIND_DATAW));
			HANDLE findHandle = FindFirstFile(filePath, &find);
			if (findHandle == INVALID_HANDLE_VALUE) {
				DWORD error = GetLastError();
				if (opened)
					CloseHandle(handle);
				return DokanNtStatusFromWin32(error);
			}
			HandleFileInformation->dwFileAttributes = (find.dwFileAttributes | AdditionalAttributeFlags(DokanFileInfo));
			HandleFileInformation->ftCreationTime = find.ftCreationTime;
			HandleFileInformation->ftLastAccessTime = find.ftLastAccessTime;
			HandleFileInformation->ftLastWriteTime = find.ftLastWriteTime;
			HandleFileInformation->nFileSizeHigh = find.nFileSizeHigh;
			HandleFileInformation->nFileSizeLow = find.nFileSizeLow;

			FindClose(findHandle);
		}
	}

	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_PINNED);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_UNPINNED);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_RECALL_ON_OPEN);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_ARCHIVE);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_COMPRESSED);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_DEVICE);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_DIRECTORY);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_EA);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_ENCRYPTED);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_HIDDEN);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_INTEGRITY_STREAM);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_NORMAL);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_NO_SCRUB_DATA);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_OFFLINE);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_READONLY);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_REPARSE_POINT);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_SPARSE_FILE);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_SYSTEM);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_TEMPORARY);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_VIRTUAL);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_FLAG_WRITE_THROUGH);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_FLAG_OVERLAPPED);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_FLAG_NO_BUFFERING);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_FLAG_RANDOM_ACCESS);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_FLAG_SEQUENTIAL_SCAN);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_FLAG_DELETE_ON_CLOSE);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_FLAG_BACKUP_SEMANTICS);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_FLAG_POSIX_SEMANTICS);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_FLAG_OPEN_REPARSE_POINT);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_FLAG_OPEN_NO_RECALL);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, SECURITY_ANONYMOUS);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, SECURITY_IDENTIFICATION);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, SECURITY_IMPERSONATION);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, SECURITY_DELEGATION);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, SECURITY_CONTEXT_TRACKING);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, SECURITY_EFFECTIVE_ONLY);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, SECURITY_SQOS_PRESENT);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, FILE_ATTRIBUTE_STRICTLY_SEQUENTIAL);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, TREE_CONNECT_ATTRIBUTE_GLOBAL);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, TREE_CONNECT_ATTRIBUTE_INTEGRITY);
	ADD_COMMENT_IF_FLAG(HandleFileInformation->dwFileAttributes, TREE_CONNECT_ATTRIBUTE_PRIVACY);

#define TREE_CONNECT_ATTRIBUTE_PRIVACY      0x00004000  
#define TREE_CONNECT_ATTRIBUTE_INTEGRITY    0x00008000  
#define TREE_CONNECT_ATTRIBUTE_GLOBAL       0x00000004  
#define FILE_ATTRIBUTE_STRICTLY_SEQUENTIAL  0x20000000  

	ADD_COMMENT_FILETIME(L"create", HandleFileInformation->ftCreationTime);
	ADD_COMMENT_FILETIME(L"lastAccess", HandleFileInformation->ftLastAccessTime);
	ADD_COMMENT_FILETIME(L"ftLastWriteTime", HandleFileInformation->ftLastWriteTime);
	ADD_COMMENT_FILESIZE(HandleFileInformation->nFileSizeHigh, HandleFileInformation->nFileSizeLow);



	if (opened)
		CloseHandle(handle);

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
MirrorFindFiles(LPCWSTR FileName,
	PFillFindData FillFindData, // function pointer
	PDOKAN_FILE_INFO DokanFileInfo) 
{
	DEFINE_EVENT(L"FindFiles", FileName, DokanFileInfo);

	WCHAR filePath[DOKAN_MAX_PATH];
	size_t fileLen;
	HANDLE hFind;
	WIN32_FIND_DATAW findData;
	DWORD error;
	int count = 0;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	fileLen = wcslen(filePath);
	if (filePath[fileLen - 1] != L'\\') {
		filePath[fileLen++] = L'\\';
	}
	filePath[fileLen] = L'*';
	filePath[fileLen + 1] = L'\0';

	hFind = FindFirstFile(filePath, &findData);

	if (hFind == INVALID_HANDLE_VALUE) {
		error = GetLastError();
		return DokanNtStatusFromWin32(error);
	}

	// Root folder does not have . and .. folder - we remove them
	BOOLEAN rootFolder = (wcscmp(FileName, L"\\") == 0);
	do {
		if (!rootFolder || (wcscmp(findData.cFileName, L".") != 0 && wcscmp(findData.cFileName, L"..") != 0))
		{
			g_Mirror()->AdornFilename(findData.cFileName);
			g_Mirror()->AdornFilename(findData.cAlternateFileName);
			findData.dwFileAttributes |= AdditionalAttributeFlags(DokanFileInfo);

			FillFindData(&findData, DokanFileInfo);

		}
		count++;
	} while (FindNextFile(hFind, &findData) != 0);

	error = GetLastError();
	FindClose(hFind);

	if (error != ERROR_NO_MORE_FILES) {
		return DokanNtStatusFromWin32(error);
	}
	ADD_QI(count);

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
MirrorDeleteFile(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo) 
{
	DEFINE_EVENT(L"DeleteFile", FileName, DokanFileInfo);

	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle = (HANDLE)DokanFileInfo->Context;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);
	DWORD dwAttrib = GetFileAttributes(filePath);

	if (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		(dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
	{
		return STATUS_ACCESS_DENIED;
	}

	if (handle && handle != INVALID_HANDLE_VALUE) 
	{
		FILE_DISPOSITION_INFO fdi;
		fdi.DeleteFile = DokanFileInfo->DeleteOnClose;
		if (!SetFileInformationByHandle(handle, FileDispositionInfo, &fdi,
			sizeof(FILE_DISPOSITION_INFO)))
		{
			return DokanNtStatusFromWin32(GetLastError());
		}
	}

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
MirrorDeleteDirectory(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo) 
{
	DEFINE_EVENT(L"DeleteDirectory", FileName, DokanFileInfo);

	WCHAR filePath[DOKAN_MAX_PATH];
	// HANDLE	handle = (HANDLE)DokanFileInfo->Context;
	HANDLE hFind;
	WIN32_FIND_DATAW findData;
	size_t fileLen;

	ZeroMemory(filePath, sizeof(filePath));
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	if (!DokanFileInfo->DeleteOnClose)
	{
		//Dokan notify that the file is requested not to be deleted.
		return STATUS_SUCCESS;
	}

	fileLen = wcslen(filePath);
	if (filePath[fileLen - 1] != L'\\') 
	{
		filePath[fileLen++] = L'\\';
	}
	filePath[fileLen] = L'*';
	filePath[fileLen + 1] = L'\0';

	hFind = FindFirstFile(filePath, &findData);

	if (hFind == INVALID_HANDLE_VALUE) 
	{
		DWORD error = GetLastError();
		return DokanNtStatusFromWin32(error);
	}

	do 
	{
		if (wcscmp(findData.cFileName, L"..") != 0 &&
			wcscmp(findData.cFileName, L".") != 0) 
		{
			FindClose(hFind);
			return STATUS_DIRECTORY_NOT_EMPTY;
		}
	} while (FindNextFile(hFind, &findData) != 0);

	DWORD error = GetLastError();
	FindClose(hFind);

	if (error != ERROR_NO_MORE_FILES) 
	{
		return DokanNtStatusFromWin32(error);
	}

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
MirrorMoveFile(LPCWSTR FileName, // existing file name
	LPCWSTR NewFileName, BOOL ReplaceIfExisting,
	PDOKAN_FILE_INFO DokanFileInfo) 
{
	DEFINE_EVENT(L"MoveFile", FileName, DokanFileInfo);
	ADD_STRINGVAL( NewFileName );
	ADD_COMMENT( L"ReplaceIfExisting",  (ReplaceIfExisting ? L"T" : L"F"));

	WCHAR filePath[DOKAN_MAX_PATH];
	WCHAR newFilePath[DOKAN_MAX_PATH];
	HANDLE handle;
	DWORD bufferSize;
	BOOL result;
	size_t newFilePathLen;

	PFILE_RENAME_INFO renameInfo = NULL;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);
	GetFilePath(newFilePath, DOKAN_MAX_PATH, NewFileName);

	handle = (HANDLE)DokanFileInfo->Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) 
	{
		return STATUS_INVALID_HANDLE;
	}
	ADD_HANDLE(handle);

	newFilePathLen = wcslen(newFilePath);

	// the PFILE_RENAME_INFO struct has space for one WCHAR for the name at
	// the end, so that
	// accounts for the null terminator

	bufferSize = (DWORD)(sizeof(FILE_RENAME_INFO) +
		newFilePathLen * sizeof(newFilePath[0]));

	renameInfo = (PFILE_RENAME_INFO)malloc(bufferSize);
	if (!renameInfo) {
		return STATUS_BUFFER_OVERFLOW;
	}
	ZeroMemory(renameInfo, bufferSize);

	renameInfo->ReplaceIfExists =
		ReplaceIfExisting
		? TRUE
		: FALSE; // some warning about converting BOOL to BOOLEAN
	renameInfo->RootDirectory = NULL; // hope it is never needed, shouldn't be
	renameInfo->FileNameLength =
		(DWORD)newFilePathLen *
		sizeof(newFilePath[0]); // they want length in bytes

	wcscpy_s(renameInfo->FileName, newFilePathLen + 1, newFilePath);

	result = SetFileInformationByHandle(handle, FileRenameInfo, renameInfo,
		bufferSize);

	free(renameInfo);

	if (result) {
		return STATUS_SUCCESS;
	}
	else {
		DWORD error = GetLastError();
		return DokanNtStatusFromWin32(error);
	}
}

static NTSTATUS DOKAN_CALLBACK MirrorLockFile(LPCWSTR FileName,
	LONGLONG ByteOffset,
	LONGLONG Length,
	PDOKAN_FILE_INFO DokanFileInfo) 
{
	DEFINE_EVENT(L"LockFile", FileName, DokanFileInfo);
	ADD_QI(ByteOffset);
	ADD_QI(Length);

	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle;
	LARGE_INTEGER offset;
	LARGE_INTEGER length;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	handle = (HANDLE)DokanFileInfo->Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		return STATUS_INVALID_HANDLE;
	}
	ADD_HANDLE(handle);

	length.QuadPart = Length;
	offset.QuadPart = ByteOffset;

	if (!LockFile(handle, offset.LowPart, offset.HighPart, length.LowPart,
		length.HighPart)) {
		DWORD error = GetLastError();
		return DokanNtStatusFromWin32(error);
	}

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorSetEndOfFile(
	LPCWSTR FileName, LONGLONG ByteOffset, PDOKAN_FILE_INFO DokanFileInfo) {

	DEFINE_EVENT(L"SetEndOfFile", FileName, DokanFileInfo);
	ADD_QI(ByteOffset);

	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle;
	LARGE_INTEGER offset;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);


	handle = (HANDLE)DokanFileInfo->Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		return STATUS_INVALID_HANDLE;
	}
	ADD_HANDLE(handle);

	offset.QuadPart = ByteOffset;
	if (!SetFilePointerEx(handle, offset, NULL, FILE_BEGIN)) {
		DWORD error = GetLastError();
		return DokanNtStatusFromWin32(error);
	}

	if (!SetEndOfFile(handle)) {
		DWORD error = GetLastError();
		return DokanNtStatusFromWin32(error);
	}

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorSetAllocationSize(
	LPCWSTR FileName, LONGLONG AllocSize, PDOKAN_FILE_INFO DokanFileInfo) 
{
	DEFINE_EVENT(L"SetAllocationSize", FileName, DokanFileInfo);
	ADD_QI(AllocSize);

	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle;
	LARGE_INTEGER fileSize;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	handle = (HANDLE)DokanFileInfo->Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) 
	{
		return STATUS_INVALID_HANDLE;
	}
	ADD_HANDLE(handle);

	if (GetFileSizeEx(handle, &fileSize)) 
	{
		if (AllocSize < fileSize.QuadPart) 
		{
			fileSize.QuadPart = AllocSize;
			if (!SetFilePointerEx(handle, fileSize, NULL, FILE_BEGIN)) 
			{
				DWORD error = GetLastError();
				return DokanNtStatusFromWin32(error);
			}
			if (!SetEndOfFile(handle)) 
			{
				DWORD error = GetLastError();
				return DokanNtStatusFromWin32(error);
			}
		}
	}
	else {
		DWORD error = GetLastError();
		return DokanNtStatusFromWin32(error);
	}
	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorSetFileAttributes(
	LPCWSTR FileName, DWORD FileAttributes, PDOKAN_FILE_INFO DokanFileInfo) 
{
	UNREFERENCED_PARAMETER(DokanFileInfo);

	DEFINE_EVENT(L"SetFileAttributes", FileName, DokanFileInfo);
	ADD_QI(FileAttributes);

	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);


	if (FileAttributes != 0) {
		if (!SetFileAttributes(filePath, FileAttributes)) {
			DWORD error = GetLastError();
			return DokanNtStatusFromWin32(error);
		}
	}
	else {
		// case FileAttributes == 0 :
		// MS-FSCC 2.6 File Attributes : There is no file attribute with the value 0x00000000
		// because a value of 0x00000000 in the FileAttributes field means that the file attributes for this file MUST NOT be changed when setting basic information for the file
	}

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
MirrorSetFileTime(LPCWSTR FileName, CONST FILETIME *CreationTime,
	CONST FILETIME *LastAccessTime, CONST FILETIME *LastWriteTime,
	PDOKAN_FILE_INFO DokanFileInfo) 
{
	DEFINE_EVENT(L"SetFileTime", FileName, DokanFileInfo);
	ADD_COMMENT_FILETIME(L"create", *CreationTime);
	ADD_COMMENT_FILETIME(L"access", *LastAccessTime);
	ADD_COMMENT_FILETIME(L"write", *LastWriteTime);


	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	handle = (HANDLE)DokanFileInfo->Context;
	ADD_HANDLE(handle);

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		return STATUS_INVALID_HANDLE;
	}

	if (!SetFileTime(handle, CreationTime, LastAccessTime, LastWriteTime)) {
		DWORD error = GetLastError();
		return DokanNtStatusFromWin32(error);
	}

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
MirrorUnlockFile(LPCWSTR FileName, LONGLONG ByteOffset, LONGLONG Length,
	PDOKAN_FILE_INFO DokanFileInfo) 
{
	DEFINE_EVENT(L"UnlockFile", FileName, DokanFileInfo);
	ADD_QI(ByteOffset);
	ADD_QI(Length);

	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle;
	LARGE_INTEGER length;
	LARGE_INTEGER offset;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	handle = (HANDLE)DokanFileInfo->Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		return STATUS_INVALID_HANDLE;
	}
	ADD_HANDLE(handle);

	length.QuadPart = Length;
	offset.QuadPart = ByteOffset;

	if (!UnlockFile(handle, offset.LowPart, offset.HighPart, length.LowPart,
		length.HighPart)) {
		DWORD error = GetLastError();
		return DokanNtStatusFromWin32(error);
	}

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorGetFileSecurity(
	LPCWSTR FileName, PSECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG BufferLength,
	PULONG LengthNeeded, PDOKAN_FILE_INFO DokanFileInfo) 
{
	DEFINE_EVENT(L"GetFileSecurity", FileName, DokanFileInfo);

	WCHAR filePath[DOKAN_MAX_PATH];
	BOOLEAN requestingSaclInfo;

	UNREFERENCED_PARAMETER(DokanFileInfo);

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	ADD_COMMENT_IF_FLAG(*SecurityInformation, FILE_SHARE_READ);
	ADD_COMMENT_IF_FLAG(*SecurityInformation, OWNER_SECURITY_INFORMATION);
	ADD_COMMENT_IF_FLAG(*SecurityInformation, GROUP_SECURITY_INFORMATION);
	ADD_COMMENT_IF_FLAG(*SecurityInformation, DACL_SECURITY_INFORMATION);
	ADD_COMMENT_IF_FLAG(*SecurityInformation, SACL_SECURITY_INFORMATION);
	ADD_COMMENT_IF_FLAG(*SecurityInformation, LABEL_SECURITY_INFORMATION);
	ADD_COMMENT_IF_FLAG(*SecurityInformation, ATTRIBUTE_SECURITY_INFORMATION);
	ADD_COMMENT_IF_FLAG(*SecurityInformation, SCOPE_SECURITY_INFORMATION);
	ADD_COMMENT_IF_FLAG(*SecurityInformation, PROCESS_TRUST_LABEL_SECURITY_INFORMATION);
	ADD_COMMENT_IF_FLAG(*SecurityInformation, BACKUP_SECURITY_INFORMATION);
	ADD_COMMENT_IF_FLAG(*SecurityInformation, PROTECTED_DACL_SECURITY_INFORMATION);
	ADD_COMMENT_IF_FLAG(*SecurityInformation, PROTECTED_SACL_SECURITY_INFORMATION);
	ADD_COMMENT_IF_FLAG(*SecurityInformation, UNPROTECTED_DACL_SECURITY_INFORMATION);
	ADD_COMMENT_IF_FLAG(*SecurityInformation, UNPROTECTED_SACL_SECURITY_INFORMATION);

	requestingSaclInfo = ((*SecurityInformation & SACL_SECURITY_INFORMATION) ||
		(*SecurityInformation & BACKUP_SECURITY_INFORMATION));

	if (!g_HasSeSecurityPrivilege) {
		*SecurityInformation &= ~SACL_SECURITY_INFORMATION;
		*SecurityInformation &= ~BACKUP_SECURITY_INFORMATION;
	}

	HANDLE handle = CreateFile(
		filePath,
		READ_CONTROL | ((requestingSaclInfo && g_HasSeSecurityPrivilege)
			? ACCESS_SYSTEM_SECURITY
			: 0),
		FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE,
		NULL, // security attribute
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS, // |FILE_FLAG_NO_BUFFERING,
		NULL);

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		int error = GetLastError();
		return DokanNtStatusFromWin32(error);
	}

	if (!GetUserObjectSecurity(handle, SecurityInformation, SecurityDescriptor,
		BufferLength, LengthNeeded)) {
		int error = GetLastError();
		if (error == ERROR_INSUFFICIENT_BUFFER) {
			CloseHandle(handle);
			return STATUS_BUFFER_OVERFLOW;
		}
		else {
			CloseHandle(handle);
			return DokanNtStatusFromWin32(error);
		}
	}

	// Ensure the Security Descriptor Length is set
	DWORD securityDescriptorLength =
		GetSecurityDescriptorLength(SecurityDescriptor);
	*LengthNeeded = securityDescriptorLength;

	CloseHandle(handle);

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorSetFileSecurity(
	LPCWSTR FileName, PSECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG SecurityDescriptorLength,
	PDOKAN_FILE_INFO DokanFileInfo) 
{
	DEFINE_EVENT(L"SetFileSecurity", FileName, DokanFileInfo);

	HANDLE handle;
	WCHAR filePath[DOKAN_MAX_PATH];

	UNREFERENCED_PARAMETER(SecurityDescriptorLength);

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	handle = (HANDLE)DokanFileInfo->Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		return STATUS_INVALID_HANDLE;
	}

	if (!SetUserObjectSecurity(handle, SecurityInformation, SecurityDescriptor)) {
		int error = GetLastError();
		return DokanNtStatusFromWin32(error);
	}
	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorGetVolumeInformation(
	LPWSTR VolumeNameBuffer, DWORD VolumeNameSize, LPDWORD VolumeSerialNumber,
	LPDWORD MaximumComponentLength, LPDWORD FileSystemFlags,
	LPWSTR FileSystemNameBuffer, DWORD FileSystemNameSize,
	PDOKAN_FILE_INFO DokanFileInfo) {
	UNREFERENCED_PARAMETER(DokanFileInfo);

	DEFINE_EVENT(L"GetVolumeInformation", L"", DokanFileInfo);

	WCHAR volumeRoot[4];
	DWORD fsFlags = 0;

	wcscpy_s(VolumeNameBuffer, VolumeNameSize, L"DOKAN");

	if (VolumeSerialNumber)
		*VolumeSerialNumber = 0x19831116;
	if (MaximumComponentLength)
		*MaximumComponentLength = 255;
	if (FileSystemFlags)
		*FileSystemFlags = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES |
		FILE_SUPPORTS_REMOTE_STORAGE | FILE_UNICODE_ON_DISK |
		FILE_PERSISTENT_ACLS | FILE_NAMED_STREAMS;

	volumeRoot[0] = RootDirectory[0];
	volumeRoot[1] = ':';
	volumeRoot[2] = '\\';
	volumeRoot[3] = '\0';

	if (GetVolumeInformation(volumeRoot, NULL, 0, NULL, MaximumComponentLength,
		&fsFlags, FileSystemNameBuffer,
		FileSystemNameSize)) {

		if (FileSystemFlags)
			*FileSystemFlags &= fsFlags;

	}
	else {
		// File system name could be anything up to 10 characters.
		// But Windows check few feature availability based on file system name.
		// For this, it is recommended to set NTFS or FAT here.
		wcscpy_s(FileSystemNameBuffer, FileSystemNameSize, L"NTFS");
	}

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorDokanGetDiskFreeSpace(
	PULONGLONG pFreeBytesAvailable, PULONGLONG pTotalNumberOfBytes,
	PULONGLONG pTotalNumberOfFreeBytes, PDOKAN_FILE_INFO DokanFileInfo)
{
	UNREFERENCED_PARAMETER(DokanFileInfo);
	DEFINE_EVENT(L"GetDiskFreeSpace", L"", DokanFileInfo);

	ULARGE_INTEGER FreeBytesAvailable;		FreeBytesAvailable.QuadPart = 0;
	ULARGE_INTEGER TotalNumberOfBytes;		TotalNumberOfBytes.QuadPart = 0;
	ULARGE_INTEGER TotalNumberOfFreeBytes;	TotalNumberOfFreeBytes.QuadPart = 0;
	BOOL r = ::GetDiskFreeSpaceEx(RootDirectory, (PULARGE_INTEGER)&FreeBytesAvailable, (PULARGE_INTEGER)&TotalNumberOfBytes, (PULARGE_INTEGER)&TotalNumberOfFreeBytes);

	*pFreeBytesAvailable = FreeBytesAvailable.QuadPart;
	*pTotalNumberOfBytes = TotalNumberOfBytes.QuadPart;
	*pTotalNumberOfFreeBytes = TotalNumberOfFreeBytes.QuadPart;

	//  ADD_RETURN(r);
	ADD_QI(*pFreeBytesAvailable);
	ADD_QI(*pTotalNumberOfBytes);
	ADD_QI(*pTotalNumberOfFreeBytes);

	return STATUS_SUCCESS;
}

/**
 * Avoid #include <winternl.h> which as conflict with FILE_INFORMATION_CLASS
 * definition.
 * This only for MirrorFindStreams. Link with ntdll.lib still required.
 *
 * Not needed if you're not using NtQueryInformationFile!
 *
 * BEGIN
 */
#pragma warning(push)
#pragma warning(disable : 4201)
typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	} DUMMYUNIONNAME;

	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
#pragma warning(pop)

NTSYSCALLAPI NTSTATUS NTAPI NtQueryInformationFile(
	_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length,
	_In_ FILE_INFORMATION_CLASS FileInformationClass);
/**
 * END
 */

NTSTATUS DOKAN_CALLBACK
MirrorFindStreams(LPCWSTR FileName, PFillFindStreamData FillFindStreamData,
	PDOKAN_FILE_INFO DokanFileInfo) 
{
	DEFINE_EVENT(L"FindStreams", FileName, DokanFileInfo);

	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE hFind;
	WIN32_FIND_STREAM_DATA findData;
	DWORD error;
	int count = 0;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	hFind = FindFirstStreamW(filePath, FindStreamInfoStandard, &findData, 0);

	if (hFind == INVALID_HANDLE_VALUE) {
		error = GetLastError();
		return DokanNtStatusFromWin32(error);
	}

	FillFindStreamData(&findData, DokanFileInfo);
	count++;

	while (FindNextStreamW(hFind, &findData) != 0) 
	{
		FillFindStreamData(&findData, DokanFileInfo);
		count++;
	}

	error = GetLastError();
	FindClose(hFind);

	if (error != ERROR_HANDLE_EOF) {
		return DokanNtStatusFromWin32(error);
	}

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorMounted(PDOKAN_FILE_INFO DokanFileInfo) 
{
	UNREFERENCED_PARAMETER(DokanFileInfo);
	DEFINE_EVENT(L"Mounted", L"", DokanFileInfo);

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorUnmounted(PDOKAN_FILE_INFO DokanFileInfo) 
{
	UNREFERENCED_PARAMETER(DokanFileInfo);
	DEFINE_EVENT(L"Unmounted", L"", DokanFileInfo);

	return STATUS_SUCCESS;
}
//=========================================================================================================

#pragma warning(pop)

BOOL WINAPI CtrlHandler(DWORD dwCtrlType) 
{
	switch (dwCtrlType) 
	{
		case CTRL_C_EVENT:
		case CTRL_BREAK_EVENT:
		case CTRL_CLOSE_EVENT:
		case CTRL_LOGOFF_EVENT:
		case CTRL_SHUTDOWN_EVENT:
			g_Queue()->Disable();
			SetConsoleCtrlHandler(CtrlHandler, FALSE);
			DokanRemoveMountPoint(MountPoint);
			return TRUE;
		default:
			return FALSE;
	}
}

/*
void ShowUsage() {
	// clang-format off
	fprintf(stderr, "mirror.exe\n"
		"  /r RootDirectory (ex. /r c:\\test)\t\t Directory source to mirror.\n"
		"  /l MountPoint (ex. /l m)\t\t\t Mount point. Can be M:\\ (drive letter) or empty NTFS folder C:\\mount\\dokan .\n"
		"  /t ThreadCount (ex. /t 5)\t\t\t Number of threads to be used internally by Dokan library.\n\t\t\t\t\t\t More threads will handle more event at the same time.\n"
		"  /d (enable debug output)\t\t\t Enable debug output to an attached debugger.\n"
		"  /s (use stderr for output)\t\t\t Enable debug output to stderr.\n"
		"  /n (use network drive)\t\t\t Show device as network device.\n"
		"  /m (use removable drive)\t\t\t Show device as removable media.\n"
		"  /w (write-protect drive)\t\t\t Read only filesystem.\n"
		"  /o (use mount manager)\t\t\t Register device to Windows mount manager.\n\t\t\t\t\t\t This enables advanced Windows features like recycle bin and more...\n"
		"  /c (mount for current session only)\t\t Device only visible for current user session.\n"
		"  /u (UNC provider name ex. \\localhost\\myfs)\t UNC name used for network volume.\n"
		"  /p (Impersonate Caller User)\t\t\t Impersonate Caller User when getting the handle in CreateFile for operations.\n\t\t\t\t\t\t This option requires administrator right to work properly.\n"
		"  /a Allocation unit size (ex. /a 512)\t\t Allocation Unit Size of the volume. This will behave on the disk file size.\n"
		"  /k Sector size (ex. /k 512)\t\t\t Sector Size of the volume. This will behave on the disk file size.\n"
		"  /f User mode Lock\t\t\t\t Enable Lockfile/Unlockfile operations. Otherwise Dokan will take care of it.\n"
		"  /i (Timeout in Milliseconds ex. /i 30000)\t Timeout until a running operation is aborted and the device is unmounted.\n\n"
		"Examples:\n"
		"\tmirror.exe /r C:\\Users /l M:\t\t\t# Mirror C:\\Users as RootDirectory into a drive of letter M:\\.\n"
		"\tmirror.exe /r C:\\Users /l C:\\mount\\dokan\t# Mirror C:\\Users as RootDirectory into NTFS folder C:\\mount\\dokan.\n"
		"\tmirror.exe /r C:\\Users /l M: /n /u \\myfs\\myfs1\t# Mirror C:\\Users as RootDirectory into a network drive M:\\. with UNC \\\\myfs\\myfs1\n\n"
		"Unmount the drive with CTRL + C in the console or alternatively via \"dokanctl /u MountPoint\".\n");
	// clang-format on
}
*/

bool CDokanyMirror::Run(const Configuration& config)
{
	//	g_DebugMode = TRUE;

	int status;

	// allocated DOKAN_OPERATION
	PDOKAN_OPERATIONS dokanOperations = (PDOKAN_OPERATIONS)malloc(sizeof(DOKAN_OPERATIONS));
	if (dokanOperations == NULL) 
	{
		return false;
	}

	// allocate DOKAN_OPTIONS
	PDOKAN_OPTIONS dokanOptions = (PDOKAN_OPTIONS)malloc(sizeof(DOKAN_OPTIONS));
	if (dokanOptions == NULL) 
	{
		free(dokanOperations);
		return false;
	}

	// init the structure
	ZeroMemory(dokanOptions, sizeof(DOKAN_OPTIONS));
	dokanOptions->Version = DOKAN_VERSION;
	dokanOptions->ThreadCount = 0; // use default

	// -- BEGIN FILLING DOKAN_OPTIONS --

	// incorporate configuration now:
	wcscpy_s(MountPoint, sizeof(MountPoint) / sizeof(WCHAR), config.MountPoint.c_str());
	dokanOptions->MountPoint = MountPoint;

	// handle network configuration
	if (config.IsNetworkDrive)
	{
		dokanOptions->Options |= DOKAN_OPTION_NETWORK;

		if (!config.UseWindowsMountManager)
		{
			const wchar_t* unc = L"\\\\MyFileServer\\MyShare\\";
			wcscpy_s(UNCName, sizeof(UNCName) / sizeof(WCHAR), unc);
			dokanOptions->UNCName = UNCName;
		}
	}
	// handle removeable drive
	if (config.RemovableDrive)
	{
		dokanOptions->Options |= DOKAN_OPTION_REMOVABLE;
	}
	// handle mount manager config
	if (config.UseWindowsMountManager)
	{
		dokanOptions->Options |= DOKAN_OPTION_MOUNT_MANAGER;
	}
	if (g_DebugMode) 
	{
		dokanOptions->Options |= DOKAN_OPTION_DEBUG;
	}
	dokanOptions->Options |= DOKAN_OPTION_ALT_STREAM;

	// -- END FILLING DOKAN_OPTIONS --

	// -- BEGING FILLING DOKAN_OPERATIONS --

	ZeroMemory(dokanOperations, sizeof(DOKAN_OPERATIONS));
	dokanOperations->ZwCreateFile = MirrorCreateFile;
	dokanOperations->Cleanup = MirrorCleanup;
	dokanOperations->CloseFile = MirrorCloseFile;
	dokanOperations->ReadFile = MirrorReadFile;
	dokanOperations->WriteFile = MirrorWriteFile;
	dokanOperations->FlushFileBuffers = MirrorFlushFileBuffers;
	dokanOperations->GetFileInformation = MirrorGetFileInformation;
	dokanOperations->FindFiles = MirrorFindFiles;
	dokanOperations->FindFilesWithPattern = NULL;
	dokanOperations->SetFileAttributes = MirrorSetFileAttributes;
	dokanOperations->SetFileTime = MirrorSetFileTime;
	dokanOperations->DeleteFile = MirrorDeleteFile;
	dokanOperations->DeleteDirectory = MirrorDeleteDirectory;
	dokanOperations->MoveFile = MirrorMoveFile;
	dokanOperations->SetEndOfFile = MirrorSetEndOfFile;
	dokanOperations->SetAllocationSize = MirrorSetAllocationSize;
	if (config.EnableLockApi)
	{
		dokanOperations->LockFile = MirrorLockFile;
		dokanOperations->UnlockFile = MirrorUnlockFile;
	}
	if (config.EnableSecurityApi)
	{
		dokanOperations->GetFileSecurity = MirrorGetFileSecurity;
		dokanOperations->SetFileSecurity = MirrorSetFileSecurity;
	}
	dokanOperations->GetDiskFreeSpace = MirrorDokanGetDiskFreeSpace;
	dokanOperations->GetVolumeInformation = MirrorGetVolumeInformation;
	dokanOperations->Unmounted = MirrorUnmounted;
	dokanOperations->FindStreams = MirrorFindStreams;
	dokanOperations->Mounted = MirrorMounted;
	// -- BEGING FILLING DOKAN_OPERATIONS --

	// Add security name privilege. Required here to handle GetFileSecurity
	// properly.
	g_HasSeSecurityPrivilege = AddSeSecurityNamePrivilege();

	// This is a NON-DOKAN item:
	//		RootDirectory is used to fixup incoming path requests to match the mirrored folder
	wcscpy_s(RootDirectory, sizeof(RootDirectory) / sizeof(WCHAR), config.RootDirectory.c_str());

	if (!SetConsoleCtrlHandler(CtrlHandler, TRUE))
	{
#ifdef _DEBUG
		DebugBreak();
#endif
	}

	// RUN DOKAN :)
	status = DokanMain(dokanOptions, dokanOperations);

	// Error?
	switch (status) {
		case DOKAN_SUCCESS:
			break;
		case DOKAN_ERROR:
			m_pDialog->NotifyError(L"Error");
			break;
		case DOKAN_DRIVE_LETTER_ERROR:
			m_pDialog->NotifyError(L"Bad Drive letter");
			break;
		case DOKAN_DRIVER_INSTALL_ERROR:
			m_pDialog->NotifyError(L"Can't install driver");
			break;
		case DOKAN_START_ERROR:
			m_pDialog->NotifyError(L"Driver something wrong");
			break;
		case DOKAN_MOUNT_ERROR:
			m_pDialog->NotifyError(L"Can't assign a drive letter");
			break;
		case DOKAN_MOUNT_POINT_ERROR:
			m_pDialog->NotifyError(L"Mount point error");
			break;
		case DOKAN_VERSION_ERROR:
			m_pDialog->NotifyError(L"Version error");
			break;
		default:
			m_pDialog->NotifyError(L"Unknown Error");
			break;
	}

	free(dokanOptions);
	free(dokanOperations);
	return EXIT_SUCCESS;

}

#if 0
int __cdecl wmain(ULONG argc, PWCHAR argv[]) {
	int status;
	ULONG command;
	PDOKAN_OPERATIONS dokanOperations =
		(PDOKAN_OPERATIONS)malloc(sizeof(DOKAN_OPERATIONS));
	if (dokanOperations == NULL) {
		return EXIT_FAILURE;
	}
	PDOKAN_OPTIONS dokanOptions = (PDOKAN_OPTIONS)malloc(sizeof(DOKAN_OPTIONS));
	if (dokanOptions == NULL) {
		free(dokanOperations);
		return EXIT_FAILURE;
	}

	if (argc < 3) {
		ShowUsage();
		free(dokanOperations);
		free(dokanOptions);
		return EXIT_FAILURE;
	}

	g_DebugMode = FALSE;
	g_UseStdErr = FALSE;

	ZeroMemory(dokanOptions, sizeof(DOKAN_OPTIONS));
	dokanOptions->Version = DOKAN_VERSION;
	dokanOptions->ThreadCount = 0; // use default

	for (command = 1; command < argc; command++) {
		switch (towlower(argv[command][1])) {
		case L'r':
			command++;
			wcscpy_s(RootDirectory, sizeof(RootDirectory) / sizeof(WCHAR),
				argv[command]);
			DbgPrint(L"RootDirectory: %ls\n", RootDirectory);
			break;
		case L'l':
			command++;
			wcscpy_s(MountPoint, sizeof(MountPoint) / sizeof(WCHAR), argv[command]);
			dokanOptions->MountPoint = MountPoint;
			break;
		case L't':
			command++;
			dokanOptions->ThreadCount = (USHORT)_wtoi(argv[command]);
			break;
		case L'd':
			g_DebugMode = TRUE;
			break;
		case L's':
			g_UseStdErr = TRUE;
			break;
		case L'n':
			dokanOptions->Options |= DOKAN_OPTION_NETWORK;
			break;
		case L'm':
			dokanOptions->Options |= DOKAN_OPTION_REMOVABLE;
			break;
		case L'w':
			dokanOptions->Options |= DOKAN_OPTION_WRITE_PROTECT;
			break;
		case L'o':
			dokanOptions->Options |= DOKAN_OPTION_MOUNT_MANAGER;
			break;
		case L'c':
			dokanOptions->Options |= DOKAN_OPTION_CURRENT_SESSION;
			break;
		case L'f':
			dokanOptions->Options |= DOKAN_OPTION_FILELOCK_USER_MODE;
			break;
		case L'u':
			command++;
			wcscpy_s(UNCName, sizeof(UNCName) / sizeof(WCHAR), argv[command]);
			dokanOptions->UNCName = UNCName;
			DbgPrint(L"UNC Name: %ls\n", UNCName);
			break;
		case L'p':
			g_ImpersonateCallerUser = TRUE;
			break;
		case L'i':
			command++;
			dokanOptions->Timeout = (ULONG)_wtol(argv[command]);
			break;
		case L'a':
			command++;
			dokanOptions->AllocationUnitSize = (ULONG)_wtol(argv[command]);
			break;
		case L'k':
			command++;
			dokanOptions->SectorSize = (ULONG)_wtol(argv[command]);
			break;
		default:
			fwprintf(stderr, L"unknown command: %s\n", argv[command]);
			free(dokanOperations);
			free(dokanOptions);
			return EXIT_FAILURE;
		}
	}

	if (wcscmp(UNCName, L"") != 0 &&
		!(dokanOptions->Options & DOKAN_OPTION_NETWORK)) {
		fwprintf(
			stderr,
			L"  Warning: UNC provider name should be set on network drive only.\n");
	}

	if (dokanOptions->Options & DOKAN_OPTION_NETWORK &&
		dokanOptions->Options & DOKAN_OPTION_MOUNT_MANAGER) {
		fwprintf(stderr, L"Mount manager cannot be used on network drive.\n");
		free(dokanOperations);
		free(dokanOptions);
		return EXIT_FAILURE;
	}

	if (!(dokanOptions->Options & DOKAN_OPTION_MOUNT_MANAGER) &&
		wcscmp(MountPoint, L"") == 0) {
		fwprintf(stderr, L"Mount Point required.\n");
		free(dokanOperations);
		free(dokanOptions);
		return EXIT_FAILURE;
	}

	if ((dokanOptions->Options & DOKAN_OPTION_MOUNT_MANAGER) &&
		(dokanOptions->Options & DOKAN_OPTION_CURRENT_SESSION)) {
		fwprintf(stderr,
			L"Mount Manager always mount the drive for all user sessions.\n");
		free(dokanOperations);
		free(dokanOptions);
		return EXIT_FAILURE;
	}

	if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
		fwprintf(stderr, L"Control Handler is not set.\n");
	}

	// Add security name privilege. Required here to handle GetFileSecurity
	// properly.
	g_HasSeSecurityPrivilege = AddSeSecurityNamePrivilege();
	if (!g_HasSeSecurityPrivilege) {
		fwprintf(stderr, L"Failed to add security privilege to process\n");
		fwprintf(stderr,
			L"\t=> GetFileSecurity/SetFileSecurity may not work properly\n");
		fwprintf(stderr, L"\t=> Please restart mirror sample with administrator "
			L"rights to fix it\n");
	}

	if (g_ImpersonateCallerUser && !g_HasSeSecurityPrivilege) {
		fwprintf(stderr, L"Impersonate Caller User requires administrator right to "
			L"work properly\n");
		fwprintf(stderr, L"\t=> Other users may not use the drive properly\n");
		fwprintf(stderr, L"\t=> Please restart mirror sample with administrator "
			L"rights to fix it\n");
	}

	if (g_DebugMode) {
		dokanOptions->Options |= DOKAN_OPTION_DEBUG;
	}
	if (g_UseStdErr) {
		dokanOptions->Options |= DOKAN_OPTION_STDERR;
	}

	dokanOptions->Options |= DOKAN_OPTION_ALT_STREAM;

	ZeroMemory(dokanOperations, sizeof(DOKAN_OPERATIONS));
	dokanOperations->ZwCreateFile = MirrorCreateFile;
	dokanOperations->Cleanup = MirrorCleanup;
	dokanOperations->CloseFile = MirrorCloseFile;
	dokanOperations->ReadFile = MirrorReadFile;
	dokanOperations->WriteFile = MirrorWriteFile;
	dokanOperations->FlushFileBuffers = MirrorFlushFileBuffers;
	dokanOperations->GetFileInformation = MirrorGetFileInformation;
	dokanOperations->FindFiles = MirrorFindFiles;
	dokanOperations->FindFilesWithPattern = NULL;
	dokanOperations->SetFileAttributes = MirrorSetFileAttributes;
	dokanOperations->SetFileTime = MirrorSetFileTime;
	dokanOperations->DeleteFile = MirrorDeleteFile;
	dokanOperations->DeleteDirectory = MirrorDeleteDirectory;
	dokanOperations->MoveFile = MirrorMoveFile;
	dokanOperations->SetEndOfFile = MirrorSetEndOfFile;
	dokanOperations->SetAllocationSize = MirrorSetAllocationSize;
	dokanOperations->LockFile = MirrorLockFile;
	dokanOperations->UnlockFile = MirrorUnlockFile;
	dokanOperations->GetFileSecurity = MirrorGetFileSecurity;
	dokanOperations->SetFileSecurity = MirrorSetFileSecurity;
	dokanOperations->GetDiskFreeSpace = NULL; // MirrorDokanGetDiskFreeSpace;
	dokanOperations->GetVolumeInformation = MirrorGetVolumeInformation;
	dokanOperations->Unmounted = MirrorUnmounted;
	dokanOperations->FindStreams = MirrorFindStreams;
	dokanOperations->Mounted = MirrorMounted;

	status = DokanMain(dokanOptions, dokanOperations);
	switch (status) {
	case DOKAN_SUCCESS:
		fprintf(stderr, "Success\n");
		break;
	case DOKAN_ERROR:
		fprintf(stderr, "Error\n");
		break;
	case DOKAN_DRIVE_LETTER_ERROR:
		fprintf(stderr, "Bad Drive letter\n");
		break;
	case DOKAN_DRIVER_INSTALL_ERROR:
		fprintf(stderr, "Can't install driver\n");
		break;
	case DOKAN_START_ERROR:
		fprintf(stderr, "Driver something wrong\n");
		break;
	case DOKAN_MOUNT_ERROR:
		fprintf(stderr, "Can't assign a drive letter\n");
		break;
	case DOKAN_MOUNT_POINT_ERROR:
		fprintf(stderr, "Mount point error\n");
		break;
	case DOKAN_VERSION_ERROR:
		fprintf(stderr, "Version error\n");
		break;
	default:
		fprintf(stderr, "Unknown error: %d\n", status);
		break;
	}

	free(dokanOptions);
	free(dokanOperations);
	return EXIT_SUCCESS;
}
#endif

//===================================================================
//===================================================================
//===================================================================


HANDLE  ShutdownSignal = INVALID_HANDLE_VALUE;
HANDLE	RunJobSignal = INVALID_HANDLE_VALUE;
HANDLE	ThreadHandle = INVALID_HANDLE_VALUE;

CDokanyMirror::CDokanyMirror()
{
	m_pSingleton = this;
}

unsigned int __stdcall CDokanyMirror::ThreadStart(void* ctx)
{
	CDokanyMirror* pObj = (CDokanyMirror*)ctx;
	pObj->ThreadMain();

	return 0;
}

void CDokanyMirror::OnStartup(IDialogCallback* pCB)
{
	m_pDialog = pCB;
	m_IsRunning = false;
	ShutdownSignal = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	RunJobSignal = ::CreateEvent(NULL, FALSE, FALSE, NULL);
	ThreadHandle = (HANDLE)_beginthreadex(NULL, 0, CDokanyMirror::ThreadStart, this, 0, NULL);
}
void CDokanyMirror::OnShutdown()
{
	SetEvent(ShutdownSignal);
	Unmount();
}

bool CDokanyMirror::Mount(const Configuration& config)
{
	m_StartTime = GetTickCount64();
	m_Config = config;
	SetEvent(RunJobSignal);
	return true;
}
void CDokanyMirror::Unmount()
{
	CtrlHandler(CTRL_C_EVENT);
}


void CDokanyMirror::ThreadMain()
{
	HANDLE h[2];
	h[0] = ShutdownSignal;
	h[1] = RunJobSignal;

	while (true)
	{
		DWORD waitResult = WaitForMultipleObjects(2, h, FALSE, INFINITE);

		// Shutdown Signalled?
		if (waitResult == WAIT_OBJECT_0)
			return;
		if (waitResult != (WAIT_OBJECT_0 + 1))
			return;

		m_IsRunning = true;
		Run(m_Config);
		m_IsRunning = false;
	}
}

void CDokanyMirror::AddEvent(CDokanyEvent* pE, bool forced)
{
	if (m_StartTime != 0)
	{
		pE->SetTickCount(GetTickCount64() - m_StartTime);
	}

	if (g_Queue()->AddEvent(pE, forced))
	{
		if (m_pDialog)
		{
			m_pDialog->NotifyEvent(pE);
		}
	}
	else
	{
		delete pE;
	}
}

static void InsertChar(wchar_t* loc, wchar_t c)
{
	wchar_t buf[DOKAN_MAX_PATH];
	size_t len = wcslen(loc);

	memcpy(buf, loc, (len + 1) * sizeof(wchar_t));
	*loc = c;
	memcpy(loc + 1, buf, (len + 1) * sizeof(wchar_t));
}
static void DeleteChar(wchar_t* loc, wchar_t c)
{
	if (*loc == c)
	{
		size_t len = wcslen(loc);
		memcpy(loc, loc + 1, len * sizeof(wchar_t));
	}
}


void CDokanyMirror::AdornFilename(wchar_t* pathString)
{
	if (AdornmentActive())
	{
		if (pathString[0] != L'.')
		{
			InsertChar(pathString, m_Adornment);
		}
	}

}
void CDokanyMirror::StripAdornment(wchar_t* pathString)
{
	if (AdornmentActive())
	{
		wchar_t* loc = pathString;
		while (*loc != L'\0')
		{
			if (*loc == L'\\')
			{
				++loc;
				DeleteChar(loc, m_Adornment);
			}

			++loc;
		}
	}
}

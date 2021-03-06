#pragma once
#include <string>
#include "EventQueue.h"
#include "IDialogCallback.H"

class CDokanyEvent;



class CDokanyMirror
{
public:
	struct Configuration
	{
		std::wstring	RootDirectory;
		std::wstring	MountPoint;
		std::wstring	UNCName;

		bool			IsNetworkDrive;
		bool			UseWindowsMountManager;
		bool			RemovableDrive;

		// API options
		bool			EnableSecurityApi;
		bool			EnableLockApi;

		Configuration() : IsNetworkDrive(false), UseWindowsMountManager(false), RemovableDrive(false), EnableSecurityApi(true), EnableLockApi(true) {}
	};

private:
	static CDokanyMirror*	m_pSingleton;
	IDialogCallback*		m_pDialog;

	Configuration			m_Config;
	CEventQueue				m_Queue;

	// statistical stuff:
	__int64					m_StartTime;
	bool					m_IsRunning;

	// runtime options - switchable after mount:
	wchar_t					m_Adornment;
	bool					m_SetFileAttributeRecallOnDataAccess;

public:
	CDokanyMirror();

	static CDokanyMirror* Get()
	{
		return m_pSingleton;
	}

	void OnStartup(IDialogCallback* pCB);
	void OnShutdown();

	bool Mount(const Configuration& config);
	void Unmount();
	bool IsRunning()
	{
		return m_IsRunning;
	}

	void AddEvent(CDokanyEvent* pD, bool forced );
	void SetAdornment(wchar_t c)
	{
		m_Adornment = c;
	}

	void AdornFilename(wchar_t* pathString);
	void StripAdornment(wchar_t* pathString);
	bool AdornmentActive()
	{
		return m_Adornment != L'\0';
	}
	void SetFileAttributeRecallOnDataAccess(bool b)
	{
		m_SetFileAttributeRecallOnDataAccess = b;
	}
	bool FileAttributeRecallOnDataAccessActive()
	{
		return m_SetFileAttributeRecallOnDataAccess;
	}

private:
	void ThreadMain();
	bool Run(const Configuration& config);

	static unsigned int __stdcall ThreadStart(void* pData);
};


__inline CDokanyMirror* g_Mirror()
{
	return CDokanyMirror::Get();
}

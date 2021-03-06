
// DokanyMirrorDlg.cpp : implementation file
//

#include "stdafx.h"
#include "DokanyMirror.h"
#include "DokanyMirrorDlg.h"
#include "afxdialogex.h"
#include "MIrror.H"
#include "resource.H"
#include <map>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CDokanyMirrorDlg dialog

CDokanyMirror _mirror;

#define WM_DOKANY_ERROR		(WM_USER+1)
#define WM_DOKANY_EVENT		(WM_USER+2)

#define COL_SEQUENCE	(0)
#define COL_TIME		(1)
#define COL_COMMAND		(2)
#define COL_FILENAME	(3)
#define COL_DOK			(4)
#define COL_PID			(5)
#define COL_THREAD		(6)
#define COL_CTX			(7)
#define COL_COMMENTS	(8)

class CommentEvent: public CDokanyEvent
{
public:
	CommentEvent(const std::wstring& EventName, const std::wstring& EventString )
		: CDokanyEvent(L"//", EventName.c_str(), 0, 0, 0) 
	{
		AddComment(EventString);
	}
	virtual bool Match(const std::wstring&)
	{
		return true;
	}
};



CDokanyMirrorDlg::CDokanyMirrorDlg(CWnd* pParent /*=NULL*/)
	: CDialog(IDD_DOKANYMIRROR_DIALOG, pParent), m_FilterActive(false), m_AutoScroll(true)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CDokanyMirrorDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_MIRRORED_FOLDER, m_EditMirroredFolder);
	DDX_Control(pDX, IDC_EDIT_MOUNT_POINT, m_EditMountLocation);
	DDX_Control(pDX, IDC_CHECK_NETWORK, m_CheckRunAsNetworkVolume);
	DDX_Control(pDX, IDC_CHECK_WINDOW_MOUNT, m_CheckMountManager);
	DDX_Control(pDX, IDC_CHECK_REMOVABLE, m_CheckRemovableDrive);
	DDX_Control(pDX, IDC_BUTTON_MOUNT, m_ButtonMount);
	DDX_Control(pDX, IDC_BUTTON_START, m_ButtonStart);
	DDX_Control(pDX, IDC_BUTTON_CLEAR, m_ButtonReset);
	DDX_Control(pDX, IDC_BUTTON_EXPORT, m_ButtonExport);
	DDX_Control(pDX, IDC_BUTTON_REPORT, m_ButtonReport);
	DDX_Control(pDX, IDC_BUTTON_QUIT, m_ButtonQuit);
	DDX_Control(pDX, IDC_EDIT_FILTER, m_EditSearch);
	DDX_Control(pDX, IDC_BUTTON_FILTERS, m_ButtonFilters);
	DDX_Control(pDX, IDC_BUTTON_COLUMNS, m_ButtonAutoSize);
	DDX_Control(pDX, IDC_CHECK_ADORNMENT, m_CheckAdorned);
	DDX_Control(pDX, IDC_CHECK_AUTOSCROLL, m_CheckAutoScroll);
	DDX_Control(pDX, IDC_LIST1, m_List);
	DDX_Control(pDX, IDC_CHECK_FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, m_CheckFileAttributeRecallOnDataAccess);
	DDX_Control(pDX, IDC_STATIC_GROUP_LOG, m_GroupBoxLogging);
	DDX_Control(pDX, IDC_CHECK_SCURITYAPIS, m_CheckEnableSecurityApis);
	DDX_Control(pDX, IDC_CHECK_LOCKAPIS, m_CheckEnableLockApis);
	DDX_Control(pDX, IDC_CHECK_OPEN_EXPLORER_ON_MOUNT, m_CheckOpenExplorerOnMount);
	DDX_Control(pDX, IDC_BUTTON1, m_ButtonOpenExplorer);
	DDX_Control(pDX, IDC_STATIC_STATUS, m_StatusText);
}

BEGIN_MESSAGE_MAP(CDokanyMirrorDlg, CDialog)
	ON_MESSAGE(WM_DOKANY_ERROR, OnDokanyError)
	ON_MESSAGE(WM_DOKANY_EVENT, OnDokanyEvent)
	ON_WM_TIMER()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_GETMINMAXINFO()
	ON_WM_SIZE()
	ON_BN_CLICKED(IDC_BUTTON_CLEAR, &CDokanyMirrorDlg::OnBnClickedReset)
	ON_BN_CLICKED(IDC_BUTTON_QUIT, &CDokanyMirrorDlg::OnBnClickedQuit)
	ON_BN_CLICKED(IDC_BUTTON_FILTERS, &CDokanyMirrorDlg::OnBnClickedButtonFilters)
	ON_BN_CLICKED(IDC_BUTTON_START, &CDokanyMirrorDlg::OnBnClickedStart)
	ON_BN_CLICKED(IDC_BUTTON_MOUNT, &CDokanyMirrorDlg::OnBnClickedMount)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &CDokanyMirrorDlg::OnLvnItemchangedList1)
	ON_BN_CLICKED(IDC_BUTTON_EXPORT, &CDokanyMirrorDlg::OnBnClickedButtonExport)
	ON_BN_CLICKED(IDC_CHECK_AUTOSCROLL, &CDokanyMirrorDlg::OnBnClickedCheckAutoScroll)
	ON_BN_CLICKED(IDC_BUTTON_COLUMNS, &CDokanyMirrorDlg::OnBnClickedButtonAutoSizeColumns)
	ON_BN_CLICKED(IDC_CHECK_ADORNMENT, &CDokanyMirrorDlg::OnBnClickedCheck3)
	ON_BN_CLICKED(IDC_CHECK_NETWORK, &CDokanyMirrorDlg::OnBnClickedCheckRunAsNetwork)
	ON_BN_CLICKED(IDC_CHECK_REMOVABLE, &CDokanyMirrorDlg::OnBnClickedCheckRemovable)
	ON_BN_CLICKED(IDC_CHECK_WINDOW_MOUNT, &CDokanyMirrorDlg::OnBnClickedCheckWindowMount)
	ON_BN_CLICKED(IDC_BUTTON_HELP, &CDokanyMirrorDlg::OnBnClickedHelp)
	ON_BN_CLICKED(IDC_BUTTON_REPORT, &CDokanyMirrorDlg::OnBnClickedButtonReport)
	ON_BN_CLICKED(IDC_CHECK_FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, &CDokanyMirrorDlg::OnBnClickedExperimentalFlags)
	ON_BN_CLICKED(IDC_BUTTON1, &CDokanyMirrorDlg::OnBnClickedButtonOpenExplorer)
END_MESSAGE_MAP()

void CDokanyMirrorDlg::NotifyError(const std::wstring& msg)
{
	PostMessage(WM_DOKANY_ERROR, 0, (LPARAM)new std::wstring(msg));
}
void CDokanyMirrorDlg::NotifyEvent(CDokanyEvent* pEvent)
{
	PostMessage(WM_DOKANY_EVENT, 0, (LPARAM)pEvent);
}

// CDokanyMirrorDlg message handlers

void CDokanyMirrorDlg::OnTimer(UINT_PTR t)
{
	if (t == 0)
	{
		UpdateButtons();
		UpdateStatus();

		// do some scrolling
		if (m_AutoScroll && g_Mirror()->IsRunning() && g_Queue()->GetEnabled())
		{
			m_List.EnsureVisible(m_List.GetItemCount()-1, FALSE);
		}
	}
}

void CDokanyMirrorDlg::UpdateStatus()
{
	size_t numEvents = m_List.GetItemCount();
	if (numEvents == 0)
	{
		m_StatusText.SetWindowTextW(L"");
	}
	else
	{
		wchar_t buf[1024];
		swprintf_s(buf, L"%lld events", (__int64)numEvents);
		m_StatusText.SetWindowTextW(buf);
	}
}
void CDokanyMirrorDlg::UpdateButtons()
{
	bool mounted = g_Mirror()->IsRunning();
	bool enabled = g_Queue()->GetEnabled() && mounted;

	// update some text
	m_ButtonMount.SetWindowTextW(mounted ? L"Unmount" : L"Mount");
	m_ButtonStart.SetWindowTextW(enabled ? L"Pause" : L"Resume");

	// show/hide 
	m_ButtonStart.ShowWindow(mounted ? SW_SHOW : SW_HIDE);
	m_ButtonReset.ShowWindow(m_List.GetItemCount() > 0 ? SW_SHOW : SW_HIDE);
	m_ButtonAutoSize.ShowWindow(m_List.GetItemCount() > 0 ? SW_SHOW : SW_HIDE);
	m_ButtonExport.ShowWindow(m_List.GetItemCount() > 0 ? SW_SHOW : SW_HIDE);
	m_ButtonReport.ShowWindow(m_List.GetItemCount() > 0 ? SW_SHOW : SW_HIDE);

	// disable configuration while mounted
	m_EditMirroredFolder.EnableWindow(!mounted);
	m_EditMountLocation.EnableWindow(!mounted);
	m_CheckRunAsNetworkVolume.EnableWindow(!mounted);
	m_CheckMountManager.EnableWindow(!mounted);
	m_CheckRemovableDrive.EnableWindow(!mounted);
	m_CheckEnableSecurityApis.EnableWindow(!mounted);
	m_CheckEnableLockApis.EnableWindow(!mounted);

	m_CheckOpenExplorerOnMount.ShowWindow(mounted ? SW_HIDE : SW_SHOW );
	m_ButtonOpenExplorer.ShowWindow(mounted ? SW_SHOW : SW_HIDE);

	m_EditSearch.EnableWindow(!m_FilterActive);
	m_ButtonFilters.SetWindowTextW(m_FilterActive ? L"Reset Filter" : L"Set Filter");

	// make sure these are always on
	m_CheckAutoScroll.EnableWindow(TRUE);
}


BOOL CDokanyMirrorDlg::OnInitDialog()
{
	if (__super::OnInitDialog())
	{
		// in no intentional order....

		GetClientRect(m_DefaulClienttRect);

		GetWindowRect(m_DefaultRect);
		ScreenToClient(m_DefaultRect);

		m_List.GetWindowRect(m_DefaultListRect);
		ScreenToClient(m_DefaultListRect);

		m_GroupBoxLogging.GetWindowRect(m_DefaultGroupRect);
		ScreenToClient(m_DefaultGroupRect);

		g_Mirror()->OnStartup(this);

		// Set the icon for this dialog.  The framework does this automatically
		//  when the application's main window is not a dialog
		SetIcon(m_hIcon, TRUE);			// Set big icon
		SetIcon(m_hIcon, FALSE);		// Set small icon

										// format the report view
		CRect rect;
		m_List.GetWindowRect(&rect);

		m_List.InsertColumn(COL_SEQUENCE, L"#", LVCFMT_RIGHT, rect.Width() * 3 / 100);
		m_List.InsertColumn(COL_TIME, L"Time", LVCFMT_RIGHT, rect.Width() * 6 / 100);
		m_List.InsertColumn(COL_COMMAND, L"Command", LVCFMT_LEFT, rect.Width() * 10 / 100);
		m_List.InsertColumn(COL_FILENAME, L"Filename", LVCFMT_LEFT, rect.Width() * 20 / 100);
		m_List.InsertColumn(COL_DOK, L"Dokany", LVCFMT_LEFT, rect.Width() * 6 / 100);
		m_List.InsertColumn(COL_PID, L"PID", LVCFMT_RIGHT, rect.Width() * 6 / 100);
		m_List.InsertColumn(COL_THREAD, L"TID", LVCFMT_RIGHT, rect.Width() * 6 / 100);
		m_List.InsertColumn(COL_CTX, L"Ctx", LVCFMT_RIGHT, rect.Width() * 6 / 100);
		m_List.InsertColumn(COL_COMMENTS, L"Comments", LVCFMT_LEFT, rect.Width() * 34 / 100);
		m_List.SetExtendedStyle(LVS_EX_FULLROWSELECT|LVS_EX_LABELTIP);

		// set some default values
		m_CheckAutoScroll.SetCheck(m_AutoScroll);
		m_CheckRunAsNetworkVolume.SetCheck(1);
		m_CheckEnableLockApis.SetCheck(1);
		m_CheckEnableSecurityApis.SetCheck(1);

		UpdateButtons();
		SetTimer(0, 500, NULL);
		return TRUE;  // return TRUE  unless you set the focus to a control
	}

	return FALSE;
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CDokanyMirrorDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CDokanyMirrorDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CDokanyMirrorDlg::OnBnClickedStart()
{
	if (g_Queue()->GetEnabled())
	{
		g_Queue()->Disable();
	}
	else
	{
		g_Queue()->Enable();
	}
}


void CDokanyMirrorDlg::OnBnClickedQuit()
{
	g_Mirror()->OnShutdown();
	CDialog::OnCancel();
}


void CDokanyMirrorDlg::OnBnClickedButtonFilters()
{
	CWaitCursor c;

	bool changed = false;
	CEventQueue::tEventList events;

	if (m_FilterActive)
	{
		SetFilter(L"");
		g_Queue()->GetEvents(events);
		m_EditSearch.SetWindowTextW(L"");
		m_FilterActive = false;
		changed = true;
	}
	else
	{
		CString s;
		m_EditSearch.GetWindowText(s);

		if (s.GetLength() > 0)
		{
			SetFilter((LPCWSTR)s);
			g_Queue()->GetFilteredEvents(m_FilterString, events);
			m_FilterActive = true;
			changed = true;
		}
	}

	if (changed)
	{
		bool enabled = g_Queue()->GetEnabled();

		if (enabled)
		{
			g_Queue()->Disable();
		}
		m_List.DeleteAllItems();
		for (CEventQueue::tEventList::iterator iter = events.begin(); iter != events.end(); ++iter)
		{
			AddListItem((*iter));
		}
		if (enabled)
		{
			g_Queue()->Enable();
		}
		UpdateButtons();
	}

	UpdateStatus();
}



LRESULT CDokanyMirrorDlg::OnDokanyError(WPARAM, LPARAM lpMessage)
{
	std::wstring* pS = (std::wstring*)lpMessage;
	MessageBox(pS->c_str(), L"Dokany", MB_ICONERROR);
	delete pS;
	return 0;
}
LRESULT CDokanyMirrorDlg::OnDokanyEvent(WPARAM, LPARAM lpEvent)
{
	CDokanyEvent* pEvent = (CDokanyEvent*)lpEvent;

	std::wstring filter;
	if (GetFilter(filter))
	{
		if (!pEvent->Match(m_FilterString))
		{
			return 0;
		}

	}

	AddListItem(pEvent);
	return 0;
}

void CDokanyMirrorDlg::AddListItem(CDokanyEvent* pEvent)
{
	try
	{
		int iActualItem = 0;
		int iItem = 0;

		LV_ITEM         lvitem;
		lvitem.mask = LVIF_TEXT;
		lvitem.iItem = m_List.GetItemCount();
		lvitem.iSubItem = 0;
		wchar_t buf[1024];
		swprintf_s(buf, L"%lld", pEvent->Sequence());
		lvitem.pszText = buf;
		iItem = m_List.InsertItem(&lvitem);

		int x = (int)((pEvent->TickCount()) / 1000);
		int y = (int)((pEvent->TickCount()) % 1000);
		swprintf_s(buf, L"%06d.%03d", x, y);
		lvitem.pszText = buf;
		m_List.SetItemText(iItem, COL_TIME, buf);
	
		swprintf_s(buf, L"%lld", pEvent->ThreadId());
		m_List.SetItemText(iItem, COL_THREAD, buf);

		m_List.SetItemText(iItem, COL_COMMAND, pEvent->Command().c_str());
		m_List.SetItemText(iItem, COL_FILENAME, pEvent->FileName().c_str());
		m_List.SetItemText(iItem, COL_DOK, pEvent->DokanyFlags().c_str());
		buf[0] = L'\0';
		if (pEvent->ProcessId() != 0)
		{
			swprintf_s(buf, L"%lld", pEvent->ProcessId());
		}
		m_List.SetItemText(iItem, COL_PID, buf);

		buf[0] = L'\0';
		if (pEvent->ContextId() != 0)
		{
			swprintf_s(buf, L"%lld", pEvent->ContextId());
		}
		m_List.SetItemText(iItem, COL_CTX, buf);

		m_List.SetItemText(iItem, COL_COMMENTS, pEvent->Comment().c_str());
	}
	catch (...) {}
}

void CDokanyMirrorDlg::OnGetMinMaxInfo(MINMAXINFO FAR* lpMMI)
{
	lpMMI->ptMinTrackSize.x = m_DefaultRect.Width();
	lpMMI->ptMinTrackSize.y = m_DefaultRect.Height();
}
void CDokanyMirrorDlg::OnSize(UINT nType, int cx, int cy)
{
	HWND hWnd = m_List.GetSafeHwnd();
	if (m_List.GetSafeHwnd() != 0)
	{
		int yChange = cy - m_DefaulClienttRect.Height();
		int xChange = cx - m_DefaulClienttRect.Width();

		CRect listRect = m_DefaultListRect;
		listRect.right += xChange;
		listRect.bottom += yChange;

		m_List.SetWindowPos(NULL, 0, 0, listRect.Width(), listRect.Height(), SWP_NOMOVE);

		CRect groupRect = m_DefaultGroupRect;
		groupRect.right += xChange;
		groupRect.bottom += yChange;
		m_GroupBoxLogging.SetWindowPos(NULL, 0, 0, groupRect.Width(), groupRect.Height(), SWP_NOMOVE);
	}
}


void CDokanyMirrorDlg::OnBnClickedReset()
{
	CWaitCursor c;

	bool enabled = g_Queue()->GetEnabled();

	g_Queue()->Disable();
	m_List.DeleteAllItems();
	g_Queue()->Reset();
	if (enabled)
	{
		g_Queue()->Enable();
	}
}


void CDokanyMirrorDlg::OnBnClickedMount()
{
	CWaitCursor c;

	if (g_Mirror()->IsRunning())
	{
		g_Mirror()->Unmount();
	}
	else
	{
		CDokanyMirror::Configuration config;

		wchar_t buf[1024];
		m_EditMirroredFolder.GetWindowText(buf, 1024);
		config.RootDirectory = buf;
		m_EditMountLocation.GetWindowText(buf, 1024);
		config.MountPoint = buf;
		config.IsNetworkDrive = (bool)m_CheckRunAsNetworkVolume.GetCheck();
		config.UseWindowsMountManager = (bool)m_CheckMountManager.GetCheck();
		config.RemovableDrive = (bool)m_CheckRemovableDrive.GetCheck();
		config.EnableLockApi = (bool)m_CheckEnableLockApis.GetCheck();
		config.EnableSecurityApi = (bool)m_CheckEnableSecurityApis.GetCheck();

		g_Queue()->Enable();
		g_Mirror()->Mount(config);

		if (m_CheckOpenExplorerOnMount.GetCheck())
		{
			::ShellExecute(GetSafeHwnd(), L"explore", buf, L"", L"", SW_SHOW);
		}
	}
}


void CDokanyMirrorDlg::OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: Add your control notification handler code here
	*pResult = 0;
}


void CDokanyMirrorDlg::OnBnClickedButtonExport()
{
	CWaitCursor c;

	// We're going to export this data as CSV.

	// let's put the file on the desktop:
	wchar_t desktopFolder[1024];
	SHGetSpecialFolderPath(GetSafeHwnd(), desktopFolder, CSIDL_DESKTOP, FALSE);
	wchar_t csvFile[1024];
	swprintf_s(csvFile, L"%s\\dokany_mirror_%lld.csv", desktopFolder, time(0));
	::DeleteFile(csvFile);	

	// Get a copy of the events list
	CEventQueue::tEventList l;
	g_Queue()->GetEvents(l);

	FILE *f = NULL;
	_wfopen_s(&f, csvFile, L"w+");

	if (f == NULL)
	{
		MessageBox((std::wstring(L"Unable to create ") + csvFile).c_str(), L"Error", MB_ICONERROR);
		return;
	}

	// put out the headers:
	fputws(L"#,Time,Command,Filename,PID,Thread,CTX,Comments\n",f);

	// and then the rows
	for (CEventQueue::tEventList::iterator iter = l.begin(); iter != l.end(); ++iter)
	{
		CDokanyEvent* pEvent = (*iter);
		fwprintf(f, L"%lld, %lld, %s, %s, %lld, %lld, %lld, %s\n", pEvent->Sequence(), pEvent->TickCount(), pEvent->Command().c_str(), pEvent->FileName().c_str(), pEvent->ProcessId(), pEvent->ThreadId(), pEvent->ContextId(),  pEvent->Comment().c_str() );
	}
	fclose(f);

	// ask the shell to open the file - if you have Excel it will load it
	::ShellExecute(GetSafeHwnd(), L"open", csvFile, L"", L"", SW_SHOW);
}


void CDokanyMirrorDlg::OnBnClickedCheckAutoScroll()
{
	m_AutoScroll = !m_AutoScroll;
}


void CDokanyMirrorDlg::OnBnClickedButtonAutoSizeColumns()
{
	// This is temporary until I make something more automatic...
	m_List.SetColumnWidth(COL_SEQUENCE, LVSCW_AUTOSIZE);
	m_List.SetColumnWidth(COL_TIME, LVSCW_AUTOSIZE);
	m_List.SetColumnWidth(COL_COMMAND, LVSCW_AUTOSIZE);
	m_List.SetColumnWidth(COL_FILENAME, LVSCW_AUTOSIZE);
	m_List.SetColumnWidth(COL_DOK, LVSCW_AUTOSIZE);
	m_List.SetColumnWidth(COL_PID, LVSCW_AUTOSIZE);
	m_List.SetColumnWidth(COL_THREAD, LVSCW_AUTOSIZE);
	m_List.SetColumnWidth(COL_CTX, LVSCW_AUTOSIZE);
	m_List.SetColumnWidth(COL_COMMENTS, LVSCW_AUTOSIZE);
}


void CDokanyMirrorDlg::OnBnClickedCheck3()
{
	// Adornment add "$" to the start of filenames and folders
	BOOL adorned = m_CheckAdorned.GetCheck();
	g_Mirror()->SetAdornment(adorned ? L'$' : L'\0');

	CommentEvent* pEvent = new CommentEvent(L"Adornment", adorned ? L"Enable" : L"Disable");
	g_Mirror()->AddEvent(pEvent, true);
}

void CDokanyMirrorDlg::OnBnClickedCheckRunAsNetwork()
{
}


void CDokanyMirrorDlg::OnBnClickedCheckRemovable()
{
	bool checked = m_CheckRemovableDrive.GetCheck();
	m_CheckRunAsNetworkVolume.ShowWindow(checked ? SW_HIDE : SW_SHOW);
}


void CDokanyMirrorDlg::OnBnClickedCheckWindowMount()
{
}


void CDokanyMirrorDlg::OnBnClickedHelp()
{
	ShellExecute(GetSafeHwnd(), L"open", L"https://us.awp.autotask.net/1/filelink/21-411b49f3-152884e1d9-2", L"", L"", SW_SHOW);
}


void CDokanyMirrorDlg::OnBnClickedButtonReport()
{
	CString x;
	CEventQueue::tEventList eventsList;
	g_Queue()->GetEvents(eventsList);

	typedef std::map<std::wstring, __int64>	tCountingMap;

	tCountingMap	paths;
	tCountingMap	commands;

	for (CEventQueue::tEventList::iterator iter = eventsList.begin(); iter != eventsList.end(); ++iter)
	{
		CDokanyEvent* pEvent = (*iter);

		paths[pEvent->FileName()]++;
		commands[pEvent->Command()]++;
	}


	wchar_t desktopFolder[1024];
	SHGetSpecialFolderPath(GetSafeHwnd(), desktopFolder, CSIDL_DESKTOP, FALSE);
	wchar_t reportFile[1024];
	swprintf_s(reportFile, L"%s\\dokany_mirror_report_%lld.txt", desktopFolder, time(0));
	::DeleteFile(reportFile);

	FILE *f = NULL;
	_wfopen_s(&f, reportFile, L"w+");

	if (f == NULL)
	{
		MessageBox((std::wstring(L"Unable to create ") + reportFile).c_str(), L"Error", MB_ICONERROR);
		return;
	}

	fwprintf(f, L"DokanyMirror v0.1\n\n");
	fwprintf(f, L"Total Events: %d\n\n", (int)eventsList.size());
	fwprintf(f, L"\n");

	fwprintf(f, L"Mount Options:\n");

	m_EditMirroredFolder.GetWindowTextW(x);
	fwprintf(f, L"\tMirrored Folder: %s\n", (LPCWSTR)x);
	m_EditMountLocation.GetWindowTextW(x);
	fwprintf(f, L"\tMount Point: %s\n", (LPCWSTR)x);
	fwprintf(f, L"\tRun As Network: %s\n", m_CheckRunAsNetworkVolume.GetCheck() ? L"true" : L"false");
	fwprintf(f, L"\tUse Windows Mount: %s\n", m_CheckMountManager.GetCheck() ? L"true" : L"false");
	fwprintf(f, L"\tRemovable Device: %s\n", m_CheckRemovableDrive.GetCheck() ? L"true" : L"false");
	fwprintf(f, L"\tSecurity APIs: %s\n", m_CheckEnableSecurityApis.GetCheck() ? L"true" : L"false");
	fwprintf(f, L"\tLock APIs: %s\n", m_CheckEnableLockApis.GetCheck() ? L"true" : L"false");

	fwprintf(f, L"\n");

	fwprintf(f, L"Command references\n");
	fwprintf(f, L"------------------\n");
	for (tCountingMap::iterator iter = commands.begin(); iter != commands.end(); ++iter)
	{
		const std::wstring& command = (*iter).first;
		__int64 counter = (*iter).second;
		fwprintf(f, L"%lld\t%s\n", counter, command.c_str());
	}
	fwprintf(f, L"\n\n");
	fwprintf(f, L"Path references\n");
	fwprintf(f, L"---------------\n");
	for (tCountingMap::iterator iter = paths.begin(); iter != paths.end(); ++iter)
	{
		const std::wstring& path= (*iter).first;
		__int64 counter = (*iter).second;
		fwprintf(f, L"%lld\t%s\n", counter, path.c_str());
	}
	fwprintf(f, L"\n\n");
	fclose(f);

	ShellExecute(GetSafeHwnd(), L"open", reportFile, L"", L"", SW_SHOW);
}


void CDokanyMirrorDlg::OnBnClickedExperimentalFlags()
{
	bool checked = m_CheckFileAttributeRecallOnDataAccess.GetCheck() != 0;

	CommentEvent* pEvent = new CommentEvent(L"Experimental", checked ? L"Enable" : L"Disable");

	g_Mirror()->SetFileAttributeRecallOnDataAccess(checked);
	g_Mirror()->AddEvent(pEvent, true);
}


void CDokanyMirrorDlg::OnBnClickedButtonOpenExplorer()
{
	wchar_t buf[1024];
	m_EditMountLocation.GetWindowText(buf, 1024);
	::ShellExecute(GetSafeHwnd(), L"explore", buf, L"", L"", SW_SHOW);
}

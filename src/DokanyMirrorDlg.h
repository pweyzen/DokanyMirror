
// DokanyMirrorDlg.h : header file
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"
#include "IDialogCallback.H"


// CDokanyMirrorDlg dialog
class CDokanyMirrorDlg : public CDialog, public IDialogCallback
{
// Construction
public:
	CDokanyMirrorDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DOKANYMIRROR_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	virtual void NotifyError(const std::wstring& msg);
	virtual void NotifyEvent(CDokanyEvent* pEvent);
// Implementation
protected:
	HICON m_hIcon;
	bool			m_FilterActive;
	std::wstring	m_FilterString;
	bool			m_AutoScroll;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg void OnGetMinMaxInfo(MINMAXINFO FAR* lpMMI);
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnTimer(UINT_PTR t);
	afx_msg HCURSOR OnQueryDragIcon();
	LRESULT OnDokanyError(WPARAM, LPARAM lpMessage);
	LRESULT OnDokanyEvent(WPARAM, LPARAM lpEvent);

	void AddListItem(CDokanyEvent* pE);

	void SetFilter(const std::wstring& str)
	{
		if (str.length() == 0)
		{
			m_FilterActive = false;
			m_FilterString.clear();
		}
		else
		{
			m_FilterActive = true;
			m_FilterString = str;
		}
	}
	bool GetFilter(std::wstring& str)
	{
		if (m_FilterActive)
		{
			str = m_FilterString;
			return true;
		}
		return false;
	}


	DECLARE_MESSAGE_MAP()
public:
	CRect m_DefaulClienttRect;
	CRect m_DefaultRect;
	CRect m_DefaultListRect;
	CRect m_DefaultGroupRect;

	void UpdateButtons();
	void UpdateStatus();
	
	CListCtrl m_List;
	CEdit m_EditMirroredFolder;
	CEdit m_EditMountLocation;
	CEdit m_EditSearch;
	CButton m_ButtonFilters;
	CButton m_ButtonQuit;
	CButton m_ButtonStart;
	CButton m_CheckRunAsNetworkVolume;
	CButton m_ButtonMount;
	CButton m_ButtonReset;
	CButton m_CheckAutoScroll;
	CButton m_ButtonAutoSize;
	CButton m_ButtonExport;
	CButton m_CheckAdorned;
	CButton m_CheckMountManager;
	CButton m_CheckRemovableDrive;
	CButton m_ButtonReport;
	CButton m_CheckFileAttributeRecallOnDataAccess;
	CStatic m_GroupBoxLogging;
	CButton m_CheckEnableSecurityApis;
	CButton m_CheckEnableLockApis;
	CButton m_CheckOpenExplorerOnMount;
	CButton m_ButtonOpenExplorer;
	CStatic m_StatusText;

	afx_msg void OnBnClickedStart();
	afx_msg void OnBnClickedQuit();
	afx_msg void OnBnClickedButtonFilters();
	afx_msg void OnBnClickedReset();
	afx_msg void OnBnClickedMount();
	afx_msg void OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedButtonExport();
	afx_msg void OnBnClickedCheckAutoScroll();
	afx_msg void OnBnClickedButtonAutoSizeColumns();
	afx_msg void OnBnClickedCheck3();
	afx_msg void OnBnClickedCheckRunAsNetwork();
	afx_msg void OnBnClickedCheckRemovable();
	afx_msg void OnBnClickedCheckWindowMount();
	afx_msg void OnBnClickedHelp();
	afx_msg void OnBnClickedButtonReport();
	afx_msg void OnBnClickedExperimentalFlags();
	afx_msg void OnBnClickedButtonOpenExplorer();
};

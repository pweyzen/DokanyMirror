#pragma once
#include <string>

class CDokanyEvent;

class IDialogCallback
{
public:
	virtual void NotifyError(const std::wstring& msg) = 0;
	virtual void NotifyEvent(CDokanyEvent* pEvent) = 0;
};


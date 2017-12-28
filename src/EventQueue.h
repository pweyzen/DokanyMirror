#pragma once
#include <mutex>
#include <vector>
#include <string>


class CDokanyEvent
{
	static __int64	s_Sequence;

	std::wstring	m_Command;
	std::wstring	m_FileName;
	std::wstring	m_Comment;
	std::wstring	m_DokanyFlags;
	__int64			m_Context;
	__int64			m_TickCounter;
	__int64			m_SequenceNum;
	__int64			m_ProcessId;
	__int64			m_ThreadId;
	unsigned int	m_LastError;

public:
	CDokanyEvent( const std::wstring& command, const std::wstring& fileName, __int64 ContextId, __int64 ProcessId, __int64 ThreadId )
		:	m_Command(command), 
			m_FileName(fileName), 
			m_Context(ContextId),
			m_ProcessId(ProcessId),
			m_ThreadId(ThreadId),
			m_TickCounter(0),
			m_SequenceNum(0), 
			m_LastError(0)
	{
	}
	~CDokanyEvent() {}

	__int64 Sequence()
	{
		return m_SequenceNum;
	}
	__int64 TickCount()
	{
		return m_TickCounter;
	}
	void SetTickCount
	(__int64 t )
	{
		m_TickCounter = t;
	}
	const std::wstring& Command()
	{
		return m_Command;
	}
	const std::wstring& FileName()
	{
		return m_FileName;
	}
	static void ResetCounters()
	{
		s_Sequence = 0;
	}
	void InitSequence()
	{
		m_SequenceNum = ++s_Sequence;
	}

	static bool _MatchStrings(const std::wstring& str, const std::wstring& term)
	{
		return (str.find(term) != std::wstring::npos);
	}
	virtual bool Match(const std::wstring& searchTerm) const
	{
		if (_MatchStrings(m_Command, searchTerm))
			return true;
		if (_MatchStrings(m_FileName, searchTerm))
			return true;
		if (_MatchStrings(m_Comment, searchTerm))
			return true;

		__int64 iSearchTerm = _wtoi64(searchTerm.c_str());

		if (m_ProcessId != 0 && m_ProcessId == iSearchTerm )
			return true;
		if (m_Context != 0 && m_Context == iSearchTerm )
			return true;
		if (m_ThreadId  != 0 && m_ThreadId == iSearchTerm)
			return true;
		if (m_TickCounter  != 0 && m_TickCounter == iSearchTerm)
			return true;

		return false;
	}
	__int64 ProcessId()
	{
		return m_ProcessId;
	}
	__int64 ThreadId()
	{
		return m_ThreadId;
	}
	__int64 ContextId()
	{
		return m_Context;
	}
	void SetComment(const std::wstring& s)
	{
		m_Comment = s;
	}
	void SetContext(__int64 ctx)
	{
		m_Context = ctx;
	}
	void AddComment(const std::wstring& s)
	{
		m_Comment += L" {";
		m_Comment += s;
		m_Comment += L"}";
	}
	void AddDokanyFlag
	(bool b, wchar_t f)
	{
		if (b)
		{
			m_DokanyFlags += f;
		}
	}
	const std::wstring& DokanyFlags()
	{
		return m_DokanyFlags;
	}
	const std::wstring& Comment()
	{
		return m_Comment;
	}
};



class CEventQueue
{
	static CEventQueue* m_pSingleton;
	std::recursive_mutex	m_Lock;

public:
	typedef std::vector<CDokanyEvent*>	tEventList;

private:
	size_t		m_MaxSize;
	__int64		m_Sequence;
	tEventList  m_Events;
	bool		m_Enabled;

public:
	CEventQueue(size_t maxSize = 50000 );
	~CEventQueue();

	static CEventQueue* Get()
	{
		return m_pSingleton;
	}

	void Enable()
	{
		m_Enabled = true;
	}
	void Disable()
	{
		m_Enabled = false;
	}
	bool GetEnabled() const
	{
		return m_Enabled;
	}

	void GetEvents(tEventList& l, int iStart =-1, int numEvents = -1 );
	bool AddEvent(CDokanyEvent* pEvent, bool forced = false);
	void Reset();

	void GetFilteredEvents(const std::wstring& filterString, tEventList& l );

	static void MatchEvents(const tEventList& in, tEventList& out, const std::wstring& searchTerm);

private:
	tEventList::iterator Locked_Erase(tEventList::iterator& i);
	void Locked_Trim();
};

__inline CEventQueue* g_Queue()
{
	return CEventQueue::Get();
}


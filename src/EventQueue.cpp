#include "stdafx.h"
#include "EventQueue.h"
#include <algorithm>
#include <mutex>

__int64 CDokanyEvent::s_Sequence = 0;
CEventQueue* CEventQueue::m_pSingleton = NULL;

CEventQueue::CEventQueue( size_t maxEvents )
	: m_MaxSize(maxEvents)
{
	m_pSingleton = this;
}

CEventQueue::~CEventQueue()
{
	Reset();
}

bool CEventQueue::AddEvent(CDokanyEvent* pE, bool forced )
{
	if (m_Enabled || forced)
	{
		pE->InitSequence();

		std::lock_guard<std::recursive_mutex> lock(m_Lock);
		m_Events.push_back(pE);

//		Locked_Trim();
		return true;
	}

	return false;
}

void CEventQueue::GetEvents(tEventList& l, int iStart, int numEvents )
{
	std::lock_guard<std::recursive_mutex> lock(m_Lock);

	if (iStart == -1 || numEvents == -1 )
	{
		l = m_Events;
	}
	else
	{
		l.clear();
		for (int idx = iStart; idx < (iStart + numEvents); ++idx)
		{
			l.push_back( m_Events[idx] );
		}
	}
}

void CEventQueue::Reset()
{
	std::lock_guard<std::recursive_mutex> lock(m_Lock);
	for (tEventList::iterator iter = m_Events.begin(); iter != m_Events.end(); ++iter)
	{
		delete (*iter);
	}
	m_Events.clear();

	CDokanyEvent::ResetCounters();
}

void CEventQueue::GetFilteredEvents(const std::wstring& filterString, tEventList& l)
{
	for (tEventList::iterator iter = m_Events.begin(); iter != m_Events.end(); ++iter)
	{
		CDokanyEvent* pEvent = (*iter);
		if (pEvent->Match(filterString) )
		{
			l.push_back(pEvent);
		}
	}
}

void CEventQueue::MatchEvents(const tEventList& in, tEventList& out, const std::wstring& searchTerm)
{
	for (tEventList::const_iterator iter = in.begin(); iter != in.end(); ++iter)
	{
		if ((*iter)->Match(searchTerm))
		{
			out.push_back((*iter));
		}
	}
}

CEventQueue::tEventList::iterator CEventQueue::Locked_Erase(CEventQueue::tEventList::iterator& i)
{
	delete (*i);
	return m_Events.erase(i);
}

void CEventQueue::Locked_Trim()
{
	if (m_Events.size() > (m_MaxSize + 100))
	{
		while (m_Events.size() > m_MaxSize)
		{
			Locked_Erase(m_Events.begin());
		}
	}
}

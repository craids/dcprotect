
#include "OutputBuffer.h"

namespace PeLib
{
	OutputBuffer::OutputBuffer(std::vector<unsigned char>& vBuffer) : m_vBuffer(vBuffer)
	{
		m_vBuffer.clear();
	}

	const unsigned char* OutputBuffer::data() const
	{
		return &m_vBuffer[0];
	}

	unsigned long OutputBuffer::size()
	{
		return static_cast<unsigned long>(m_vBuffer.size());
	}

	void OutputBuffer::add(const char* lpBuffer, unsigned long ulSize)
	{
		std::copy(lpBuffer, lpBuffer + ulSize, std::back_inserter(m_vBuffer));
	}

	void OutputBuffer::reset()
	{
		m_vBuffer.clear();
	}
}

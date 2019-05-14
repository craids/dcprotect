#ifndef INPUTBUFFER_H
#define INPUTBUFFER_H

#include <vector>
#include <iterator>
#include <cassert>

namespace PeLib
{
	class InputBuffer
	{
		private:
		  std::vector<unsigned char>& m_vBuffer;
		  unsigned long ulIndex;
		  
		public:
		  InputBuffer(std::vector<unsigned char>& vBuffer);
		  
		  const unsigned char* data() const;
		  unsigned long size();

		  template<typename T>
		  InputBuffer& operator>>(T& value)
		  {
			assert(ulIndex + sizeof(value) <= m_vBuffer.size());
			value = *(T*)(&m_vBuffer[ulIndex]);//reinterpret_cast<T*>(&m_vBuffer[ulIndex]);
			ulIndex += sizeof(T);
			return *this;
		  }

		  void read(char* lpBuffer, unsigned long ulSize);
		  void reset();
		  void set(unsigned long ulIndex);
		  unsigned long get();
		  void setBuffer(std::vector<unsigned char>& vBuffer);
//		  void updateData(unsigned long ulIndex,
	};
}

#endif

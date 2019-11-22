#include "writer.h"
#include <iomanip>
#include <iostream>
#include <cstdio>
#include <sstream>

std::string & writer::offset( uint32_t offset )
{
    std::stringstream tmp;
    tmp << std::setfill('0') << std::setw(8) << std::hex << offset;
    return m_offset = tmp.str();
}

std::string & writer::bytecode()
{
    std::stringstream tmp;
    tmp << std::setfill(' ') << std::setw(BYTECODE_MAX_LENGHT) << std::left << " ";
    return m_bytecode = tmp.str();
}

std::string & writer::bytecode(const uint8_t *src, size_t len)
{
    std::stringstream tmp;
    
    char	pcHEX[3];
    
    const uint8_t *src_ptr = src; 
    std::string dots = "...";
    std::string delimeter = " ";
    
    if ( len )
    {
        uint32_t max_length = BYTECODE_MAX_LENGHT;
        //FIXME magic number for more beautiful layout
        max_length -= dots.length() + 3;
        
        for (uint32_t i=0; i<len; ++i)
        {
            
            if ( m_bytecode.length() >= max_length )
            {
                m_bytecode += dots;
                break;
            }
            else
            {	
                if ( i == len - 1 )
                    delimeter = "";
                snprintf(pcHEX, sizeof(pcHEX), "%02X", src_ptr[i]);
                m_bytecode += pcHEX + delimeter;
            }
        }
        
        tmp << std::setfill(' ') << std::setw(BYTECODE_MAX_LENGHT) << std::left << m_bytecode;
        return m_bytecode = tmp.str();
        
    }
    
    return m_bytecode;   
}

std::string & writer::instructions( const char *format, ... )
{
    std::string result;
    va_list args;
    
    va_start(args, format);
    
    result = _do_format(format, args);
    
    va_end(args);
    
    std::stringstream tmp;
    tmp << std::setfill(' ') << std::setw(INSTRUCTIONS_MAX_LEN) << std::left << result;
    
    return m_instructions = tmp.str();
}

std::string & writer::comment( const char *format, ... )
{
    std::string result;
    va_list args;
    
    va_start(args, format);
    
    result = _do_format(format, args);
    
    va_end(args);
    
    return m_comment = result;

}

std::string writer::_do_format(const char* format, va_list vlist)
{
    std::string result;
    va_list args, args_size;
    
    va_copy(args, vlist);
    va_copy(args_size, args);
    
    size_t size_required = std::vsnprintf(nullptr, 0, format, args_size) + 1;
    result.resize( size_required );
    va_end(args_size);
    
    // ok for C++11
    std::vsnprintf((char*)( result.data() ), result.size(), format, args);
    va_end(args);
    
    return result;
}

void writer::clear()
{
    m_offset.clear();
    m_bytecode.clear();
    m_instructions.clear();
    m_comment.clear();
}

void writer::print()
{
    std::cout << link() << std::endl;
};

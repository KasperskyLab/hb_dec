#pragma once

#include <string>
#include <cstdarg>

extern "C"
{
#include <stdint.h>
}

class writer
{
public:
    std::string m_offset;
    std::string m_bytecode;
    std::string m_instructions;
    std::string m_comment;
    
    size_t BYTECODE_MAX_LENGHT = 30;
    size_t INSTRUCTIONS_MAX_LEN = 30;
    
    std::string & offset( uint32_t offset );
    std::string & bytecode();
    std::string & bytecode( const uint8_t *src, size_t len);
    
    std::string & instructions( const char *format=" ", ...  );
    std::string & comment( const char *format, ... );
    std::string link()    { return m_offset + std::string("  ") + m_bytecode + m_instructions + m_comment; }
    void print();
    
    void clear();
private:
    std::string _do_format(const char* format, va_list vlist);
};

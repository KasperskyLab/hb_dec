/*
 * Copyright (C) 2019  AO Kaspersky Lab
 * This program is free software; you can redistribute it and/or modify it under 
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with 
 * this program; if not, write to the Free Software Foundation, 
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */ 

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

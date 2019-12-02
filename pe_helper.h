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

#pragma pack(push,1)
//wine sourses proper work with PE structure
#include "include/wine/windef.h"
#undef __CRT_UUID_DECL

#include <stdint.h>
#include <sys/stat.h>
#include <string>

class ExeState
{
public:
    uint8_t        *filename;
	int            fd = -1;
    bool           file_read = false;
	struct stat    sb;
	std::string    _base = "";
	IMAGE_DOS_HEADER       *dos;
	IMAGE_NT_HEADERS32     *pe;
	IMAGE_SECTION_HEADER   *sections;
	
    ExeState( uint8_t* filename );
    ~ExeState();
    
    bool close_file();
    bool read_new_file( uint8_t* filename );
    
    uint8_t * base()
    {
        return (file_read ? (uint8_t *)(_base.data()) : 0);
    }
    
    uint32_t rva_to_raw( uint32_t rva, bool relative = true );
    uint32_t va_to_raw( uint32_t va );
    
    uint32_t raw_to_rva( uint32_t raw, bool relative = true );
    uint32_t raw_to_va( uint32_t raw );
    
    uint32_t rva_to_va( uint32_t va );
    
    IMAGE_SECTION_HEADER * find_section( const std::string section_name );
};

#pragma pack(pop)

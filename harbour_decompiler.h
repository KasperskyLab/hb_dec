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

#include "harbour_helper.h"
#include <stdint.h>

#include "writer.h"

/* disassembler part */
class harbour_decompiler
{
public:
    executable_hb &m_hb_ctx;
    writer        m_writer;
    size_t        m_offset;
    
    harbour_decompiler(executable_hb &hb_ctx ) :m_hb_ctx(hb_ctx)
                                               ,m_offset(0)
    {}
    void function_decompile(executable_hb_symbol *hb_symb_and_pcode);
};

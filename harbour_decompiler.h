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

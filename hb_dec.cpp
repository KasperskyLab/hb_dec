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

//order here is quite important
#include "pe_helper.h"
#include "harbour_helper.h"
#include "harbour_decompiler.h"


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <iostream>

int main(int argc, char **argv)
{
	if ( argc == 1 )
    {
        printf("usage: %s <hb_executable>\n", argv[0] );
        return 1;
    }
    
    ExeState state( (uint8_t*)( argv[1]) );
    
    if ( !state.file_read )
        return 1;
    
	executable_hb  hb_ctx( state );
    
    if ( *(uint16_t*)state.base() != 0x5A4D )
	{
		printf("it is not PE file\n");
		return 1;
	}
    
    printf("e_magic : %x\n", state.dos->e_magic );
    printf("e_lfanew(PE) : %x\n", state.dos->e_lfanew );
    
    if ( state.pe->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 )
	{
		std::cout << "it is not I386 binary, we are not ready to work with it yet" << std::endl;
		exit(0);
	}
    
    printf( "OptionalHeader.AddressOfEntryPoint: %X\n", state.pe->OptionalHeader.AddressOfEntryPoint);
    printf( "OptionalHeader.ImageBase: %X\n", state.pe->OptionalHeader.ImageBase);
    printf( "\n");
    
    if ( hb_ctx.find_hb_source_name() ) 
        std::cout << "Found hb source filename: " << hb_ctx.hb_source_name << std::endl;
    else
        std::cout << "Found hb source filename not found" << std::endl;
    
    uint32_t first_hb_symb_offset_raw = hb_ctx.pe_find_hb_symbols_table();
    if ( !first_hb_symb_offset_raw )
    {
        std::cout << "hb symbols find error " << std::endl;
        return 1;
    }
    
    if ( !hb_ctx.pe_read_hb_symbols_table(first_hb_symb_offset_raw) )
    {
        std::cout << "hb symbols read error: " << hb_ctx.hb_source_name << std::endl;
        return 1;
    }
	
	/* store pcode and size */
	hb_ctx.hb_symbols_fill_pcode();
    
    harbour_decompiler decompiler( hb_ctx );
    
    for (auto const& symbol : hb_ctx.hb_symbols_functions_sorted)
    {
        printf("PCODE for local function %s pcode size %zX\n\n", symbol->Name(), symbol->pcode_size);
        if ( symbol->pcode_size )
            decompiler.function_decompile(symbol);
    }
    
    return 0;
}

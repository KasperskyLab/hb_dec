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

#include "harbour_helper.h"

#include <cstring>
    
executable_hb_symbol::executable_hb_symbol(const char* name, intptr_t scope, intptr_t value, intptr_t dynsym)
{
    this->szName = 0;
    this->scope.value = 0;
    this->value.pCodeFunc = 0;
    this->pDynSym = 0;
    
    Name( name );
    Scope( scope );
    Value( value );
    DynSym( dynsym );
}
    
executable_hb_symbol::~executable_hb_symbol()
{
    if ( szName )
        free( (void*)szName );
}

/*there might be a leak, once you will edit the name for one hb_symbol, but this case never used */
const char * executable_hb_symbol::Name( const char* newName )
{
    if ( szName )
    {
        //free((void*)szName);
        szName = 0;
    }
    
    if ( newName )
    {
        uint32_t name_size = strlen(newName);
        char * tmp = reinterpret_cast<char*>( calloc( 1, name_size + 1 ) );
        memcpy(tmp, newName, name_size);
        szName = tmp;
    }
    else
    {
        szName = 0;
    }
    
    return szName;
}
    
void executable_hb_symbol::print_scope()
{
    const char *delimeter= "";
    uint16_t scope = Scope();
    
    if ( scope & HB_FS_PUBLIC )
    {
        printf("%sHB_FS_PUBLIC", delimeter);
        delimeter = " | ";
    }
    
    if ( scope & HB_FS_STATIC )
    {
        printf("%sHB_FS_STATIC", delimeter);
        delimeter = " | ";
    }
    
    if ( scope & HB_FS_FIRST )
    {
        printf("%sHB_FS_FIRST", delimeter);
        delimeter = " | ";
    }
    
    if ( scope & HB_FS_INIT )
    {
        printf("%sHB_FS_INIT", delimeter);
        delimeter = " | ";
    }
    
    if ( scope & HB_FS_EXIT )
    {
        printf("%sHB_FS_EXIT", delimeter);
        delimeter = " | ";
    }
    
    if ( scope & HB_FS_MESSAGE )
    {
        printf("%sHB_FS_MESSAGE", delimeter);
        delimeter = " | ";
    }
    
    if ( scope & HB_FS_MEMVAR )
    {
        printf("%sHB_FS_MEMVAR", delimeter);
        delimeter = " | ";
    }
    
    if ( scope & HB_FS_PCODEFUNC )
    {
        printf("%sHB_FS_PCODEFUNC", delimeter);
        delimeter = " | ";
    }
    if ( scope & HB_FS_LOCAL )
    {
        printf("%sHB_FS_LOCAL", delimeter);
        delimeter = " | ";
    }
    if ( scope & HB_FS_DYNCODE )
    {
        printf("%sHB_FS_DYNCODE", delimeter);
        delimeter = " | ";
    }
    if ( scope & HB_FS_DEFERRED )
    {
        printf("%sHB_FS_DEFERRED", delimeter);
        delimeter = " | ";
    }
    if ( scope & HB_FS_FRAME )
    {
        printf("%sHB_FS_FRAME", delimeter);
        delimeter = " | ";
    }
    if ( scope & HB_FS_USED )
    {
        printf("%sHB_FS_USED", delimeter);
        delimeter = " | ";
    }
}

/* executable parser harbour helper */

executable_hb::executable_hb( ExeState &exe_state )
{
    executable_hb::exe_state = &exe_state;
    BCC=false;
    MINGW=false;
}

executable_hb::~executable_hb()
{
    for ( auto hb_symbol : hb_symbols )
        delete hb_symbol;
}


bool executable_hb::find_hb_source_name()
{      
    //try to guess a name of a harbour source file, usually it is the first 
    uint8_t *src_name_search = (uint8_t*)memmem(
                                                (void*)exe_state->base(),
                                                exe_state->sb.st_size,
                                                (void*)hb_source_name_search_key.c_str(),
                                                hb_source_name_search_key.length()+1
                                                );
    
    if ( src_name_search )
    {
        uint8_t *src_ptr = (uint8_t*)src_name_search;
        uint32_t src_name_len = 0;
        
        //FIXME may be an errors here :)
        while ( *(--src_ptr) != 0 )
        {
            ++src_name_len;
        }
        src_name_search = src_name_search - src_name_len;
        src_name_len += 4; // .prg
        
        hb_source_name.assign((char*)src_name_search, src_name_len);
        
        return true;
    }
    
    return false;
}

/* quite dirty here, but it works... */
uint32_t executable_hb::pe_find_hb_symbols_table()
{
    uint32_t hb_symbols_table_raw_offset = 0;
    
    //we start from finding CPPdebugHook offset
    void * cpp_debug_hook_offset = memmem((void*)exe_state->base(), exe_state->sb.st_size, (void*)bcc_hook_name.c_str(), bcc_hook_name.length());
    
    if ( cpp_debug_hook_offset )
    {
        printf("This program most likely compiled by BCC\n");
        uint8_t BCC_usual_padding_after_debug_hook = 12;
        /* 
        * approximate data structure for BCC harbour executables.
        * 0	CPPdebugHook
        * 4	0000
        * 8	0000
        * C	HB_SYMB structure NAME offset
        * 10	HB_SYMB structure SCOPE value
        * 14	HB_SYMB structure VALUE offset (if scope HB_FS_LOCAL (0x200) than this points to eval function, 
        * 		eval fuction knows where it's pcode starts)
        * 18	HB_SYMB structure pDynSym offset
        * .......maybe a lot of functions
        * 1C	offset to the first HB_SYMB structure 0xC if our case
        * 20	PCODE (precompiled code) section blob, all local functions ( defined by a programmer) are here.
        * ....variable length
        * ??	PCODE section end up with a function name string "MAIN"(usually), the string name of first symbol in 
        * table ( HB_SYMB structure NAME offset pointing to it )
        * 
        */
        BCC = true;
        
        // take a VA right after BCC hook name
        uint32_t *CPPdebugHook_va_address = (uint32_t*)((uint8_t*)cpp_debug_hook_offset + bcc_hook_name.length());
        
        uint32_t CPPdebugHook_offset_raw = exe_state->va_to_raw(*CPPdebugHook_va_address);
        printf("\tCPPdebugHook_offset_raw : %x\n", CPPdebugHook_offset_raw);
        uint32_t  *CPPdebugHook_offset_ptr = (uint32_t*)(exe_state->base() + CPPdebugHook_offset_raw);
        
        if ( CPPdebugHook_offset_ptr[0] + CPPdebugHook_offset_ptr[1] + CPPdebugHook_offset_ptr[2] != 0 )
        {
            printf("\tusual zero padding not found (%X %X %X)\n"
                        , CPPdebugHook_offset_ptr[0]
                        , CPPdebugHook_offset_ptr[1]
                        , CPPdebugHook_offset_ptr[2]);
            return 0;
        }
        else
        {
            printf("\tusual zero padding found (%X %X %X)\n"
                        , CPPdebugHook_offset_ptr[0]
                        , CPPdebugHook_offset_ptr[1]
                        , CPPdebugHook_offset_ptr[2]);
        }
        
        //hb symbols table usually in constant padding;
        hb_symbols_table_raw_offset = CPPdebugHook_offset_raw + BCC_usual_padding_after_debug_hook;
        
        return hb_symbols_table_raw_offset;
    }
    
    //try MINGW case
    printf("Cheсking if this program compiled by MINGW\n");
    
    uint8_t MINGW_usual_padding_to_symbols_table = 0x20;
    
    // checking MINGW hb symbols table template
    auto data_section = exe_state->find_section(".data");
    if ( data_section == nullptr )
    {
        printf("\t.data section not found\n");
        return 0;
    }
    else
        printf("\t.data section found\n");
    
    uint32_t *_data_start_raw_offset = (uint32_t*)( exe_state->base() + data_section->PointerToRawData );
    uint32_t _data_start_va = exe_state->rva_to_va( data_section->VirtualAddress );
    
    //usuall padding check(data section might have different start, try to guess the symbols table offset)
    size_t i = 20;
    while ( (*_data_start_raw_offset - _data_start_va != MINGW_usual_padding_to_symbols_table) )
    {
        _data_start_raw_offset = (uint32_t*)( exe_state->base() + data_section->PointerToRawData + i*sizeof(uint32_t) );
        
        _data_start_va =  exe_state->raw_to_va( data_section->PointerToRawData + i*sizeof(uint32_t) );
        
        if ( --i == 0 )
            return 0;
    }
    
    if ( *_data_start_raw_offset - _data_start_va != MINGW_usual_padding_to_symbols_table )
    {
        printf("\tusual padding size missmatch (%X!=%X)\n", MINGW_usual_padding_to_symbols_table, (*_data_start_raw_offset - _data_start_va));
        return 0;
    }
    else
    {
        printf("\tusual padding size correct (%X==%X)\n", MINGW_usual_padding_to_symbols_table, (*_data_start_raw_offset - _data_start_va));
        //TODO check it padding are zeroes
        
        printf("\tyes, it is MINGW\n");
        MINGW = true;
    }
    
    hb_symbols_table_raw_offset = exe_state->va_to_raw(*_data_start_raw_offset);
    return hb_symbols_table_raw_offset;
}

bool executable_hb::pe_read_hb_symbols_table(uint32_t hb_symbols_table_raw_offset)
{
    uint32_t hb_symbols_table_va = exe_state->raw_to_va(hb_symbols_table_raw_offset);
    
    printf("hb_symbols_table_va : %x\n", hb_symbols_table_va );
    printf("hb_symbols_table_raw_offset : %x\n", hb_symbols_table_raw_offset);
    printf( "\n");
    
    uint32_t *hb_symb_ptr = (uint32_t*)( exe_state->base() + hb_symbols_table_raw_offset );
    uint32_t first_hb_symb_name_offset = 0;
    
    uint32_t symbols_num = 0;
    
    while ( 1 )
    {
        //TODO more accurate here
        if ( hb_symb_ptr[0] + hb_symb_ptr[1] + hb_symb_ptr[2] + hb_symb_ptr[3] == 0 ) //mingw
            break;
        if ( hb_symb_ptr[0] == 0) //mingw
            break;
        if ( hb_symb_ptr[0] == hb_symbols_table_va ) // bcc
            break;
        if ( exe_state->va_to_raw( hb_symb_ptr[0] ) == 0 ) //conversion error
            break;
        
        auto hb_symb_pcode = create_hb_symbol();
        //zero terminated name
        uint8_t *name_ptr = exe_state->base() + exe_state->va_to_raw( hb_symb_ptr[0] ); 
        
        if ( first_hb_symb_name_offset == 0 ) // save it because it used as a pcode terminator 
        {
            first_hb_symb_name_offset = hb_symb_ptr[0];
        }
        
        hb_symb_pcode->Name( reinterpret_cast<char*>( name_ptr ) );
        
        hb_symb_pcode->Scope( hb_symb_ptr[1] );
        hb_symb_pcode->Value( hb_symb_ptr[2] );
        hb_symb_pcode->DynSym( hb_symb_ptr[3] );
        
        printf("hb_symb #%d\n\tname:\t\t%s\n", symbols_num++, hb_symb_pcode->Name());
        printf("\tscope.value:\t%x ", hb_symb_pcode->Scope());
        printf("[ ");
        hb_symb_pcode->print_scope();
        printf(" ]\n");
        printf("\tvalue.pFunPtr:\t%lx\n",(uintptr_t)( hb_symb_pcode->Value() ) );
        printf("\tpDynSym:\t%lx\n===\n", (uintptr_t)( hb_symb_pcode->DynSym() ) );
        
        
        if ( hb_symb_pcode->is_symbol_function() ) // user defined local functions, must have it's pcode
        {
            //what size? we dont know yet
            uint8_t *ev_func = exe_state->base() + exe_state->va_to_raw( reinterpret_cast<intptr_t>( hb_symb_pcode->Value() ) );
            
            if ( ev_func[0] == 0xA1 && ev_func[5] == 0x50 && ev_func[6] == 0x68 )
            {//BCC function pattern, function that holds offset to start of PCODE
                uint32_t pcode_offset = *(uint32_t* )(ev_func + 7); //FIXME: magic numbers
                
                printf("\tpcode offset %x for local function %s\n===\n", pcode_offset, hb_symb_pcode->Name() );
                                
                hb_symb_pcode->pcode_va_start = pcode_offset;
                hb_symb_pcode->pcode_va_end = first_hb_symb_name_offset;
            }
            
            if ( ev_func[0] == 0x83 && ev_func[3] == 0xA1 && ev_func[8] == 0xC7 )
            {//mingw function pattern, function that holds offset to start of PCODE
                uint32_t pcode_offset = *(uint32_t* )(ev_func + 11);//FIXME: magic numbers
                
                printf("\tpcode offset %x for local function %s\n===\n", pcode_offset, hb_symb_pcode->Name() );
                
                hb_symb_pcode->pcode_va_start = pcode_offset;
                hb_symb_pcode->pcode_va_end = first_hb_symb_name_offset;
            }
        }
        
        hb_symb_ptr += 4;
    }
    
    return ( hb_symbols.size() ? true : false);
}

executable_hb_symbol * executable_hb::create_hb_symbol()
{
    executable_hb_symbol *new_hb_symbol = new executable_hb_symbol;
    
    hb_symbols.push_back(new_hb_symbol);
    
    return new_hb_symbol;
}

bool executable_hb::hb_symbols_fill_pcode()
{
    for (auto symbol_it = hb_symbols.begin(); symbol_it != hb_symbols.end(); ++symbol_it )
    {
        if ( (*symbol_it)->is_symbol_function() )
            hb_symbols_functions_sorted.push_back((*symbol_it));
    }
    
    //sort ascending pcode_va_start for proper calculating PCODE boundaries
    hb_symbols_functions_sorted.sort( symbol_va_compare );
    
    //calc sizes and fill pcode
    for (auto symbol_it = hb_symbols_functions_sorted.begin(); symbol_it != hb_symbols_functions_sorted.end(); ++symbol_it )
    {
        if ( symbol_it != std::prev( hb_symbols_functions_sorted.end() ) ) 
        {
            (*symbol_it)->pcode_va_end = ( * std::next( symbol_it ) )->pcode_va_start;
        }
        
        (*symbol_it)->pcode_size = (*symbol_it)->pcode_va_end - (*symbol_it)->pcode_va_start;
        
        const uint8_t *pcode_ptr = exe_state->base() + exe_state->va_to_raw( (*symbol_it)->pcode_va_start );
        
        while( pcode_ptr[ (*symbol_it)->pcode_size - 1 ] == 0 )
            --( (*symbol_it)->pcode_size );
        
        printf("found pcode for local function %s %X - %X = %zX\n", (*symbol_it)->Name(),
                                                                    (*symbol_it)->pcode_va_end,
                                                                    (*symbol_it)->pcode_va_start,
                                                                    (*symbol_it)->pcode_size);
        (*symbol_it)->pcode().assign(reinterpret_cast<const char*>( pcode_ptr ), (*symbol_it)->pcode_size);
    }
    printf("\n");
    
    return true;
}

bool executable_hb::symbol_va_compare( const executable_hb_symbol * elem1, const executable_hb_symbol * elem2 )
{
    return elem1->pcode_va_start < elem2->pcode_va_start;
}


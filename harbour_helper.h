#pragma once

#include "pe_helper.h"
#include "compat.h"

#include <stdint.h>

extern "C"
{
//harbour internals
#include "include/harbour/hbvmpub.h"
#include "include/harbour/hbpcode.h"
#include "include/harbour/hbpcode_awked.h"
#undef min
#undef max
};

#include <list>
#include <string>
#include <vector>

//harbour symbol class, updated to handle pcode
class executable_hb_symbol: public HB_SYMB
{
public:
	std::string m_pcode;
    uint32_t pcode_va_start;
	uint32_t pcode_va_end;
    size_t pcode_size;
    
    executable_hb_symbol( const char* name=0, intptr_t scope=0, intptr_t value=0, intptr_t dynsym=0 );
    
    ~executable_hb_symbol();
    
    const char * Name() { return szName; }
    const char * Name( const char* newName );
    
    uint16_t Scope() { return scope.value; }
    
    uint16_t Scope( uint16_t newScope ) { return scope.value = newScope; }
    
    void * Value( uint32_t newValue ) { return value.pCodeFunc = reinterpret_cast<void*>( newValue ); }
    void * Value( ) { return value.pCodeFunc ; }
    
    void * DynSym( uint32_t newDynSym ) { return pDynSym = reinterpret_cast<void*>( newDynSym ); }
    void * DynSym( ) { return pDynSym; }
    
    std::string & pcode()                       { return m_pcode; };
    
    std::string & pcode( std::string &pcode )     { return m_pcode = pcode; };
    
    bool is_symbol_function()
    {
        return ( ( (scope.value) & HB_FS_LOCAL ) ? true : false );
    }
    
    void print_scope();
    
};

/* executable parser harbour helper */
class executable_hb
{
public:
	ExeState *exe_state;
	
    bool BCC;
    bool MINGW;
    std::string hb_source_name;
	
	// all hb symbols in order they are placed in executable, so all pcode 
    // references while decompilation process will properly match
    std::vector<executable_hb_symbol*> hb_symbols;
	
	// sorted in executable VA address order, so we can easily calculate the PCODE boudary
	std::list<executable_hb_symbol*> hb_symbols_functions_sorted;
    
    executable_hb( ExeState &exe_state );
    
    ~executable_hb();
    
    bool find_hb_source_name();
    uint32_t pe_find_hb_symbols_table();
    bool pe_read_hb_symbols_table( uint32_t hb_symbols_table_raw_offset );
    
    executable_hb_symbol * create_hb_symbol();
    
    bool hb_symbols_fill_pcode();
    
private:
    const std::string hb_source_name_search_key = ".prg";
    const std::string bcc_hook_name = "fb:C++HOOK\x90\xE9";
    
    static bool symbol_va_compare( const executable_hb_symbol * elem1, const executable_hb_symbol * elem2 );
};

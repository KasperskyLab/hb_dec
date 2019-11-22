#include "pe_helper.h"
#include "compat.h"

#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <ctime>
#include <unistd.h>
#include <cstdio>
#include <string.h>


ExeState::ExeState( uint8_t* filename )
{
    read_new_file( filename );
}

ExeState::~ExeState()
{
    close_file();
}

bool ExeState::close_file()
{
    if ( file_read )
    {
        close(fd);
        fd = -1;
    }
    
    return true;
}

bool ExeState::read_new_file( uint8_t* filename )
{
    fd = open(reinterpret_cast<const char*>(filename), O_RDONLY| O_BINARY);
    
    if ( fd == -1 )
    {
        perror("open");
        return false;
    }
    
    if ( fstat(fd, &sb) == -1 )
    {
        perror("fstat");
        return false;
    }
    
    _base.resize(sb.st_size);
    
    read(fd, (void*)_base.data(), sb.st_size);
    file_read = true;
    
    close_file();
    
    dos = reinterpret_cast<IMAGE_DOS_HEADER*>( base() );
    
    pe = reinterpret_cast<IMAGE_NT_HEADERS32*>( base() + dos->e_lfanew );
    
    sections = reinterpret_cast<IMAGE_SECTION_HEADER*>( base() + dos->e_lfanew + sizeof(IMAGE_NT_HEADERS32) );
    
    return true;
}

uint32_t ExeState::rva_to_raw( uint32_t rva, bool relative )
{
    uint32_t	offset;
    uint32_t	size = 0;
    
    if ( !relative )
        rva -= pe->OptionalHeader.ImageBase;
    
    offset = rva;
    
    if ( rva < sections->PointerToRawData )
        return rva;
    
    for ( size_t i = 0; i < pe->FileHeader.NumberOfSections; i++ )
    {
        if ( sections[i].SizeOfRawData )
            size = sections[i].SizeOfRawData;
        else
            return 0;
        
        if ( rva >= sections[i].VirtualAddress && 
            rva < ( sections[i].VirtualAddress + size )
        )
        {
            if ( sections[i].PointerToRawData != 0 )
            {
                offset -= sections[i].VirtualAddress;
                offset += sections[i].PointerToRawData;
            }
            return offset;
        }
    }
    return 0;
}

uint32_t ExeState::va_to_raw( uint32_t va )
{
    return ExeState::rva_to_raw( va, false );
}

uint32_t ExeState::raw_to_rva( uint32_t raw, bool relative )
{
    uint32_t				offset = raw;
    uint32_t				size = 0;

    for (size_t i = 0; i < pe->FileHeader.NumberOfSections; i++)
    {
        if ( sections[i].SizeOfRawData )
            size = sections[i].SizeOfRawData;
        else
            return 0;

        if ( raw >= sections[i].PointerToRawData && 
            raw < ( sections[i].PointerToRawData + size )
        )
        {
            if ( sections[i].PointerToRawData != 0 )
            {
                offset -= sections[i].PointerToRawData;
                offset += sections[i].VirtualAddress;
                if ( !relative )
                    offset += pe->OptionalHeader.ImageBase;
            }
            return offset;
        }
    }
    return 0;
}

uint32_t ExeState::raw_to_va( uint32_t raw )
{
    return ExeState::raw_to_rva( raw, false );
}

uint32_t ExeState::rva_to_va( uint32_t va )
{
    return va + pe->OptionalHeader.ImageBase;
}

IMAGE_SECTION_HEADER * ExeState::find_section( const std::string section_name )
{
    for (size_t i = 0; i < pe->FileHeader.NumberOfSections; i++)
    {
        if ( memmem((const void*)(sections[i].Name), IMAGE_SIZEOF_SHORT_NAME , section_name.c_str(), section_name.length()) )
            return sections + i;
    }
    return nullptr;
}

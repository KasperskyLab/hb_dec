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

#include "harbour_decompiler.h"

#include <inttypes.h>

//yes, there is a lot of C here :)

void harbour_decompiler::function_decompile(executable_hb_symbol *hb_symb_and_pcode)
{
    const uint8_t *pcode_ptr = reinterpret_cast<const uint8_t*>( hb_symb_and_pcode->pcode().c_str() );
    const uint8_t *pcode_base = pcode_ptr;
    
    uint32_t bytecode_len = 0;
    uint8_t* bytecode = 0;
    uint32_t offset= m_offset;
    
    while (1)
    {
        m_writer.offset(offset);
        
        if ( *pcode_ptr < HB_P_LAST_PCODE )
        {
            bytecode_len = hb_comp_pcode_len[ *pcode_ptr ];
            
            /* keep in mind that opcodes has zero bytecode_len, it must be calculated additionaly*/
            m_writer.bytecode(pcode_ptr, bytecode_len);
        }
        
        switch ( *pcode_ptr )
        {
            /*TODO add more handlers,
             * find uncovered opcode marked as '<= !';
             * find its name and text description in /include/harbour/hbpcode.h file;
             * find handler function in /src/vm/hvm.c file, see what is done there to implement proper description and action with opcode parameters;
             */
            case HB_P_ARRAYPUSH: // 0x1 1
            {
                m_writer.instructions("<ARRAY INDEX> = pop()");
                m_writer.print();
                m_writer.clear();
                
                m_writer.offset(offset);
                m_writer.bytecode();
                m_writer.instructions("<ARRAY obj> = pop()");
                m_writer.print();
                m_writer.clear();
                
                m_writer.offset(offset);
                m_writer.bytecode();
                m_writer.instructions("push <ARRAY obj>[<ARRAY INDEX>]");
                m_writer.comment("/* push value from INDEX of ARRAY object variable to stack*/");
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                
                break;
            }
            case HB_P_ARRAYPOP: // 0x2 2
            {
                m_writer.instructions("<ARRAY INDEX> = pop()");
                m_writer.comment("/* mov value from stack to INDEX of ARRAY object variable*/");
                m_writer.print();
                m_writer.clear();
                
                m_writer.offset(offset);
                m_writer.bytecode();
                m_writer.instructions("<ARRAY obj> = pop()");
                m_writer.print();
                m_writer.clear();
                
                m_writer.offset(offset);
                m_writer.bytecode();
                m_writer.instructions("<ARRAY obj>[<ARRAY INDEX>] = pop()");
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
            
                break;
            }
            //case HB_P_ARRAYDIM: // 0x3 3
            case HB_P_ARRAYGEN: // 0x4 4 
            {
                m_writer.instructions("push <new ARRAY obj> = pop(%d)", *(uint16_t*)(pcode_ptr+1));
                m_writer.comment("/* creating an ARRAY object and pushing %d elements from stack */", *(uint16_t*)(pcode_ptr+1));
                
                m_writer.print();
                
                m_writer.clear();
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_EQUAL: // 0x5 5
            {
                m_writer.instructions("push ( pop() == pop()");
                m_writer.comment("/* compare last two params (param == param1) */");
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_ENDBLOCK: // 0x6 6
            {
                m_writer.instructions("ret");
                m_writer.comment("/* end of CODEBLOCK */");
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_ENDPROC: // 0x07 7
			{
				m_writer.instructions("end proc");
				m_writer.print();
                m_writer.clear();
				
				pcode_ptr += bytecode_len;
				offset += bytecode_len;
				break;
			}
            case HB_P_EXACTLYEQUAL: // 0x8 8
            {
                m_writer.instructions("push ( pop() == pop() )");
                m_writer.comment("/* compare last two params (param == param1) */");
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_FALSE: // 0x9 9
            {
                m_writer.instructions("push FALSE");
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            //case HB_P_FORTEST: // 0xA 10
            //case HB_P_FUNCTION: // 0xB 11
            case HB_P_FUNCTIONSHORT: // 0x0C 12
            {// it executes a function by name previosly pushed to the stack, for function params see an example below
             // CALL 0 - calls a previosly pushed function
             // CALL 1 - calls te function stack[1] and stack[0] will be a function parameter
                m_writer.instructions("call %X", pcode_ptr[1] );
                m_writer.comment("/* call a function from stack saving its result */");
                m_writer.print(); 
                m_writer.clear();
                
                m_writer.offset(offset);
                m_writer.bytecode();
                m_writer.instructions("push eax");
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                
                break;
            }
            case HB_P_FRAME: //0xD 13
            {
                m_writer.instructions();
                
                m_writer.comment("/* function frame has %d locals and %d parameters */", pcode_ptr[1], pcode_ptr[2]);
                
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            //case HB_P_FUNCPTR: //0xE 14
            case HB_P_GREATER: // 0xF 15
            {
                m_writer.instructions("push ( pop() > pop() )");
                m_writer.comment("/* compare last two params (param > param1)  */");
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            //case HB_P_GREATEREQUAL: // 0x10 16
            case HB_P_DEC: // 0x11 17
            {
                m_writer.instructions("push --pop()");
                m_writer.comment("/* decrements lats stack value*/");
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
            
                break;
            }
            case HB_P_DIVIDE: // 0x12 18
            {
                m_writer.instructions("push ( pop() / pop() )");
                m_writer.comment("/* divides the latest two values on the stack, removing them and leaving the result param1 / param */");
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            //case HB_P_DO: // 0x13 19
            case HB_P_DOSHORT: // 0x14 20
			{
				m_writer.instructions("call %X", pcode_ptr[1]);
				
				m_writer.comment("/* call a function from STACK[-%d] and discard the results */", pcode_ptr[1]);
				
                m_writer.print();
                m_writer.clear();
                
				pcode_ptr += bytecode_len;
				offset += bytecode_len;
				break;
				
			}
            case HB_P_DUPLICATE: // 0x15 21 
            {
                m_writer.instructions("push STACK[-1]");
                m_writer.comment("/* push copy of prev value one more time */");
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            //case HB_P_PUSHTIMESTAMP: // 0x16 22
            case HB_P_INC: // 0x17 23
            {
                m_writer.instructions( "push ++pop()");
                m_writer.comment("/* increments last stack value*/");
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
            
                break;
            }
            case HB_P_INSTRING: //0x18 24
            {
                m_writer.instructions("push ( strstr( pop(), pop() ) > 0 )");
                m_writer.comment("/* checks if last(-2) stack value is a substring of the latest one */");
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                
                break;
            }
            case HB_P_JUMPNEAR: //0x19 25
            {
                m_writer.instructions("jmp near %X", offset + (signed char)(pcode_ptr[1]) );
                m_writer.comment("/* jump to EIP + ( %d ) = %X )*/",*(signed char *)(pcode_ptr + 1), offset + ( (signed char)(pcode_ptr[1]) ) );
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_JUMP: // 0x1A 26
            {
                m_writer.instructions("jmp %X", offset + ( *(int16_t*)(pcode_ptr + 1) ) );
                m_writer.comment("/* jump to EIP + ( %d ) = %X )*/",*(int16_t *)(pcode_ptr + 1), offset + ( *(int16_t*)(pcode_ptr + 1) ) );
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            //case HB_P_JUMPFAR: // 0x1B 27
            case HB_P_JUMPFALSENEAR: // 0x1C 28
            {
                m_writer.instructions("jmp %X if ( ! pop() ) ", offset + ( (signed char)(pcode_ptr[1]) ));
                m_writer.comment("/* jump on FALSE to EIP + ( %d ) = %X ) */",*(signed char *)(pcode_ptr + 1), offset + ( (signed char)(pcode_ptr[1]) ) );
                
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                
                break;
            }
            case HB_P_JUMPFALSE: // 0x1D 29
            {
                m_writer.instructions("jmp %X if ( ! pop() ) ", offset + ( *(int16_t*)(pcode_ptr+1) ) );
                m_writer.comment("/* jump on previous stack FALSE value to EIP + ( %d ) = %X ), if (not BOOL) -> jmp*/",*(int16_t*)(pcode_ptr + 1), offset + ( *(int16_t*)(pcode_ptr+1) ) );
                
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                
                break;
            }
            //case HB_P_JUMPFALSEFAR: // 0x1E 30
            case HB_P_JUMPTRUENEAR: // 0x1F 31
            {
                m_writer.instructions("jmp %X if ( pop() )", offset + ( (signed char)(pcode_ptr[1]) ));
                m_writer.comment("/* jump on TRUE to EIP + ( %d ) = %X )*/",*(signed char *)(pcode_ptr + 1), offset + ( (signed char)(pcode_ptr[1]) ) );
                
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                
                break;
            }
            case HB_P_JUMPTRUE: // 0x20 32
            {
                m_writer.instructions("jmp %X if ( pop() )", offset + ( *(int16_t*)(pcode_ptr + 1) ));
                m_writer.comment("/* jump on TRUE to EIP + ( %d ) = %X )*/", *(int16_t*)(pcode_ptr + 1), offset + ( *(int16_t*)(pcode_ptr + 1) ) );
                
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                
                break;
            }
            //case HB_P_JUMPTRUEFAR: // 0x21 33
            //case HB_P_LESSEQUAL: // 0x22 34
            case HB_P_LESS: // 0x23 35
            {
                m_writer.instructions("push ( pop() < pop() )");
                m_writer.comment("/* compare last two params (param < param1) */");
                
                m_writer.print();
                m_writer.clear();
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_LINE: // 0x24 36
            {
                m_writer.instructions();
                m_writer.comment("/* currently compiled source code line number %d */", *(uint16_t*)&pcode_ptr[1]);
                
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            //case HB_P_LOCALNAME: // 0x25 37
            //case HB_P_MACROPOP: // 0x26 38
            //case HB_P_MACROPOPALIASED: // 0x27 39
            //case HB_P_MACROPUSH: // 0x28 40
            //case HB_P_MACROARRAYGEN: // 0x29 41
            //case HB_P_MACROPUSHLIST: // 0x2A 42
            //case HB_P_MACROPUSHINDEX: // 0x2B 43
            //case HB_P_MACROPUSHPARE: // 0x2C 44
            //case HB_P_MACROPUSHALIASED: // 0x2D 45
            //case HB_P_MACROSYMBOL: // 0x2E 46
            //case HB_P_MACROTEXT: // 0x2F 47
            //case HB_P_MESSAGE: // 0x30 48
            case HB_P_MINUS: // 0x31 49
            {
                m_writer.instructions("push ( pop() - pop() )");
                m_writer.comment("/* subs the latest two values on the stack, removing them and leaving the result (param1 - param) */");
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            //case HB_P_MODULUS: // 0x32 50
            case HB_P_MODULENAME: // 0x33 51
            {
                uint32_t modulename_len = strlen( reinterpret_cast<const char*>(pcode_ptr+1) )+1;
                m_writer.bytecode(pcode_ptr, modulename_len+1);
                m_writer.instructions();
                m_writer.comment(" /* sets modulename \"%s\" for trace */",  pcode_ptr+1);
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += (1 + modulename_len);
                offset += (1 + modulename_len);
                break;
            }
            //case HB_P_MMESSAGE: // 0x34 52
            //case HB_P_MPOPALIASEDFIELD: // 0x35 53
            //case HB_P_MPOPALIASEDVAR: // 0x36 54
            //case HB_P_MPOPFIELD: // 0x37 55
            //case HB_P_MPOPMEMVAR: // 0x38 56
            //case HB_P_MPUSHALIASEDFIELD: // 0x39 57
            //case HB_P_MPUSHALIASEDVAR: // 0x3A 58
            //case HB_P_MPUSHBLOCK: // 0x3B 59
            //case HB_P_MPUSHFIELD: // 0x3C 60
            //case HB_P_MPUSHMEMVAR: // 0x3D 61
            //case HB_P_MPUSHMEMVARREF: // 0x3E 62
            //case HB_P_MPUSHSYM: // 0x3F 63
            //case HB_P_MPUSHVARIABLE: // 0x40 64
            case HB_P_MULT: // 0x41 65 
            {
                m_writer.instructions("push ( pop() * pop() )");
                m_writer.comment("/* multiplies the latest two values on the stack, removing them and leaving the result (param * param1) */");
                
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            //case HB_P_NEGATE: // 0x42 66
            //case HB_P_NOOP: // 0x43 67
            case HB_P_NOT: // 0x44 68
            {
                m_writer.instructions("push !pop()");
                m_writer.comment("/* logically negates the latest value on the stack */");
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_NOTEQUAL: //0x45 69
            {
                m_writer.instructions("push ( pop() != pop() )");
                m_writer.comment("/* compare last two params (param != param1), put result to the stack */");
                
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            //case HB_P_OR: // 0x46 70
            //case HB_P_PARAMETER // 0x47 71
            case HB_P_PLUS: // 0x48 72
            {                
                m_writer.instructions("push ( pop() + pop() )");
                m_writer.comment("/* adds the latest two values on the stack, removing them and leaving the result (param + param1) */");
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            //case HB_P_POP: // 0x49 73
            //case HB_P_POPALIAS: // 0x4A 74
            //case HB_P_POPALIASEDFIELD: // 0x4B 75
            //case HB_P_POPALIASEDFIELDNEAR: // 0x4C 76
            //case HB_P_POPALIASEDVAR: // 0x4D 77
            //case HB_P_POPFIELD: // 0x4E 78
            //case HB_P_POPLOCAL: // 0x4F 79
            case HB_P_POPLOCALNEAR: // 0x50 80
            {
                m_writer.instructions("VAR_%d = pop()", ( signed char )pcode_ptr[1]);
                m_writer.comment("/* pop value from stack to local variable/function param %d)*/", (signed char)pcode_ptr[1]);
                
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
            
                break;
            }
            case HB_P_POPMEMVAR: // 0x51 81
            //case HB_P_POPSTATIC: // 0x52 82
            case HB_P_POPVARIABLE: // 0x53 83
            {
                m_writer.instructions("%s = pop()", m_hb_ctx.hb_symbols[ *(uint16_t*)( pcode_ptr + 1) ]->Name());
                m_writer.comment("/* pop value from stack to local(0x53)/memory(0x51) variable %u */", *(uint16_t*)( pcode_ptr + 1));
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
            
                break;
            }
            case HB_P_POWER: // 0x54 84
            {
                m_writer.instructions("push pow( pop(), pop() )");
                m_writer.comment("/* pows the latest two values on the stack, removing them and leaving the result pow(param1, param) */");
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            //case HB_P_PUSHALIAS: // 0x55 85
            //case HB_P_PUSHALIASEDFIELD: // 0x56 86
            //case HB_P_PUSHALIASEDFIELDNEAR: // 0x57 87
            //case HB_P_PUSHALIASEDVAR: // 0x58 88
            case HB_P_PUSHBLOCK: //0x59 89
            {
                bytecode_len = *(uint16_t*)( pcode_ptr + 1 );
                m_writer.bytecode(pcode_ptr, bytecode_len);
                m_writer.instructions("push CODEBLOCK");
                m_writer.comment("/* start of a codeblock definition, codeblock size: %d */", bytecode_len);
                
                m_writer.print();
                m_writer.clear();
                
                printf("{\n");
                {
                    uint16_t parameters  = *(uint16_t*)(pcode_ptr + 3);
                    uint16_t locals = *(uint16_t*)(pcode_ptr + 5);
                    printf("/* codeblock frame has %d locals and %d parameters */\n", locals, parameters);
                    //TODO local variables table, yet never met.
                    
                    //than start of table with referenced local variables or 0
                    executable_hb_symbol symb_clone;
                    symb_clone.Name( hb_symb_and_pcode->Name() );
                    symb_clone.Scope( hb_symb_and_pcode->Scope() );
                    symb_clone.Value( (intptr_t)hb_symb_and_pcode->Value() );
                    symb_clone.DynSym( (intptr_t)hb_symb_and_pcode->DynSym() );
                    
                    //magic numbers 3 = pcode[0] + sizeof(uint16_t)
                    //              4 = sizeof(uint16_t) + sizeof(uint16_t)
                    symb_clone.pcode_size = bytecode_len - (8 + ( locals << 1 ));
                    symb_clone.pcode().assign( reinterpret_cast<const char*>( pcode_ptr + 3 + 4 + ( locals << 1 ) ),
                                               symb_clone.pcode_size
                                             );
                    
                    harbour_decompiler decompiler_local( m_hb_ctx );
                    
                    decompiler_local.function_decompile(&symb_clone);
                    
                };
                printf("}\n");
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHBLOCKSHORT: // 0x5A 90
            {
                bytecode_len = pcode_ptr[ 1 ];
                m_writer.bytecode(pcode_ptr, bytecode_len);
                m_writer.instructions("push CODEBLOCK");
                m_writer.comment("/* start of a codeblock definition, codeblock size: %d */", bytecode_len);
                
                m_writer.print();
                m_writer.clear();
                
                printf("{\n");
                {
                    executable_hb_symbol symb_clone;
                    symb_clone.Name( hb_symb_and_pcode->Name() );
                    symb_clone.Scope( hb_symb_and_pcode->Scope() );
                    symb_clone.Value( (intptr_t)hb_symb_and_pcode->Value() );
                    symb_clone.DynSym( (intptr_t)hb_symb_and_pcode->DynSym() );
                    
                    //magic numbers 3 = pcode[0] + sizeof(uint16_t)
                    //              4 = sizeof(uint16_t) + sizeof(uint16_t)
                    symb_clone.pcode_size = bytecode_len - 2;
                    symb_clone.pcode().assign( reinterpret_cast<const char*>(pcode_ptr + 2),
                                               symb_clone.pcode_size
                                             );
                    
                    harbour_decompiler decompiler_local( m_hb_ctx );
                    
                    decompiler_local.function_decompile(&symb_clone);
                    
                };
                printf("}\n");
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            //case HB_P_PUSHFIELD: // 0x5B 91
            case HB_P_PUSHBYTE: //0x5C  92
            {
                m_writer.instructions("push %X", pcode_ptr[1]);
                m_writer.comment("/* pushes byte integer 0x%X( %d ) to stack */", pcode_ptr[1], (int8_t)pcode_ptr[1]);
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHINT: // 0x5D 93
            {
                m_writer.instructions("push %X", *(int16_t*)(pcode_ptr+1));
                m_writer.comment("/* push int %d (0x%X) to stack*/", *(int16_t*)(pcode_ptr+1), *(int16_t*)(pcode_ptr+1));
                
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            //case HB_P_PUSHLOCAL: // 0x5E 94
            case HB_P_PUSHLOCALNEAR: // 0x5F 95
            {
                m_writer.instructions("push VAR_%d", pcode_ptr[1]);
                m_writer.comment("/* pushes the contents of a local variable %d to the stack (function param) */", pcode_ptr[1]);
                
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHLOCALREF: // 0x60 96
            {
                m_writer.instructions("push &VAR_%d",  *(uint16_t*)(pcode_ptr+1) );
                
                m_writer.comment("/* pushes the reference of a local variable %d to the stack (function param or variable) */", *(uint16_t*)(pcode_ptr+1));
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHLONG: //0x61 97
            {
                m_writer.instructions("push %X", *(int32_t*)(pcode_ptr+1));
                m_writer.comment("/* push long %d (0x%X) to stack*/", *(int32_t*)(pcode_ptr+1), *(int32_t*)(pcode_ptr+1));
                
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
            
                break;
            }
            case HB_P_PUSHMEMVAR: // 0x62 98
            case HB_P_PUSHMEMVARREF: // 0x63 99
            {
                m_writer.instructions("push %s", m_hb_ctx.hb_symbols[ *(uint16_t*)( pcode_ptr + 1) ]->Name());
                m_writer.comment("/* push value from memvar variable %d to stack*/", *(uint16_t*)(pcode_ptr + 1));
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
            
                break;
            }
            case HB_P_PUSHNIL: //0x64 100
			{
				m_writer.instructions("push nill");
				
				m_writer.print();
                m_writer.clear();
                
				pcode_ptr += bytecode_len;
				offset += bytecode_len;
				break;
			}
			case HB_P_PUSHDOUBLE: // 0x65 101
            {
                // 1 + sizeof( double ) + sizeof( HB_BYTE ) + sizeof( HB_BYTE ),   
                m_writer.instructions("push %lf", *(double*)( pcode_ptr + 1));
                m_writer.comment("/* places a double number %lf (width:%d dec:%d) on the stack */", 
                    *(double *)(pcode_ptr + 1),
                    *(int8_t *)(pcode_ptr + 1 + sizeof(double) ),
                    *(int8_t *)(pcode_ptr + 2 + sizeof(double) )
                );
                
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            //case HB_P_PUSHSELF: // 0x66 102
            //case HB_P_PUSHSTATIC: // 0x67 103
            //case HB_P_PUSHSTATICREF: // 0x68 104
            case HB_P_PUSHSTR: // 0x69 105
            {
                // opcode + sizeof(uint16_t) + strlen + 1
                bytecode_len = 3 + *(uint16_t*)(pcode_ptr + 1);
                
                m_writer.bytecode(pcode_ptr, bytecode_len);
                m_writer.instructions("push offset\"%s\"", pcode_ptr + 3);
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHSTRSHORT: // 0x6A 106
            {
                bytecode_len = 2 + pcode_ptr[1];
                m_writer.bytecode(pcode_ptr, bytecode_len);
                
                m_writer.instructions("push offset \"%s\"", pcode_ptr+2);
                
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            //case HB_P_PUSHSYM: // 0x6B 107
            case HB_P_PUSHSYMNEAR: // 0x6C 108
            {
                m_writer.instructions("push offset %s", m_hb_ctx.hb_symbols[ *(uint8_t*)( pcode_ptr + 1) ]->Name());
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHVARIABLE: // 0x6D 109
            {
                m_writer.instructions("push offset %s", m_hb_ctx.hb_symbols[ *(uint16_t*)( pcode_ptr + 1) ]->Name());
                m_writer.comment("/* push value from local variable %d to stack*/", pcode_ptr[1]);
                m_writer.print();
                m_writer.clear();
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
            
                break;
            }
			case HB_P_RETVALUE: //0x6E 110 
			{
				m_writer.instructions("ret");
				m_writer.print();
                m_writer.clear();
				
				pcode_ptr += bytecode_len;
				offset += bytecode_len;
				
				break;
			}
            //case HB_P_SEND: // 0x6F 111
            //case HB_P_SENDSHORT: // 0x70 112
            //case HB_P_SEQBEGIN: // 0x71 113
            //case HB_P_SEQEND: // 0x72 114
            //case HB_P_SEQRECOVER: // 0x73 115
            //case HB_P_SFRAME: // 0x74 116
            //case HB_P_STATICS: // 0x75 117
            //case HB_P_STATICNAME: // 0x76 118
            //case HB_P_SWAPALIAS: // 0x77 119
            case HB_P_TRUE: /* 0x78 120 */
            {
                m_writer.instructions("push TRUE");
                m_writer.comment("/* pushes true on the virtual machine stack */");
                
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_ZERO: /* 0x79 121 */
            {
                m_writer.instructions("push 0");
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_ONE: // 0x7A 122
            {
                m_writer.instructions("push 1");
                
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            //case HB_P_MACROFUNC: // 0x7B 123
            //case HB_P_MACRODO: // 0x7C 124
            //case HB_P_MPUSHSTR: // 0x7D 125
            case HB_P_LOCALNEARADDINT: // 0x7E 126
            {
                m_writer.instructions("VAR_%d += %d", pcode_ptr[1], *(uint16_t*)( pcode_ptr + 2 ));
                
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            //case HB_P_MACROPUSHREF: // 0x7F 127
            //case HB_P_PUSHLONGLONG: // 0x80 128
            //case HB_P_ENUMSTART: // 0x81 129
            //case HB_P_ENUMNEXT: // 0x82 130
            //case HB_P_ENUMPREV: // 0x83 131
            //case HB_P_ENUMEND: // 0x84 132
            //case HB_P_SWITCH: // 0x85 133
            //case HB_P_PUSHDATE: // 0x86 134
            
            case HB_P_PLUSEQPOP: //0x87 135
            {
                m_writer.instructions("*pop() += pop()");
                m_writer.comment("/* adds a value to the variable by reference */");
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            //case HB_P_MINUSEQPOP: //0x88 136
            //case HB_P_MULTEQPOP: //0x89 137
            //case HB_P_DIVEQPOP: //0x8A 138
            //case HB_P_PLUSEQ: //0x8B 139
            //case HB_P_MINUSEQ: //0x8C 140
            //case HB_P_MULTEQ: //0x8D 141
            //case HB_P_DIVEQ: //0x8E 142
            //case HB_P_WITHOBJECTSTART: //0x8F 143
            //case HB_P_WITHOBJECTMESSAGE: //0x90 144
            //case HB_P_WITHOBJECTEND: //0x91 145
            //case HB_P_MACROSEND: //0x92 146
            //case HB_P_PUSHOVARREF: //0x93 147
            //case HB_P_ARRAYPUSHREF: //0x94 148
            //case HB_P_VFRAME: //0x95 149
            //case HB_P_LARGEFRAME: //0x96 150
            //case HB_P_LARGEVFRAME: //0x97 151
            //case HB_P_PUSHSTRHIDDEN: //0x98 152
            //case HB_P_LOCALADDINT: //0x99 153
            //case HB_P_MODEQPOP: //0x9A 154
            //case HB_P_EXPEQPOP: //0x9B 155
            //case HB_P_MODEQ: //0x9C 156
            //case HB_P_EXPEQ: //0x9D 157
            //case HB_P_DUPLUNREF: //0x9E 158
            //case HB_P_MPUSHBLOCKLARGE: //0x9F 159
            //case HB_P_MPUSHSTRLARGE: //0xA0 160
            //case HB_P_PUSHBLOCKLARGE: //0xA1 161
            //case HB_P_PUSHSTRLARGE: //0xA2 162
            //case HB_P_SWAP: //0xA3 163
            //case HB_P_PUSHVPARAMS: //0xA4 164
            case HB_P_PUSHUNREF: // 0xA5 165
            {/* 165 push unreferenced top item on HVM stack */
                m_writer.instructions("push *pop()");
                m_writer.comment("/* push unreferenced top item on HVM stack */");
                
                m_writer.print();
                m_writer.clear();
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                
                break;
            }
            //case HB_P_SEQALWAYS: //0xA6 166
            //case HB_P_ALWAYSBEGIN: //0xA7 167
            //case HB_P_ALWAYSEND: //0xA8 168
            //case HB_P_DECEQPOP: //0xA9 169
            //case HB_P_INCEQPOP: //0xAA 170
            //case HB_P_DECEQ: //0xAB 171
            //case HB_P_INCEQ: //0xAC 172
            case HB_P_LOCALDEC: // 0xAD 173
            {
                m_writer.instructions("--VAR_%d", *(uint16_t*)(pcode_ptr + 1) );
                m_writer.comment("/* decrements the local variable %d (0x%X) */",*(uint16_t*)(pcode_ptr + 1), *(uint16_t*)(pcode_ptr + 1));
                
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                
                break;
            }
            //case HB_P_LOCALINC: //0xAE 174
            case HB_P_LOCALINCPUSH: // 0xAF 175
            {
                m_writer.instructions("push ++VAR_%d", *(uint16_t*)(pcode_ptr + 1) );
                m_writer.comment("/* increments the local variable %d (0x%X) and push it to the stack */",*(uint16_t*)(pcode_ptr + 1), *(uint16_t*)(pcode_ptr + 1));
                
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                
                break;
            }
            case HB_P_PUSHFUNCSYM: //0xB0 176 
            {
                m_writer.instructions("push offset %s", m_hb_ctx.hb_symbols[ *(uint16_t*)( pcode_ptr + 1) ]->Name() );
                
                m_writer.print();
                m_writer.clear();
                
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            //case HB_P_HASHGEN: // 0xB1 177
            //case HB_P_SEQBLOCK: // 0xB2 178
            //case HB_P_THREADSTATICS: // 0xB3 179
            //case HB_P_PUSHAPARAMS: // 0xB4 180
            default:
            {
                if ( *pcode_ptr < HB_P_LAST_PCODE )
                {
                    if ( bytecode_len )
                    {
                        m_writer.instructions("<= !");
                        m_writer.print();
                        m_writer.clear();
                        
                        pcode_ptr += bytecode_len;
                        offset += bytecode_len;
                        break;
                    }
                }
                else
                {
                    printf("pcode %d (0x%X) is too big", *pcode_ptr, *pcode_ptr);
                }
                
                /* print the rest code if bytecode_len == 0 
                 that happens when we have variable length opcode
                */
                printf("\t");
                uint32_t columns = 0;
                uint32_t i;
                
                uint32_t size = hb_symb_and_pcode->pcode_size - (pcode_ptr - pcode_base);
                
                for(i=0; i < size; i++,pcode_ptr++,columns++)
                {
                    printf("%X ", *pcode_ptr);
                    
                    if (columns == 15)
                    {
                            printf("\n\t");
                            columns = 0;
                    }
                }
                
                printf("\n");
                break;
            }
        }
        
        if ( (pcode_ptr - pcode_base) >= hb_symb_and_pcode->pcode_size )
        {
            printf("\n");
            break;
        }
    }
}

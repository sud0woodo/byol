import os
import struct
import logging
import argparse
from enum import Enum


logging.basicConfig(level=logging.DEBUG, format='%(message)s')


VA_BASE = 0x1000    # RVA from ImageBase


DOS_STUB = b'This program cannot be run in DOS mode.\x0d\x0d\x0a\x24\x00\x00\x00\x00\x00\x00\x00'


class CHARACTERISTICS(Enum):
    IMAGE_FILE_RELOCS_STRIPPED          = 0x0001
    IMAGE_FILE_EXECUTABLE_IMAGE         = 0x0002
    IMAGE_FILE_LINE_NUMS_STRIPPED       = 0x0004 
    IMAGE_FILE_LOCAL_SYMS_STRIPPED      = 0x0008
    IMAGE_FILE_AGGRESSIVE_WS_TRIM       = 0x0010
    IMAGE_FILE_LARGE_ADDRESS_AWARE      = 0x0020
    IMAGE_FILE_BYTES_REVERSED_LO        = 0x0080
    IMAGE_FILE_32BIT_MACHINE            = 0x0100
    IMAGE_FILE_DEBUG_STRIPPED           = 0x0200
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP  = 0x0400 
    IMAGE_FILE_NET_RUN_FROM_SWAP        = 0x0800
    IMAGE_FILE_SYSTEM                   = 0x1000
    IMAGE_FILE_DLL                      = 0x2000
    IMAGE_FILE_UP_SYSTEM_ONLY           = 0x4000
    IMAGE_FILE_BYTES_REVERSED_HI        = 0x8000


class DLL_CHARACTERISTICS(Enum):
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA        = 0x0020
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE           = 0x0040
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY        = 0x0080
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT              = 0x0100 
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION           = 0x0200 
    IMAGE_DLLCHARACTERISTICS_NO_SEH                 = 0x0400
    IMAGE_DLLCHARACTERISTICS_NO_BIND                = 0x0800 
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER           = 0x1000
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER             = 0x2000 
    IMAGE_DLLCHARACTERISTICS_GUARD_CF               = 0x4000
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE  = 0x8000 


class SECTION_FLAGS(Enum):
    IMAGE_SCN_TYPE_NO_PAD               = 0x00000008	
    IMAGE_SCN_CNT_CODE                  = 0x00000020
    IMAGE_SCN_CNT_INITIALIZED_DATA      = 0x00000040 
    IMAGE_SCN_CNT_UNINITIALIZED_DATA    = 0x00000080 	
    IMAGE_SCN_LNK_O                     = 0x00000100	
    IMAGE_SCN_LNK_INFO                  = 0x00000200
    IMAGE_SCN_LNK_REMOVE                = 0x00000800	
    IMAGE_SCN_LNK_COMDAT                = 0x00001000	
    IMAGE_SCN_GPREL                     = 0x00008000	
    IMAGE_SCN_MEM_PURGEABLE             = 0x00020000	
    IMAGE_SCN_MEM_16BIT                 = 0x00020000	
    IMAGE_SCN_MEM_LOCKED                = 0x00040000	
    IMAGE_SCN_MEM_PRELOAD               = 0x00080000	
    IMAGE_SCN_ALIGN_1BYTES              = 0x00100000	
    IMAGE_SCN_ALIGN_2BYTES              = 0x00200000	
    IMAGE_SCN_ALIGN_4BYTES              = 0x00300000	
    IMAGE_SCN_ALIGN_8BYTES              = 0x00400000	
    IMAGE_SCN_ALIGN_16BYTES             = 0x00500000	
    IMAGE_SCN_ALIGN_32BYTES             = 0x00600000	
    IMAGE_SCN_ALIGN_64BYTES             = 0x00700000	
    IMAGE_SCN_ALIGN_128BYTES            = 0x00800000	
    IMAGE_SCN_ALIGN_256BYTES            = 0x00900000	
    IMAGE_SCN_ALIGN_512BYTES            = 0x00A00000	
    IMAGE_SCN_ALIGN_1024BYTES           = 0x00B00000	
    IMAGE_SCN_ALIGN_2048BYTES           = 0x00C00000	
    IMAGE_SCN_ALIGN_4096BYTES           = 0x00D00000	
    IMAGE_SCN_ALIGN_8192BYTES           = 0x00E00000	
    IMAGE_SCN_LNK_NRELOC_OVFL           = 0x01000000	
    IMAGE_SCN_MEM_DISCARDABLE           = 0x02000000	
    IMAGE_SCN_MEM_NOT_CACHED            = 0x04000000	
    IMAGE_SCN_MEM_NOT_PAGED             = 0x08000000	
    IMAGE_SCN_MEM_SHARED                = 0x10000000	
    IMAGE_SCN_MEM_EXECUTE               = 0x20000000	
    IMAGE_SCN_MEM_READ                  = 0x40000000	
    IMAGE_SCN_MEM_WRITE                 = 0x80000000


def attach_x64dbg(x64dbg_location:str, shellcode_exe: str):
    os.system(f'{x64dbg_location} {shellcode_exe}')


def build_text_section(shellcode: bytes):

    text_section = bytearray()

    # Adhering CDECL calling convention
    # Save the base pointer and stack pointer
    text_section += b'\x55'     # push ebp
    text_section += b'\x8b\xec' # mov ebp, esp

    # Shellcode
    text_section += shellcode

    text_section += b'\x5d'     # pop ebp
    text_section += b'\xc3'     # ret

    return text_section


def build_section_table(virtual_size: int, text_section_size: int):

    section_table = bytearray()

    # .text
    section_table += b'.text\x00\x00\x00'                   # Name
    section_table += struct.pack('<I', virtual_size)        # VirtualSize
    section_table += struct.pack('<I', VA_BASE)             # VirtualAddress
    section_table += struct.pack('<I', text_section_size)   # SizeOfRawData
    section_table += struct.pack('<I', 0x400)               # PointerToRawData 
    section_table += b'\x00' * 4                            # PointerToRelocations
    section_table += b'\x00' * 4                            # PointerToLinenumbers 
    section_table += b'\x00\x00'                            # NumberOfRelocations 
    section_table += b'\x00\x00'                            # NumberOfLinenumbers 
    # Set memory characteristics to RWX for executable code section
    section_table_flags = (
        SECTION_FLAGS.IMAGE_SCN_CNT_CODE.value 
        + SECTION_FLAGS.IMAGE_SCN_MEM_EXECUTE.value 
        + SECTION_FLAGS.IMAGE_SCN_MEM_READ.value 
        + SECTION_FLAGS.IMAGE_SCN_MEM_WRITE.value
    )
    section_table += struct.pack('<I', section_table_flags)                               

    return section_table


def build_data_directories():

    data_directories = bytearray()

    data_directories += b'\x00' * 8   # ExportDirectory
    data_directories += b'\x00' * 8   # ImportDirectory
    data_directories += b'\x00' * 8   # ResourceDirectory
    data_directories += b'\x00' * 8   # ExceptionDirectory
    data_directories += b'\x00' * 8   # SecurityDirectory
    data_directories += b'\x00' * 8   # BaseRelocationTable
    data_directories += b'\x00' * 8   # DebugDirectory
    data_directories += b'\x00' * 8   # ArchitectureData
    data_directories += b'\x00' * 8   # RVAOfGlobalPointer
    data_directories += b'\x00' * 8   # TLS Directory
    data_directories += b'\x00' * 8   # LoadConfigurationDirectory
    data_directories += b'\x00' * 8   # BoundImportDirectoryHeaders
    data_directories += b'\x00' * 8   # ImportAddressTable
    data_directories += b'\x00' * 8   # DelayReloadImportDescriptors
    data_directories += b'\x00' * 8   # .NETHeader
    data_directories += b'\x00' * 8   # Reserved

    return data_directories

def build_optional_header(text_section_size: int, size_of_image: int):

    optional_header = bytearray()

    optional_header += struct.pack('<H', 0x10b)             # Magic (PE32)
    optional_header += b'\x00'                              # Linker version major
    optional_header += b'\x00'                              # Linker version minor
    optional_header += struct.pack('<I', text_section_size) # SizeOfCode
    optional_header += struct.pack('<I', 0x0)               # SizeOfInitializedData
    optional_header += struct.pack('<I', 0x0)               # SizeOfUninitializedData
    optional_header += struct.pack('<I', VA_BASE)           # AddressOfEntryPoint
    optional_header += struct.pack('<I', VA_BASE)           # BaseOfCode
    optional_header += struct.pack('<I', 0x4000)            # BaseOfData
    optional_header += struct.pack('<I', 0x400000)          # Imagebase
    optional_header += struct.pack('<I', 0x1000)            # SectionAlignment
    optional_header += struct.pack('<I', 0x200)             # FileAlignment
    optional_header += struct.pack('<H', 0x5)               # OS version major
    optional_header += struct.pack('<H', 0x0)               # OS version minor
    optional_header += struct.pack('<H', 0x0)               # Image version major
    optional_header += struct.pack('<H', 0x0)               # Image version minor
    optional_header += struct.pack('<H', 0x5)               # MajorSubsystemVersion
    optional_header += struct.pack('<H', 0x0)               # MinorSubsystemVersion
    optional_header += struct.pack('<I', 0x0)               # Win32 version
    optional_header += struct.pack('<I', size_of_image)     # SizeOfImage
    optional_header += struct.pack('<I', 0x200)             # SizeOfHeaders
    optional_header += struct.pack('<I', 0x0)               # Checksum
    optional_header += struct.pack('<H', 0x2)               # Subsystem
    optional_header += struct.pack('<H', 0x0)               # Dllcharacteristics
    optional_header += struct.pack('<I', 0x100000)          # SizeOfStackReserve
    optional_header += struct.pack('<I', 0x1000)            # SizeOfStackCommit
    optional_header += struct.pack('<I', 0x100000)          # SizeOfHeapReserver
    optional_header += struct.pack('<I', 0x1000)            # SizeOfHeapCommits
    optional_header += struct.pack('<I', 0x0)               # LoaderFlags
    optional_header += struct.pack('<I', 0x10)              # NumberOfRvaAndSizes

    return optional_header


def build_file_header(optional_header_size: int):

    file_header = bytearray()

    file_header += b'PE\x00\x00'
    file_header += struct.pack('<H', 0x14c)                 # 0x8664 -> x64 machine -> 0x14c x86
    file_header += struct.pack('<H', 0x1)                   # NumberOfSections
    file_header += struct.pack('<I', 0x0)                   # TimeDateStamp
    file_header += struct.pack('<I', 0x0)                   # PointerToSymbolTable
    file_header += struct.pack('<I', 0x0)                   # NumberOfSymbols
    file_header += struct.pack('<H', optional_header_size)  # SizeOfOptionalHeader
    file_header += struct.pack(
        '<H',
        CHARACTERISTICS.IMAGE_FILE_EXECUTABLE_IMAGE.value
    )                                                       # Characteristics -> 0x2 EXE / 0x2000 DLL

    return file_header


def build_dos_header():

    dos_header = bytearray()

    dos_header += b'MZ'                    # Magic number
    dos_header += struct.pack('<H', 0x0)   # Bytes on last page of file
    dos_header += struct.pack('<H', 0x0)   # Pages in file
    dos_header += struct.pack('<H', 0x0)   # Relocations
    dos_header += struct.pack('<H', 0x0)   # Size of headers in paragraphs
    dos_header += struct.pack('<H', 0x0)   # Minimum extra paragraphs needed
    dos_header += struct.pack('<H', 0x0)   # Maximum extra paragraphs needed
    dos_header += struct.pack('<H', 0x0)   # Initial SS value
    dos_header += struct.pack('<H', 0x0)   # Initial SP value
    dos_header += struct.pack('<H', 0x0)   # Checksum
    dos_header += struct.pack('<H', 0x0)   # Initial IP value
    dos_header += struct.pack('<H', 0x0)   # Initial CS value
    dos_header += struct.pack('<H', 0x0)   # File address of relocation table
    dos_header += struct.pack('<H', 0x0)   # Overlay number
    dos_header += b'\x00' * 8              # Reserved words
    dos_header += struct.pack('<H', 0x0)   # OEM Identifier
    dos_header += struct.pack('<H', 0x0)   # OEM Information
    dos_header += b'\x00' * 20             # Reserved words
    dos_header += struct.pack('<I', 0x100) # location of file header (PE\0\0)

    dos_header += DOS_STUB

    return dos_header


def build_pe(shellcode: bytes):

    text_section = build_text_section(shellcode=shellcode)
    text_section_size = len(text_section)

    # FileAlignment 0x200
    virtual_size = 0x200 * (int(len(text_section) / 0x200) + 1)

    # SectionAlignment 0x1000
    size_of_image = 0x1000 * (int((VA_BASE + virtual_size) / 0x1000) + 1)

    # Build the Optional Header in advance
    # we need the size of the Optional Header for the SizeOfOptionalHeader
    # field in the COFF File Header
    optional_header = build_optional_header(
        text_section_size=text_section_size,
        size_of_image=size_of_image
    )
    optional_header += build_data_directories()
    optional_header_size = len(optional_header)

    file_header = build_file_header(optional_header_size=optional_header_size)

    section_table = build_section_table(
        virtual_size=virtual_size,
        text_section_size=text_section_size
    )
    
    # Build the headers
    pe = build_dos_header()

    # Align COFF File Header to 0x100
    pe += b'\x00' * (0x100 - len(pe))
    pe += file_header

    pe += optional_header 

    pe += section_table

     # Align .text section to 0x400
    pe += b'\x00' * (0x400 - len(pe))
    pe += text_section
    pe += b'\x00' * 64

    return pe


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument('--infile', required=False, help='.bin file containing the shellcode')
    parser.add_argument('--shellcode', required=False, help='the shellcode to load as hex')
    parser.add_argument('--outfile', required=False, default='shellcode.exe', help='output filename (default: shellcode.exe)')
    parser.add_argument('--debug', required=False, help='x86dbg location')
    parser.add_argument('--cleanup', required=False, help='delete executable after running script')

    args = parser.parse_args()

    if not args.infile and not args.shellcode:
        logging.error("[!] please specify either a file containing shellcode, or the shellcode itself")
        exit()

    elif args.shellcode:
        shellcode = bytes.fromhex(args.shellcode)

    elif args.infile:
        with open(args.infile, 'rb') as binfile:
            shellcode = binfile.read()
    
    outfile = args.outfile
    if not outfile:
        outfile = 'shellcode.exe'

    x64dbg_location = args.debug
    cleanup_shellcode = args.cleanup

    logging.info("[*] building PE")

    shellcode_pe = build_pe(shellcode=shellcode)

    logging.info(f"[*] final PE size: {len(shellcode_pe)} bytes")

    with open(outfile, 'wb') as shellcode_file:
        shellcode_file.write(shellcode_pe)
    
    logging.info(f'[+] PE written to: {outfile}')

    cwd = os.getcwd()
    shellcode_exe = os.path.join(cwd, outfile)

    if x64dbg_location:
        logging.info('[*] attaching debugger')

        attach_x64dbg(
            x64dbg_location=args.debug,
            shellcode_exe=shellcode_exe
        )

    if cleanup_shellcode:
        os.remove(outfile)
        logging.info('[*] executable deleted')


if __name__ == '__main__':
    main()

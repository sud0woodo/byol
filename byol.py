import os
import struct
import logging
import argparse
from enum import Enum


logging.basicConfig(level=logging.DEBUG, format='%(message)s')

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


class CreatePE:
    def __init__(self, shellcode: bytes):
        self.shellcode              = shellcode

        self.dos_header             = bytearray()
        self.file_header            = bytearray()
        self.optional_header        = bytearray()

        self.data_directories       = bytearray()
        self.section_table          = bytearray()
        self.text_section           = bytearray()
        self.idata_section          = bytearray()

        self.import_table           = bytearray()

        self.va_base                = 0x1000

        # We build this in advance so we can calculate the
        #  VirtualSize of the .text section for SizeOfImage
        self.build_text_section()
        self.build_data_directories()

        self.virtual_size           = 0x200 * (int(len(self.text_section) / 0x200) + 1)
        self.build_sections_table()

        # Build the PE
        self.build_dos_header()
        self.build_optional_header()
        self.build_file_header()

    def get_pe(self):

        # Build the headers
        pe = self.dos_header
        # Align COFF File Header to 0x100
        pe += b'\x00' * (0x100 - len(pe))
        pe += self.file_header
        pe += self.optional_header 
        pe += self.data_directories
        pe += self.section_table
         # Align .text section to 0x400
        pe += b'\x00' * (0x400 - len(pe))
        
        pe += self.text_section

        pe += b'\x00' * 64

        logging.info(f"[*] final PE size: {len(pe)} bytes")

        return pe

    def build_dos_header(self):

        self.dos_header = b'MZ'                     # Magic number
        self.dos_header += struct.pack('<H', 0x0)   # Bytes on last page of file
        self.dos_header += struct.pack('<H', 0x0)   # Pages in file
        self.dos_header += struct.pack('<H', 0x0)   # Relocations
        self.dos_header += struct.pack('<H', 0x0)   # Size of headers in paragraphs
        self.dos_header += struct.pack('<H', 0x0)   # Minimum extra paragraphs needed
        self.dos_header += struct.pack('<H', 0x0)   # Maximum extra paragraphs needed
        self.dos_header += struct.pack('<H', 0x0)   # Initial SS value
        self.dos_header += struct.pack('<H', 0x0)   # Initial SP value
        self.dos_header += struct.pack('<H', 0x0)   # Checksum
        self.dos_header += struct.pack('<H', 0x0)   # Initial IP value
        self.dos_header += struct.pack('<H', 0x0)   # Initial CS value
        self.dos_header += struct.pack('<H', 0x0)   # File address of relocation table
        self.dos_header += struct.pack('<H', 0x0)   # Overlay number
        self.dos_header += b'\x00' * 8              # Reserved words
        self.dos_header += struct.pack('<H', 0x0)   # OEM Identifier
        self.dos_header += struct.pack('<H', 0x0)   # OEM Information
        self.dos_header += b'\x00' * 20             # Reserved words
        self.dos_header += struct.pack('<I', 0x100) # location of file header (PE\0\0)

        self.dos_header += DOS_STUB

    def build_file_header(self):

        optional_header_size = len(self.optional_header) + len(self.data_directories)

        self.file_header += b'PE\x00\x00'
        self.file_header += struct.pack('<H', 0x14c)         # 0x8664 -> x64 machine -> 0x14c x86
        self.file_header += struct.pack('<H', 0x1)           # NumberOfSections
        self.file_header += struct.pack('<I', 0x0)           # TimeDateStamp
        self.file_header += struct.pack('<I', 0x0)           # PointerToSymbolTable
        self.file_header += struct.pack('<I', 0x0)           # NumberOfSymbols
        self.file_header += struct.pack('<H', optional_header_size) # SizeOfOptionalHeader
        self.file_header += struct.pack(
            'H',
            CHARACTERISTICS.IMAGE_FILE_EXECUTABLE_IMAGE.value
        )                                                   # Characteristics -> 0x2 EXE / 0x2000 DLL

    def build_optional_header(self):
        
        # Since we align to 0x1000 we need to make sure to round upwards
        size_of_image = 0x1000 * (int((self.va_base + self.virtual_size) / 0x1000) + 1)

        self.optional_header += struct.pack('<H', 0x10b)                     # Magic (PE32)
        self.optional_header += b'\x00'                                      # Linker version major
        self.optional_header += b'\x00'                                      # Linker version minor
        self.optional_header += struct.pack('<I', len(self.text_section))    # SizeOfCode
        self.optional_header += struct.pack('<I', 0x0)                       # SizeOfInitializedData
        self.optional_header += struct.pack('<I', 0x0)                       # SizeOfUninitializedData
        self.optional_header += struct.pack('<I', self.va_base)              # AddressOfEntryPoint
        self.optional_header += struct.pack('<I', self.va_base)              # BaseOfCode
        self.optional_header += struct.pack('<I', 0x4000)                    # BaseOfData
        self.optional_header += struct.pack('<I', 0x400000)                  # Imagebase
        self.optional_header += struct.pack('<I', 0x1000)                    # SectionAlignment
        self.optional_header += struct.pack('<I', 0x200)                     # FileAlignment
        self.optional_header += struct.pack('<H', 0x5)                       # OS version major
        self.optional_header += struct.pack('<H', 0x0)                       # OS version minor
        self.optional_header += struct.pack('<H', 0x0)                       # Image version major
        self.optional_header += struct.pack('<H', 0x0)                       # Image version minor
        self.optional_header += struct.pack('<H', 0x5)                       # MajorSubsystemVersion
        self.optional_header += struct.pack('<H', 0x0)                       # MinorSubsystemVersion
        self.optional_header += struct.pack('<I', 0x0)                       # Win32 version
        self.optional_header += struct.pack('<I', size_of_image)             # SizeOfImage
        self.optional_header += struct.pack('<I', 0x200)                     # SizeOfHeaders
        self.optional_header += struct.pack('<I', 0x0)                       # Checksum
        self.optional_header += struct.pack('<H', 0x2)                       # Subsystem
        self.optional_header += struct.pack('<H', 0x0)                       # Dllcharacteristics
        self.optional_header += struct.pack('<I', 0x100000)                  # SizeOfStackReserve
        self.optional_header += struct.pack('<I', 0x1000)                    # SizeOfStackCommit
        self.optional_header += struct.pack('<I', 0x100000)                  # SizeOfHeapReserver
        self.optional_header += struct.pack('<I', 0x1000)                    # SizeOfHeapCommits
        self.optional_header += struct.pack('<I', 0x0)                       # LoaderFlags
        self.optional_header += struct.pack('<I', 0x10)                      # NumberOfRvaAndSizes

    def build_data_directories(self):

        self.data_directories += b'\x00' * 8   # ExportDirectory
        self.data_directories += b'\x00' * 8   # ImportDirectory
        self.data_directories += b'\x00' * 8   # ResourceDirectory
        self.data_directories += b'\x00' * 8   # ExceptionDirectory
        self.data_directories += b'\x00' * 8   # SecurityDirectory
        self.data_directories += b'\x00' * 8   # BaseRelocationTable
        self.data_directories += b'\x00' * 8   # DebugDirectory
        self.data_directories += b'\x00' * 8   # ArchitectureData
        self.data_directories += b'\x00' * 8   # RVAOfGlobalPointer
        self.data_directories += b'\x00' * 8   # TLS Directory
        self.data_directories += b'\x00' * 8   # LoadConfigurationDirectory
        self.data_directories += b'\x00' * 8   # BoundImportDirectoryHeaders
        self.data_directories += b'\x00' * 8   # ImportAddressTable
        self.data_directories += b'\x00' * 8   # DelayReloadImportDescriptors
        self.data_directories += b'\x00' * 8   # .NETHeader
        self.data_directories += b'\x00' * 8   # Reserved

    def build_sections_table(self):

        # .text
        text_section = b'.text\x00\x00\x00'
        text_section += struct.pack('<I', self.virtual_size)        # VirtualSize
        text_section += struct.pack('<I', self.va_base)             # VirtualAddress
        text_section += struct.pack('<I', len(self.text_section))   # SizeOfRawData
        text_section += struct.pack('<I', 0x400)                    # PointerToRawData 
        text_section += b'\x00' * 4                                 # PointerToRelocations
        text_section += b'\x00' * 4                                 # PointerToLinenumbers 
        text_section += b'\x00\x00'                                 # NumberOfRelocations 
        text_section += b'\x00\x00'                                 # NumberOfLinenumbers 
        # Set memory characteristics to RWX for executable code section
        text_section_flags = (
            SECTION_FLAGS.IMAGE_SCN_CNT_CODE.value 
            + SECTION_FLAGS.IMAGE_SCN_MEM_EXECUTE.value 
            + SECTION_FLAGS.IMAGE_SCN_MEM_READ.value 
            + SECTION_FLAGS.IMAGE_SCN_MEM_WRITE.value
        )
        text_section += struct.pack('<I', text_section_flags)

        self.section_table = text_section

    def build_text_section(self):

        # Adhering CDECL calling convention
        # Save the base pointer and stack pointer
        self.text_section += b'\x55'        # push ebp
        self.text_section += b'\x8b\xec'    # mov ebp, esp

        # Shellcode
        self.text_section += self.shellcode

        self.text_section += b'\x5d'        # pop ebp
        self.text_section += b'\xc3'        # ret


def attach_x64dbg(x64dbg_location:str, shellcode_exe: str):
    os.system(f'{x64dbg_location} {shellcode_exe}')


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument('--infile', required=False, help='.bin file containing the shellcode')
    parser.add_argument('--shellcode', required=False, help='the shellcode to load as hex')
    parser.add_argument('--outfile', required=False, help='output filename (default: shellcode.exe)')
    parser.add_argument('--debug', required=False, help='x86dbg location')
    parser.add_argument('--cleanup', required=False, help='delete executable after running script')

    args = parser.parse_args()

    if not args.infile and not args.shellcode:
        logging.error("[!] please specify either a file containing shellcode, or the shellcode itself")
        exit()

    elif args.shellcode:
        shellcode = bytes(args.shellcode, encoding='utf-8')
        
    elif args.infile:
        with open(args.infile, 'rb') as binfile:
            shellcode = binfile.read()
    
    outfile = args.outfile
    if not outfile:
        outfile = 'shellcode.exe'

    x64dbg_location = args.debug
    cleanup_shellcode = args.cleanup

    logging.info("[*] building PE")

    build_pe = CreatePE(shellcode=shellcode)
    shellcode_pe = build_pe.get_pe()

    with open(outfile, 'wb') as shellcode_file:
        shellcode_file.write(shellcode_pe)
    
    logging.info(f'[+] PE written to: {outfile}')

    cwd = os.getcwd()
    shellcode_exe = f'{cwd}\{outfile}'

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

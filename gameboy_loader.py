import ida_idaapi 
import idaapi
import ida_idp
import ida_loader
import ida_segment
import ida_bytes 
import ida_entry
import ida_name
import ida_kernwin
import ida_funcs
import struct

NINTENDO_LOGO = bytes([
    0xCE, 0xED, 0x66, 0x66, 0xCC, 0x0D, 0x00, 0x0B, 0x03, 0x73, 0x00, 0x83, 0x00, 0x0C, 0x00, 0x0D,
    0x00, 0x08, 0x11, 0x1F, 0x88, 0x89, 0x00, 0x0E, 0xDC, 0xCC, 0x6E, 0xE6, 0xDD, 0xDD, 0xD9, 0x99,
    0xBB, 0xBB, 0x67, 0x63, 0x6E, 0x0E, 0xEC, 0xCC, 0xDD, 0xDC, 0x99, 0x9F, 0xBB, 0xB9, 0x33, 0x3E
])

ROM_HEADER_OFFSET_TITLE = 0x0134
ROM_HEADER_OFFSET_CARTRIDGE_TYPE = 0x0147
ROM_HEADER_OFFSET_ROM_SIZE = 0x0148
ROM_HEADER_OFFSET_RAM_SIZE = 0x0149

INTERRUPT_VECTORS = {
    0x0040: "VBlank_Interrupt",
    0x0048: "LCD_STAT_Interrupt",
    0x0050: "Timer_Overflow_Interrupt",
    0x0058: "Serial_Transfer_Complete_Interrupt",
    0x0060: "Joypad_Interrupt"
}

IO_REGISTERS = {
    0xFF00: "P1_JOYP", 0xFF01: "SB", 0xFF02: "SC", 0xFF04: "DIV", 0xFF05: "TIMA",
    0xFF06: "TMA", 0xFF07: "TAC", 0xFF0F: "IF", 0xFF40: "LCDC", 0xFF41: "STAT",
    0xFF42: "SCY", 0xFF43: "SCX", 0xFF44: "LY", 0xFF45: "LYC", 0xFF46: "DMA",
    0xFF47: "BGP", 0xFF48: "OBP0", 0xFF49: "OBP1", 0xFF4A: "WY", 0xFF4B: "WX",
    0xFFFF: "IE"
}

CARTRIDGE_TYPES = {
    0x00: "ROM ONLY", 0x01: "MBC1", 0x02: "MBC1+RAM", 0x03: "MBC1+RAM+BATTERY",
    0x1B: "MBC5+RAM+BATTERY", 0x1E: "MBC5+RUMBLE+RAM+BATTERY" 
}

ROM_SIZES = {
    0x00: (32, 2), 0x01: (64, 4), 0x02: (128, 8), 0x03: (256, 16),
    0x04: (512, 32), 0x05: (1024, 64)
}

RAM_SIZES = {
    0x00: 0, 0x02: 8, 0x03: 32
}

def u8(li, offset):
    li.seek(offset)
    return struct.unpack("<B", li.read(1))[0]

def cstr(li, offset, length):
    li.seek(offset)
    return li.read(length).decode('ascii', errors='ignore').rstrip('\0')

def check_gb_rom_content(loader_input):
    ida_kernwin.msg("GB Loader: check_gb_rom_content()\n")
    try:
        if loader_input.size() < 0x150: return False
        original_pos = loader_input.tell()
        loader_input.seek(0x0104)
        logo_from_file = loader_input.read(len(NINTENDO_LOGO))
        loader_input.seek(original_pos) 
        return logo_from_file == NINTENDO_LOGO
    except Exception as e:
        ida_kernwin.msg(f"GB Loader: Exception in check_gb_rom_content: {e}\n")
        return False

def accept_file(li, n_arg):
    ida_kernwin.msg(f"GB Loader: accept_file(n_arg='{n_arg}')\n")
    
    filename_to_check = None
    is_initial_scan = False

    if isinstance(n_arg, str):
        if not n_arg.isdigit(): 
            filename_to_check = n_arg
            is_initial_scan = True 
        else: 
            is_initial_scan = (int(n_arg) == 0)
    elif isinstance(n_arg, int): 
        is_initial_scan = (n_arg == 0)
    
    if not filename_to_check and (is_initial_scan or isinstance(n_arg, int)): 
        try:
            filename_to_check = ida_loader.get_path(ida_loader.PATH_TYPE_INPUT)
        except:
            ida_kernwin.msg("GB Loader: Failed to get path via PATH_TYPE_INPUT.\n")
            return 0

    if not filename_to_check:
        ida_kernwin.msg("GB Loader: No filename to check.\n")
        return 0

    ida_kernwin.msg(f"GB Loader: Checking filename: '{filename_to_check}', is_initial_scan: {is_initial_scan}\n")

    if filename_to_check.lower().endswith((".gb", ".gbc")):
        ida_kernwin.msg("GB Loader: Extension matched.\n")
        if check_gb_rom_content(li):
            ida_kernwin.msg("GB Loader: Content matched. Accepting.\n")
            return "Game Boy ROM (.gb/.gbc)"
        else:
            ida_kernwin.msg("GB Loader: Content mismatch.\n")
    else:
        ida_kernwin.msg("GB Loader: Extension mismatch.\n")
        
    return 0

def load_file(li, neflags, format_str):
    ida_kernwin.msg("GB Loader: load_file() called.\n")

    if not ida_idp.set_processor_type("z80", ida_idp.SETPROC_LOADER_NON_FATAL):
        ida_kernwin.msg("GB Loader Error: Failed to set processor type to z80.\n")
        return 0
    ida_kernwin.msg("GB Loader: Processor type set to z80.\n")

    min_ea_set_ok = False
    start_ea_set_ok = False 

    try:
        ida_kernwin.msg("GB Loader: Attempting to set inf.min_ea = 0.\n")
        if hasattr(idaapi, 'inf_set_min_ea'):
            idaapi.inf_set_min_ea(0)
            if hasattr(idaapi, 'inf_get_min_ea') and idaapi.inf_get_min_ea() == 0:
                 ida_kernwin.msg("GB Loader: inf.min_ea set and verified to 0 via idaapi.inf_set_min_ea().\n")
                 min_ea_set_ok = True
            else:
                 ida_kernwin.msg("GB Loader Warning: idaapi.inf_set_min_ea() called, but verification failed or inf_get_min_ea not found.\n")
        else: 
            ida_kernwin.msg("GB Loader Warning: idaapi.inf_set_min_ea() not found. Trying older methods.\n")
            if hasattr(idaapi, 'get_inf_structure'): 
                inf = idaapi.get_inf_structure()
                if hasattr(inf, 'min_ea'): 
                    inf.min_ea = 0
                    if inf.min_ea == 0:
                        ida_kernwin.msg("GB Loader: inf.min_ea set to 0 via idaapi.get_inf_structure().min_ea.\n")
                        min_ea_set_ok = True
            if not min_ea_set_ok and hasattr(ida_idaapi, 'cvar') and hasattr(ida_idaapi.cvar, 'inf') and hasattr(ida_idaapi.cvar.inf, 'minEA'): 
                ida_idaapi.cvar.inf.minEA = 0
                if ida_idaapi.cvar.inf.minEA == 0:
                    ida_kernwin.msg("GB Loader: inf.minEA set to 0 via ida_idaapi.cvar.inf.minEA.\n")
                    min_ea_set_ok = True
        
        if not min_ea_set_ok:
             ida_kernwin.msg("GB Loader CRITICAL: Could not set min_ea to 0 through any known method. Aborting.\n")
             return 0
    except Exception as e:
        ida_kernwin.msg(f"GB Loader Error setting min_ea: {e}. Aborting.\n")
        return 0

    ida_kernwin.msg("GB Loader: Skipping LFLG_LZERO set attempt as constant is reported missing.\n")

    try:
        ida_kernwin.msg("GB Loader: Attempting to set inf.start_ea = 0x0100.\n")
        if hasattr(idaapi, 'inf_set_start_ea'):
            idaapi.inf_set_start_ea(0x0100)
            if hasattr(idaapi, 'inf_get_start_ea') and idaapi.inf_get_start_ea() == 0x0100:
                ida_kernwin.msg("GB Loader: inf.start_ea set and verified to 0x0100 via idaapi.inf_set_start_ea().\n")
                start_ea_set_ok = True
            else:
                ida_kernwin.msg("GB Loader Warning: idaapi.inf_set_start_ea() called, but verification failed or inf_get_start_ea not found.\n")
        else: 
            ida_kernwin.msg("GB Loader Warning: idaapi.inf_set_start_ea() not found. Trying older methods.\n")
            if hasattr(idaapi, 'get_inf_structure'):
                inf = idaapi.get_inf_structure()
                if hasattr(inf, 'start_ea'):
                    inf.start_ea = 0x0100
                    if inf.start_ea == 0x0100:
                        ida_kernwin.msg("GB Loader: inf.start_ea set to 0x0100 via idaapi.get_inf_structure().start_ea.\n")
                        start_ea_set_ok = True
            if not start_ea_set_ok and hasattr(ida_idaapi, 'cvar') and hasattr(ida_idaapi.cvar, 'inf') and hasattr(ida_idaapi.cvar.inf, 'startEA'):
                 ida_idaapi.cvar.inf.startEA = 0x0100
                 if ida_idaapi.cvar.inf.startEA == 0x0100:
                    ida_kernwin.msg("GB Loader: inf.startEA set to 0x0100 via ida_idaapi.cvar.inf.startEA.\n")
                    start_ea_set_ok = True
        if not start_ea_set_ok:
            ida_kernwin.msg("GB Loader Warning: Could not set start_ea through known methods.\n")
    except Exception as e:
        ida_kernwin.msg(f"GB Loader Error setting start_ea: {e}\n")

    li.seek(0) 
    rom_title = cstr(li, ROM_HEADER_OFFSET_TITLE, 11) 
    cart_type_code = u8(li, ROM_HEADER_OFFSET_CARTRIDGE_TYPE)
    rom_size_code = u8(li, ROM_HEADER_OFFSET_ROM_SIZE)
    ram_size_code = u8(li, ROM_HEADER_OFFSET_RAM_SIZE)

    cart_type_str = CARTRIDGE_TYPES.get(cart_type_code, f"Unknown (0x{cart_type_code:02X})")
    rom_size_kb, rom_banks = ROM_SIZES.get(rom_size_code, (0,0))
    ram_size_kb = RAM_SIZES.get(ram_size_code, 0)
    ida_kernwin.msg(f"GB Loader: ROM Title: {rom_title}, Cartridge: {cart_type_str}, ROM: {rom_size_kb}KB, RAM: {ram_size_kb}KB\n")

    try:
        ida_segment.add_segm(0, 0x0000, 0x4000, "ROM0", "CODE", ida_segment.ADDSEG_OR_DIE)
        ida_segment.add_segm(0, 0x4000, 0x8000, "ROMX", "CODE", ida_segment.ADDSEG_OR_DIE)
        ida_segment.add_segm(0, 0x8000, 0xA000, "VRAM", "DATA", ida_segment.ADDSEG_OR_DIE)
        if ram_size_kb > 0:
            eram_segment_size = min(0x2000, ram_size_kb * 1024)
            if eram_segment_size > 0:
                 ida_segment.add_segm(0, 0xA000, 0xA000 + eram_segment_size, "ERAM", "DATA", ida_segment.ADDSEG_OR_DIE)
        ida_segment.add_segm(0, 0xC000, 0xD000, "WRAM0", "DATA", ida_segment.ADDSEG_OR_DIE)
        ida_segment.add_segm(0, 0xD000, 0xE000, "WRAMX", "DATA", ida_segment.ADDSEG_OR_DIE) 
        ida_segment.add_segm(0, 0xFE00, 0xFEA0, "OAM", "DATA", ida_segment.ADDSEG_OR_DIE)
        ida_segment.add_segm(0, 0xFF00, 0xFF80, "IOREGS", "DATA", ida_segment.ADDSEG_OR_DIE)
        ida_segment.add_segm(0, 0xFF80, 0xFFFF, "HRAM", "DATA", ida_segment.ADDSEG_OR_DIE)
        ida_segment.add_segm(0, 0xFFFF, 0x10000, "IE_REG", "DATA", ida_segment.ADDSEG_OR_DIE)
        ida_kernwin.msg("GB Loader: All memory segments defined (structure only).\n")
    except Exception as e_add_segm:
        ida_kernwin.msg(f"GB Loader Error during initial segment definition: {e_add_segm}\n")
        return 0

    ida_kernwin.msg(f"GB Loader: Type of 'li' before file2base: {type(li)}, repr: {repr(li)}\n")
    try:
        li.file2base(0, 0x0000, 0x4000, 1) 
        ida_kernwin.msg("GB Loader: ROM0 segment data loaded.\n")

        rom_file_size = li.size() 
        switchable_rom_load_size = 0
        if rom_file_size > 0x4000:
            switchable_rom_load_size = min(0x4000, rom_file_size - 0x4000)
        
        if switchable_rom_load_size > 0:
            li.file2base(0x4000 * 1, 0x4000, 0x8000, 1) 
            ida_kernwin.msg("GB Loader: ROMX segment data loaded (if any).\n")
        else:
            ida_kernwin.msg("GB Loader: ROMX segment: no additional data to load or ROM too small.\n")

    except AttributeError as e_attr:
        ida_kernwin.msg(f"GB Loader Error: AttributeError during file2base call. 'li' object might not have 'file2base' method: {e_attr}\n")
        return 0
    except Exception as e_load_data: 
        ida_kernwin.msg(f"GB Loader Error during file2base data loading: {e_load_data}\n")
        if isinstance(e_load_data, TypeError) and "linput_t" in str(e_load_data):
             ida_kernwin.msg("GB Loader CRITICAL: file2base TypeError on linput_t encountered again during data loading.\n")
        return 0

    ida_entry.add_entry(0x0100, 0x0100, "entry_point_0100", 1) 
    ida_funcs.add_func(0x0100) 
    for addr, name in INTERRUPT_VECTORS.items():
        ida_entry.add_entry(addr, addr, name, 1) 
        ida_funcs.add_func(addr) 
        ida_name.set_name(addr, name, ida_name.SN_CHECK)
    ida_kernwin.msg("GB Loader: Entry point and interrupt vectors defined.\n")

    for addr, name in IO_REGISTERS.items():
        ida_bytes.create_byte(addr, 1)
        ida_name.set_name(addr, name, ida_name.SN_CHECK | ida_name.SN_PUBLIC)
    ida_kernwin.msg("GB Loader: I/O registers named.\n")
    
    ida_kernwin.msg("Game Boy ROM loading is complete.\n")
    return 1

LOADER_ENTRY = {
    "version": ida_idp.IDP_INTERFACE_VERSION,
    "flags": ida_loader.LDRF_RELOAD, 
    "name": "Game Boy ROM Loader (.gb/.gbc)", 
    "load": load_file,
    "accept": accept_file,
    "move_segm": None, 
    "save_file": None
}

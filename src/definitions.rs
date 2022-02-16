#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(dead_code)]
use argh::FromArgs;
use std::ffi::c_void;
use goblin::container::Endian;
use goblin::pe::data_directories::DataDirectory;
use scroll::ctx::TryFromCtx;
use scroll::Pread;


// define pub constants
pub const DONUT_KEY_LEN: usize = 16;
pub const DONUT_BLK_LEN: usize = 16;

pub const DONUT_ERROR_SUCCESS: usize = 0;
pub const DONUT_ERROR_FILE_NOT_FOUND: usize = 1;
pub const DONUT_ERROR_FILE_EMPTY: usize = 2;
pub const DONUT_ERROR_FILE_ACCESS: usize = 3;
pub const DONUT_ERROR_FILE_INVALID: usize = 4;
pub const DONUT_ERROR_NET_PARAMS: usize = 5;
pub const DONUT_ERROR_NO_MEMORY: usize = 6;
pub const DONUT_ERROR_INVALID_ARCH: usize = 7;
pub const DONUT_ERROR_INVALID_URL: usize = 8;
pub const DONUT_ERROR_URL_LENGTH: usize = 9;
pub const DONUT_ERROR_INVALID_PARAMETER: usize = 10;
pub const DONUT_ERROR_RANDOM: usize = 11;
pub const DONUT_ERROR_DLL_FUNCTION: usize = 12;
pub const DONUT_ERROR_ARCH_MISMATCH: usize = 13;
pub const DONUT_ERROR_DLL_PARAM: usize = 14;
pub const DONUT_ERROR_BYPASS_INVALID: usize = 15;
pub const DONUT_ERROR_NORELOC: usize = 16;
pub const DONUT_ERROR_INVALID_FORMAT: usize = 17;
pub const DONUT_ERROR_INVALID_ENGINE: usize = 18;
pub const DONUT_ERROR_COMPRESSION: usize = 19;
pub const DONUT_ERROR_INVALID_ENTROPY: usize = 20;
pub const DONUT_ERROR_MIXED_ASSEMBLY: usize = 21;

// target architecture
pub const DONUT_ARCH_ANY: i32 = -1; // for vbs and js files
pub const DONUT_ARCH_X86: u32 = 1; // x86
pub const DONUT_ARCH_X64: u32 = 2; // AMD64
pub const DONUT_ARCH_X84: u32 = 3; // x86 + AMD64

// module type
pub const DONUT_MODULE_NET_DLL: u32 = 1; // .NET DLL. Requires class and method
pub const DONUT_MODULE_NET_EXE: u32 = 2; // .NET EXE. Executes Main if no class and method provided
pub const DONUT_MODULE_DLL: u32 = 3; // Unmanaged DLL, function is optional
pub const DONUT_MODULE_EXE: u32 = 4; // Unmanaged EXE
pub const DONUT_MODULE_VBS: u32 = 5; // VBScript
pub const DONUT_MODULE_JS: u32 = 6; // JavaScript or JScript
pub const DONUT_MODULE_XSL: u32 = 7; // XSL with JavaScript/JScript or VBscript embedded

// format type
pub const DONUT_FORMAT_BINARY: u32 = 1;
pub const DONUT_FORMAT_BASE64: u32 = 2;
pub const DONUT_FORMAT_RUBY: u32 = 3;
pub const DONUT_FORMAT_C: u32 = 4;
pub const DONUT_FORMAT_PYTHON: u32 = 5;
pub const DONUT_FORMAT_POWERSHELL: u32 = 6;
pub const DONUT_FORMAT_CSHARP: u32 = 7;
pub const DONUT_FORMAT_HEX: u32 = 8;

// compression engine
pub const DONUT_COMPRESS_NONE: u32 = 1;
pub const DONUT_COMPRESS_APLIB: u32 = 2;
pub const DONUT_COMPRESS_LZNT1: u32 = 3; // COMPRESSION_FORMAT_LZNT1
pub const DONUT_COMPRESS_XPRESS: u32 = 4; // COMPRESSION_FORMAT_XPRESS
pub const DONUT_COMPRESS_XPRESS_HUFF: u32 = 5; // COMPRESSION_FORMAT_XPRESS_HUFF

// entropy level
pub const DONUT_ENTROPY_NONE: u32 = 1; // don't use any entropy
pub const DONUT_ENTROPY_RANDOM: u32 = 2; // use random names
pub const DONUT_ENTROPY_DEFAULT: u32 = 3; // use random names + symmetric encryption

// misc options
pub const DONUT_OPT_EXIT_THREAD: u32 = 1; // after the main shellcode ends, return to the caller which eventually calls RtlExitUserThread
pub const DONUT_OPT_EXIT_PROCESS: u32 = 2; // after the main shellcode ends, call RtlExitUserProcess to terminate host process

// instance type
pub const DONUT_INSTANCE_EMBED: u32 = 1; // Module is embedded
pub const DONUT_INSTANCE_HTTP: u32 = 2; // Module is downloaded from remote HTTP/HTTPS server
pub const DONUT_INSTANCE_DNS: u32 = 3; // Module is downloaded from remote DNS server

// AMSI/WLDP level
pub const DONUT_BYPASS_NONE: u32 = 1; // Disables bypassing AMSI/WDLP
pub const DONUT_BYPASS_ABORT: u32 = 2; // If bypassing AMSI/WLDP fails, the loader stops running
pub const DONUT_BYPASS_CONTINUE: u32 = 3; // If bypassing AMSI/WLDP fails, the loader continues running

pub const DONUT_MAX_NAME: usize = 256; // maximum length of string for domain, class, method and parameter names
pub const DONUT_MAX_DLL: u32 = 8; // maximum number of DLL supported by instance
pub const DONUT_MAX_MODNAME: u32 = 8;
pub const DONUT_SIG_LEN: usize = 8; // 64-bit string to verify decryption ok
pub const DONUT_VER_LEN: usize = 32;
pub const DONUT_DOMAIN_LEN: usize = 8;

pub const MARU_MAX_STR: usize = 64;
pub const MARU_BLK_LEN: usize = 16;
pub const MARU_HASH_LEN: usize = 8;
pub const MARU_IV_LEN: usize = 8;

pub const DONUT_RUNTIME_NET2: &str = "v2.0.50727";
pub const DONUT_RUNTIME_NET4: &str = "v4.0.30319";

pub const NTDLL_DLL: &str =    "ntdll.dll";
pub const KERNEL32_DLL: &str = "kernel32.dll";
pub const ADVAPI32_DLL: &str = "advapi32.dll";
pub const CRYPT32_DLL: &str =  "crypt32.dll";
pub const MSCOREE_DLL: &str =  "mscoree.dll";
pub const OLE32_DLL: &str =    "ole32.dll";
pub const OLEAUT32_DLL: &str = "oleaut32.dll";
pub const WININET_DLL: &str =  "wininet.dll";
pub const COMBASE_DLL: &str =  "combase.dll";
pub const USER32_DLL: &str =   "user32.dll";
pub const SHLWAPI_DLL: &str =  "shlwapi.dll";
pub const SHELL32_DLL: &str =  "shell32.dll";

// structs
/// Only the finest artisanal donuts are made of shells.
#[derive(Clone, Debug, FromArgs)]
pub struct DonutParser {
    /// input file
    #[argh(option)]
    pub input: String,

    // MODULE OPTIONS
    /// module name for HTTP staging. If entropy is enabled, this is generated randomly.
    #[argh(option)]
    pub modname: Option<String>,
    /// HTTP server that will host the donut module.
    #[argh(option)]
    pub server: Option<String>,
    /// entropy. 1=None, 2=Use random names, 3=Random names + symmetric encryption (default)
    #[argh(option, default = "3")]
    pub entropy: u32,

    // PIC/SHELLCODE OPTIONS
    /// target architecture : 1=x86, 2=amd64, 3=x86+amd64(default).
    #[argh(option, default = "3" )]
    pub arch: u32,
    /// bypass AMSI/WLDP : 1=None, 2=Abort on fail, 3=Continue on fail.(default)
    #[argh(option, default = "3")]
    pub bypass: u32,
    /// output file to save loader. Default is "loader.bin"
    #[argh(option, default = "\"loader.bin\".to_string()")]
    pub output: String,
    /// create thread for loader and continue execution at address (original entrypoint) supplied.
    #[argh(option)]
    pub oep: Option<u64>,
    /// exiting. 1=Exit thread (default), 2=Exit process
    #[argh(option, default = "1")]
    pub exit_opt: u32,
    
    // FILE OPTIONS
    /// optional class name. (required for .NET DLL)
    #[argh(option)]
    pub class: Option<String>,
    /// the AppDomain name to create for .NET assembly. If entropy is enabled, this is generated randomly.
    #[argh(option)]
    pub domain: Option<String>,
    /// optional method or function for DLL. (a method is required for .NET DLL)
    #[argh(option)]
    pub method: Option<String>,
    /// optional parameters/command line inside quotations for DLL method/function or EXE.
    #[argh(option)]
    pub parameters: Option<String>,
    /// command line is passed to unmanaged DLL function in UNICODE format. (default is ANSI)
    #[argh(option)]
    pub unicode: Option<u32>,
    /// CLR runtime version. MetaHeader used by default or v4.0.30319 if none available.
    #[argh(option)]
    pub runtime: Option<String>,
    /// execute the entrypoint of an unmanaged EXE as a thread.
    #[argh(option)]
    pub thread: Option<u32>,
    /// pack/Compress file. 1=None, 2=aPLib
    #[argh(option, default = "1")]
    pub compress: u32,
}

//#[repr(C)]
pub struct DonutConfig {
    pub len: u32, // original length of input file
    pub zlen: u32, // compressed length

    // general / misc options for loader
    pub arch: u32, // target architecture
    pub bypass: u32, // bypass option for AMSI/WDLP
    pub compress: u32, // engine to use when compressing file via RtlCompressBuffer
    pub entropy: u32, // entropy/encryption level
    pub format: u32, // output format for loader
    pub exit_opt: u32, // return to caller or invoke RtlExitUserProcess to terminate the host process
    pub thread: u32, // run entrypoint of unmanaged EXE as a thread. attempts to intercept calls to exit-related API
    pub oep: u64, // original entrypoint of target host file

    // .NET stuff
    pub runtime: String, // runtime version to use for CLR
    pub domain: String, // name of domain to create for .NET DLL/EXE
    pub class: String, // name of class with optional namespace for .NET DLL
    pub method: String, // name of method or DLL function to invoke for .NET DLL and unmanaged DLL

    // command line for DLL/EXE
    pub parameters: String, // command line to use for unmanaged DLL/EXE and .NET DLL/EXE
    pub unicode: u32, // param is passed to DLL function without converting to unicode

    // HTTP/DNS staging information
    pub server: String, // points to root path of where module will be stored on remote HTTP server or DNS server
    pub modname: String, // name of module written to disk for http stager

    // DONUT_MODULE
    pub module_type: u32, // VBS/JS/DLL/EXE
    pub module_len: u32, // size of DONUT_MODULE
    pub module: DonutModule, // points to DONUT_MODULE
    pub module_data: Vec<u8>, // raw module  

    // DONUT_INSTANCE
    pub instance_type: u32, // DONUT_INSTANCE_EMBED or DONUT_INSTANCE_HTTP
    pub instance_len: u32, // size of DONUT_INSTANCE
    pub instance: DonutInstance, // points to DONUT_INSTANCE

    // shellcode generated from configuration
    pub pic_len: u32, // size of loader/shellcode
    pub pic: *mut c_void, // points to loader/shellcode
}

impl Default for DonutConfig {
    fn default() -> Self {
        DonutConfig{
            len: 0,
            zlen: 0,
            arch: 0,
            bypass: 0,
            compress: 1,
            entropy: 0,
            format: 0,
            exit_opt: 0,
            thread: 0,
            oep: 0,
            runtime: String::new(),
            domain: String::new(),
            class: String::new(),
            method: String::new(),
            parameters: String::new(),
            unicode: 0,
            server: String::new(),
            modname: String::new(),
            module_type: 0,
            module_len: 0,
            module: DonutModule {
                module_type: 0,
                thread: 0,
                compress: 0,
                runtime: [0; DONUT_MAX_NAME],
                domain: [0; DONUT_MAX_NAME],
                class: [0; DONUT_MAX_NAME],
                method: [0; DONUT_MAX_NAME],
                parameters: [0; DONUT_MAX_NAME],
                unicode: 0,
                sig: [0;DONUT_SIG_LEN],
                mac: 0,
                zlen: 0,
                len: 0,
                data: [0; 4],
            },
            module_data: Vec::new(),
            instance_type: 0,
            instance_len: 0,
            instance: DonutInstance {
                len: 0,
                master_key: [0; 16],
                counter_and_nonce: [0; 16],
                iv: 0,
                hash: [0; 64],
                exit_opt: 0,
                entropy: 0,
                oep: 0,
                api_cnt: 0,
                dll_names: [0; DONUT_MAX_NAME],
                dataname: [0; 8],
                kernelbase: [0; 12],
                amsi: [0; 8],
                clr: [0; 4],
                wldp: [0; 8],
                cmd_syms: [0; DONUT_MAX_NAME],
                exit_api: [0; DONUT_MAX_NAME],
                bypass: 0,
                wldp_query: [0; 32],
                wldp_is_approved: [0; 32],
                amsi_init: [0; 16],
                amsi_scan_buf: [0; 16],
                amsi_scan_str: [0; 16],
                wscript: [0; 8],
                wscript_exe: [0; 12],
                xIID_IUnknown: GUID::default(),
                xIID_IDispatch: GUID::default(),
                xCLSID_CLRMetaHost: GUID::default(),
                xIID_ICLRMetaHost: GUID::default(),
                xIID_ICLRRuntimeInfo: GUID::default(),
                xCLSID_CorRuntimeHost: GUID::default(),
                xIID_ICorRuntimeHost: GUID::default(),
                xIID_AppDomain: GUID::default(),
                xCLSID_ScriptLanguage: GUID::default(),
                xIID_IHost: GUID::default(),
                xIID_IActiveScript: GUID::default(),
                xIID_IActiveScriptSite: GUID::default(),
                xIID_IActiveScriptSiteWindow: GUID::default(),
                xIID_IActiveScriptParse32: GUID::default(),
                xIID_IActiveScriptParse64: GUID::default(),
                instance_type: 0,
                server: [0; DONUT_MAX_NAME],
                http_req: [0; 8],
                sig: [0; DONUT_MAX_NAME],
                mac: 0,
                mod_master_key: [0; 16],
                mod_counter_and_nonce: [0; 16],
                mod_len: 0,
            },
            pic_len: 0,
            pic: 0 as *mut c_void,
        }
    }
}

//#[derive(Clone, Debug)]
#[repr(C)]
pub struct DonutInstance {
    pub len: u32, // total size of instance
    pub master_key: [u8; 16],
    pub counter_and_nonce: [u8; 16],

    pub iv: u64, // the 64-bit initial value for maru hash

    pub hash: [u64; 64], // holds up to 64 api hashes

    pub exit_opt: u32, // 1 to call RtlExitUserProcess and terminate the host process
    pub entropy: u32, // indicates entropy level
    pub oep: u64, // original entrypoint

    // everything from here is encrypted
    pub api_cnt: u32, // the 64-bit hashes of API required for instance to work
    pub dll_names: [u8; DONUT_MAX_NAME], // a list of DLL strings to load, separated by semi-colon

    pub dataname: [u8; 8], // ".data"
    pub kernelbase: [u8; 12], // "kernelbase"
    pub amsi: [u8; 8], // "amsi"
    pub clr: [u8; 4], // "clr"
    pub wldp: [u8; 8], // "wldp"

    pub cmd_syms: [u8; DONUT_MAX_NAME], // symbols related to command line
    pub exit_api: [u8; DONUT_MAX_NAME], // exit-related API

    pub bypass: u32, // indicates behaviour of byassing AMSI/WLDP
    pub wldp_query: [u8; 32], // WldpQueryDynamicCodeTrust
    pub wldp_is_approved: [u8; 32], // WldpIsClassInApprovedList
    pub amsi_init: [u8; 16], // AmsiInitialize
    pub amsi_scan_buf: [u8; 16], // AmsiScanBuffer
    pub amsi_scan_str: [u8; 16], // AmsiScanString

    pub wscript: [u8; 8], // WScript
    pub wscript_exe: [u8; 12], // wscript.exe

    pub xIID_IUnknown: GUID,
    pub xIID_IDispatch: GUID,

    // GUID required to load .NET assemblies
    pub xCLSID_CLRMetaHost: GUID,
    pub xIID_ICLRMetaHost: GUID,
    pub xIID_ICLRRuntimeInfo: GUID,
    pub xCLSID_CorRuntimeHost: GUID,
    pub xIID_ICorRuntimeHost: GUID,
    pub xIID_AppDomain: GUID,

    // GUID required to run VBS and JS files
    pub xCLSID_ScriptLanguage: GUID, // vbs or js
    pub xIID_IHost: GUID, // wscript object
    pub xIID_IActiveScript: GUID, // engine
    pub xIID_IActiveScriptSite: GUID, // implementation
    pub xIID_IActiveScriptSiteWindow: GUID, // basic GUI stuff
    pub xIID_IActiveScriptParse32: GUID, // parser
    pub xIID_IActiveScriptParse64: GUID,

    pub instance_type: u32, // DONUT_INSTANCE_EMBED, DONUT_INSTANCE_HTTP
    pub server: [u8; DONUT_MAX_NAME], // staging server hosting donut module
    pub http_req: [u8; 8], // just a buffer for "GET"

    pub sig: [u8; DONUT_MAX_NAME], // string to hash
    pub mac: u64, // to verify decryption ok

    pub mod_master_key: [u8; 16],
    pub mod_counter_and_nonce: [u8; 16],
    pub mod_len: u64, // total size of module
}

#[repr(C)]
pub struct DonutModule {
    pub module_type: u32, // EXE/DLL/JS/VBS
    pub thread: u32, // run entrypoint of unmanaged EXE as a thread
    pub compress: u32, // indicates engine used for compression

    pub runtime: [u8; DONUT_MAX_NAME], // runtime version for .NET EXE/DLL
    pub domain: [u8; DONUT_MAX_NAME], // domain name to use for .NET EXE/DLL
    pub class: [u8; DONUT_MAX_NAME], // name of class and optional namespace for .NET EXE/DLL
    pub method: [u8; DONUT_MAX_NAME], // name of method to invoke for .NET DLL or api for unmanaged DLL

    pub parameters: [u8; DONUT_MAX_NAME], // string parameters for both managed and unmanaged DLL/EXE
    pub unicode: u32, // convert param to unicode for unmanaged DLL function

    pub sig: [u8; DONUT_SIG_LEN], // string to verify decryption
    pub mac: u64, // hash of sig, to verify decryption was ok

    pub zlen: u32, // compressed size of EXE/DLL/JS/VBS file
    pub len: u32, // real size of EXE/DLL/JS/VBS file
    pub data: [u8; 4], // data of EXE/DLL/JS/VBS file
}

#[derive(Default)]
#[repr(C)]
pub struct ApiImport {
    pub module: String,
    pub name: String,
}

#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct GUID {
    data_1: u32,
    data_2: u16,
    data_3: u16,
    data_4: [u8; 8],
}

#[derive(Debug, Default)]
pub struct DotNetResult {
    pub is_dotnet: bool,
    pub version: String,
}

#[repr(C)]
#[derive(Debug, Pread)]
pub struct CliHeader {
    pub cb: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub metadata: DataDirectory,
    pub flags: u32,
    pub entry_point_token: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct MetadataRoot<'a> {
    pub signature: u32,
    pub major_version: u16,
    pub minor_version: u16,
    _reserved: u32,
    pub length: u32,
    pub version: &'a str,
}

impl<'a> TryFromCtx<'a, Endian> for MetadataRoot<'a> {
    type Error = scroll::Error;
    fn try_from_ctx(src: &'a [u8], endian: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let signature = src.gread_with(offset, endian)?;
        let major_version = src.gread_with(offset, endian)?;
        let minor_version = src.gread_with(offset, endian)?;
        let reserved = src.gread_with(offset, endian)?;
        let length = src.gread_with(offset, endian)?;
        let version = src.gread(offset)?;
        Ok((
            Self {
                signature,
                major_version,
                minor_version,
                _reserved: reserved,
                length,
                version,
            },
            *offset,
        ))
    }
}

// required to load .NET assemblies
pub const xCLSID_CorRuntimeHost: GUID = GUID {
  data_1: 0xcb2f6723, data_2: 0xab3a, data_3: 0x11d2, data_4: [0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e]};

pub const xIID_ICorRuntimeHost: GUID = GUID {
  data_1: 0xcb2f6722, data_2: 0xab3a, data_3: 0x11d2, data_4: [0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e]};

pub const xCLSID_CLRMetaHost: GUID = GUID {
  data_1: 0x9280188d, data_2: 0xe8e, data_3: 0x4867, data_4: [0xb3, 0xc, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde]};

pub const xIID_ICLRMetaHost: GUID = GUID {
  data_1: 0xD332DB9E, data_2: 0xB9B3, data_3: 0x4125, data_4: [0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16]};

pub const xIID_ICLRRuntimeInfo: GUID = GUID {
  data_1: 0xBD39D1D2, data_2: 0xBA2F, data_3: 0x486a, data_4: [0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91]};

pub const xIID_AppDomain: GUID = GUID {
  data_1: 0x05F696DC, data_2: 0x2B29, data_3: 0x3663, data_4: [0xAD, 0x8B, 0xC4,0x38, 0x9C, 0xF2, 0xA7, 0x13]};

// required to load VBS and JS files
pub const xIID_IUnknown: GUID = GUID {
  data_1: 0x00000000, data_2: 0x0000, data_3: 0x0000, data_4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]};

pub const xIID_IDispatch: GUID = GUID {
  data_1: 0x00020400, data_2: 0x0000, data_3: 0x0000, data_4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]};

pub const xIID_IHost : GUID = GUID {
  data_1: 0x91afbd1b, data_2: 0x5feb, data_3: 0x43f5, data_4: [0xb0, 0x28, 0xe2, 0xca, 0x96, 0x06, 0x17, 0xec]};

pub const xIID_IActiveScript: GUID = GUID {
  data_1: 0xbb1a2ae1, data_2: 0xa4f9, data_3: 0x11cf, data_4: [0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64]};

pub const xIID_IActiveScriptSite: GUID = GUID {
  data_1: 0xdb01a1e3, data_2: 0xa42b, data_3: 0x11cf, data_4: [0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64]};

pub const xIID_IActiveScriptSiteWindow: GUID = GUID {
  data_1: 0xd10f6761, data_2: 0x83e9, data_3: 0x11cf, data_4: [0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64]};

pub const xIID_IActiveScriptParse32: GUID = GUID {
  data_1: 0xbb1a2ae2, data_2: 0xa4f9, data_3: 0x11cf, data_4: [0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64]};

pub const xIID_IActiveScriptParse64: GUID = GUID {
  data_1: 0xc7ef7658, data_2: 0xe1ee, data_3: 0x480e, data_4: [0x97, 0xea, 0xd5, 0x2c, 0xb4, 0xd7, 0x6d, 0x17]};

pub const xCLSID_VBScript: GUID = GUID {
  data_1: 0xB54F3741, data_2: 0x5B07, data_3: 0x11cf, data_4: [0xA4, 0xB0, 0x00, 0xAA, 0x00, 0x4A, 0x55, 0xE8]};

pub const xCLSID_JScript : GUID = GUID {
  data_1: 0xF414C260, data_2: 0x6AC0, data_3: 0x11CF, data_4: [0xB6, 0xD1, 0x00, 0xAA, 0x00, 0xBB, 0xBB, 0x58]};

pub fn generate_api_imports() -> Vec<ApiImport> {
    vec![
        ApiImport{module: KERNEL32_DLL.to_string(), name: "LoadLibraryA".to_string() }, //0
        ApiImport{module: KERNEL32_DLL.to_string(), name: "GetProcAddress".to_string() },
        ApiImport{module: KERNEL32_DLL.to_string(), name: "GetModuleHandleA".to_string() },
        ApiImport{module: KERNEL32_DLL.to_string(), name: "VirtualAlloc".to_string() },
        ApiImport{module: KERNEL32_DLL.to_string(), name: "VirtualFree".to_string() },
        ApiImport{module: KERNEL32_DLL.to_string(), name: "VirtualQuery".to_string() }, // 5
        ApiImport{module: KERNEL32_DLL.to_string(), name: "VirtualProtect".to_string() },
        ApiImport{module: KERNEL32_DLL.to_string(), name: "Sleep".to_string() },
        ApiImport{module: KERNEL32_DLL.to_string(), name: "MultiByteToWideChar".to_string() },
        ApiImport{module: KERNEL32_DLL.to_string(), name: "GetUserDefaultLCID".to_string() },
        ApiImport{module: KERNEL32_DLL.to_string(), name: "WaitForSingleObject".to_string() }, //10
        ApiImport{module: KERNEL32_DLL.to_string(), name: "CreateThread".to_string() },
        ApiImport{module: KERNEL32_DLL.to_string(), name: "GetThreadContext".to_string() },
        ApiImport{module: KERNEL32_DLL.to_string(), name: "GetCurrentThread".to_string() },
        ApiImport{module: KERNEL32_DLL.to_string(), name: "GetCommandLineA".to_string() },
        ApiImport{module: KERNEL32_DLL.to_string(), name: "GetCommandLineW".to_string() }, // 15

        ApiImport{module: SHELL32_DLL.to_string(), name: "CommandLineToArgvW".to_string() },

        ApiImport{module: OLEAUT32_DLL.to_string(), name: "SafeArrayCreate".to_string() },
        ApiImport{module: OLEAUT32_DLL.to_string(), name: "SafeArrayCreateVector".to_string() },
        ApiImport{module: OLEAUT32_DLL.to_string(), name: "SafeArrayPutElement".to_string() },
        ApiImport{module: OLEAUT32_DLL.to_string(), name: "SafeArrayDestroy".to_string() }, // 20
        ApiImport{module: OLEAUT32_DLL.to_string(), name: "SafeArrayGetLBound".to_string() },
        ApiImport{module: OLEAUT32_DLL.to_string(), name: "SafeArrayGetUBound".to_string() },
        ApiImport{module: OLEAUT32_DLL.to_string(), name: "SysAllocString".to_string() },
        ApiImport{module: OLEAUT32_DLL.to_string(), name: "SysFreeString".to_string() },
        ApiImport{module: OLEAUT32_DLL.to_string(), name: "LoadTypeLib".to_string() }, // 25

        ApiImport{module: WININET_DLL.to_string(), name: "InternetCrackUrlA".to_string() },
        ApiImport{module: WININET_DLL.to_string(), name: "InternetOpenA".to_string() },
        ApiImport{module: WININET_DLL.to_string(), name: "InternetConnectA".to_string() },
        ApiImport{module: WININET_DLL.to_string(), name: "InternetSetOptionA".to_string() },
        ApiImport{module: WININET_DLL.to_string(), name: "InternetReadFile".to_string() }, // 30
        ApiImport{module: WININET_DLL.to_string(), name: "InternetCloseHandle".to_string() },
        ApiImport{module: WININET_DLL.to_string(), name: "HttpOpenRequestA".to_string() },
        ApiImport{module: WININET_DLL.to_string(), name: "HttpSendRequestA".to_string() },
        ApiImport{module: WININET_DLL.to_string(), name: "HttpQueryInfoA".to_string() },

        ApiImport{module: MSCOREE_DLL.to_string(), name: "CorBindToRuntime".to_string() }, // 35
        ApiImport{module: MSCOREE_DLL.to_string(), name: "CLRCreateInstance".to_string() },

        ApiImport{module: OLE32_DLL.to_string(), name: "CoInitializeEx".to_string() },
        ApiImport{module: OLE32_DLL.to_string(), name: "CoCreateInstance".to_string() },
        ApiImport{module: OLE32_DLL.to_string(), name: "CoUninitialize".to_string() },

        ApiImport{module: NTDLL_DLL.to_string(), name: "RtlEqualUnicodeString".to_string() }, // 40
        ApiImport{module: NTDLL_DLL.to_string(), name: "RtlEqualString".to_string() },
        ApiImport{module: NTDLL_DLL.to_string(), name: "RtlUnicodeStringToAnsiString".to_string() },
        ApiImport{module: NTDLL_DLL.to_string(), name: "RtlInitUnicodeString".to_string() },
        ApiImport{module: NTDLL_DLL.to_string(), name: "RtlExitUserThread".to_string() },
        ApiImport{module: NTDLL_DLL.to_string(), name: "RtlExitUserProcess".to_string() }, // 45
        ApiImport{module: NTDLL_DLL.to_string(), name: "RtlCreateUnicodeString".to_string() },
        ApiImport{module: NTDLL_DLL.to_string(), name: "RtlGetCompressionWorkSpaceSize".to_string() },
        ApiImport{module: NTDLL_DLL.to_string(), name: "RtlDecompressBuffer".to_string() },
        ApiImport{module: NTDLL_DLL.to_string(), name: "NtContinue".to_string() },

        ApiImport{module: KERNEL32_DLL.to_string(), name: "AddVectoredExceptionHandler".to_string() }, // 50
        ApiImport{module: KERNEL32_DLL.to_string(), name: "RemoveVectoredExceptionHandler".to_string() },
    ]
}

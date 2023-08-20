use std::{ffi::{c_char, c_void, CString, c_int, c_uint, c_ushort, c_ulong, c_long}, ptr};

use pcre2::bytes::{Regex, Captures};
use va_list::VaList;


enum XmlDtd {}

enum XmlNode {}

enum XmlNs {}

enum XmlValidState {}

enum XmlAutomata {}

enum XmlAutomataState {}

enum XmlSAXHandler {}
enum XmlParserInput {}
enum XmlParserNodeInfo {}
enum XmlParserNodeInfoSeq {}
enum XmlParserInputState {}
enum XmlDict {}
enum XmlStartTag {}
enum XmlHashTable {}
enum XmlAttr {}
enum XmlError {}
enum XmlParserMode {}

struct XmlParserCtxt {
    sax: *mut XmlSAXHandler,
    userData: *mut c_void,
    myDoc: *mut XmlDoc,
    wellFormed: c_int,
    replaceEntities: c_int,
    version: *const c_char,
    encoding: *const c_char,
    standalone: c_int,
    html: c_int,
    input: *mut XmlParserInput,
    inputNr: c_int,
    inputMax: c_int,
    inputTab: *mut *mut XmlParserInput,
    node: *mut XmlNode,
    nodeNr: c_int,
    nodeMax: c_int,
    nodeTab: *mut *mut XmlNode,
    record_info: c_int,
    node_seq: XmlParserNodeInfoSeq,
    errNo: c_int,
    hasExternalSubset: c_int,
    hasPErefs: c_int,
    external: c_int,
    valid: c_int,
    validate: c_int,
    vctxt: XmlValidCtxt,
    instate: XmlParserInputState,
    token: c_int,
    directory: *mut char,
    name: *const c_char,
    nameNr: c_int,
    nameMax: c_int,
    nameTab: *const *mut c_char,
    nbChars: c_long,
    checkIndex: c_long,
    keepBlanks: c_int,
    disableSAX: c_int,
    inSubset: c_int,
    intSubName: *const c_char,
    extSubURI: *mut c_char,
    extSubSystem: *mut c_char,
    space: *mut c_int,
    spaceNr: c_int,
    spaceMax: c_int,
    spaceTab: *mut c_int,
    depth: c_int,
    entity: *mut XmlParserInput,
    charset: c_int,
    nodelen: c_int,
    nodemem: c_int,
    pedantic: c_int,
    _private: *mut c_void,
    loadsubset: c_int,
    linenumbers: c_int,
    catalogs: *mut c_void,
    recovery: c_int,
    progressive: c_int,
    dict: *mut XmlDict,
    atts: *const *mut c_char,
    maxatts: c_int,
    docdict: c_int,
    str_Xml: *const c_char,
    str_Xmlns: *const c_char,
    str_Xml_ns: *const c_char,
    sax2: c_int,
    nsNr: c_int,
    nsMax: c_int,
    nsTab: *const *mut c_char,
    attallocs: *mut c_int,
    pushTab: *mut XmlStartTag,
    attsDefault: *mut XmlHashTable,
    attsSpecial: *mut XmlHashTable,
    nsWellFormed: c_int,
    options: c_int,
    dictNames: c_int,
    freeElemsNr: c_int,
    freeElems: *mut XmlNode,
    freeAttrsNr: c_int,
    freeAttrs: *mut XmlAttr,
    lastError: XmlError,
    parseMode: XmlParserMode,
    nbentities: c_ulong,
    sizeentities: c_ulong,
    nodeInfo: *mut XmlParserNodeInfo,
    nodeInfoNr: c_int,
    nodeInfoMax: c_int,
    nodeInfoTab: *mut XmlParserNodeInfo,
    input_id: c_int,
    sizeentcopy: c_ulong,
    endCheckState: c_int,
    nbErrors: c_ushort,
    nbWarnings: c_ushort,
}

enum XmlElementType {}

enum _XmlDict {}

#[repr(C)]
struct XmlValidCtxt {
    userData: *mut c_void,
    error: *mut extern "C" fn (*mut c_void, *const c_char, ...),
    warning: *mut extern "C" fn (*mut c_void, *const c_char, ...),
    node: *mut XmlNode,
    nodeNr: c_int,
    nodeMax: c_int,
    nodeTab: *mut *mut XmlNode,
    flags: c_uint,
    doc: *mut XmlDoc,
    valid: c_int,
    vstate: *mut XmlValidState,
    vstateNr: c_int,
    vstateMax: c_int,
    vstateTab: *mut XmlValidState,
    am: *mut XmlAutomata,
    state: *mut XmlAutomataState,
}

#[repr(C)]
struct XmlDoc {
    _private: *mut c_void,
    type_: XmlElementType,
    name: *const c_char,
    children: *mut XmlNode,
    last: *mut XmlNode,
    parent: *mut XmlNode,
    next: *mut XmlNode,
    prev: *mut XmlNode,
    doc: *mut XmlDoc,
    compression: c_int,
    standalone: c_int,
    intSubset: *mut XmlDtd,
    extSubset: *mut XmlDtd,
    oldns: *mut XmlNs,
    version: *const c_char,
    encoding: *const c_char,
    ids: *mut c_void,
    refs: *mut c_void,
    URL: *const c_char,
    charset: c_int,
    dict: *mut _XmlDict,
    psvi: *mut c_void,
    parseFlags: c_int,
    properties: c_int,
}

#[derive(Clone, Copy)]
struct XmlValidCtxtPtr(pub *mut XmlValidCtxt);

unsafe impl Send for XmlValidCtxtPtr {}
unsafe impl Sync for XmlValidCtxtPtr {}

static XML_PARSE_DTDVALID: c_int = 16;
static XML_PARSE_NOERROR: c_int = 32;
static XML_PARSE_NOWARNING: c_int = 64;
static XML_PARSE_PEDANTIC: c_int = 128;
static XML_PARSE_NOBLANKS: c_int = 256;
static XML_PARSE_NONET: c_int = 2048;


#[link(name = "xml2")]
extern "C" {
    
    fn xmlParseFile(
        filename: *const ::std::os::raw::c_char
    ) -> *mut XmlDoc;
    fn xmlFreeDoc(cur: *mut XmlDoc);
    fn xmlNewValidCtxt() -> *mut XmlValidCtxt;
    fn xmlFreeValidCtxt(ctxt: *mut XmlValidCtxt);
    fn xmlValidateDocument(
        ctxt: *mut XmlValidCtxt,
        doc: *mut XmlDoc,
    ) -> ::std::os::raw::c_int;
    fn xmlGetIntSubset(
        doc: *mut XmlDoc,
    ) -> *mut XmlDtd;
    fn xmlValidateDtd(
        ctxt: *mut XmlValidCtxt,
        doc: *mut XmlDoc,
        dtd: *mut XmlDtd,
    ) -> ::std::os::raw::c_int;
    fn xmlValidityErrorFunc(ctx : *mut c_void, msg: *const c_char, ...) -> ();
    fn xmlNewParserCtxt() -> *mut XmlParserCtxt;
    fn xmlCtxtReadFile(
        ctxt: *mut XmlParserCtxt,
        filename: *const c_char,
        encoding: *const c_char,
        options: c_int,
    ) -> *mut XmlDoc;
    
}

const REGEX : &str = r#"(%(?:(?:[-+0 #]{0,5})(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:h|l|ll|w|I|I32|I64)?[cCdiouxXeEfgGaAnpsSZ])|%%)"#;

/*
pub(crate) fn validate_Xml_file(filename: &str) -> bool {
    let filename = CString::new(filename).unwrap();
    let doc = unsafe {
        XmlParseFile(
            filename.as_ptr() as *const ::std::os::raw::c_char,
        )
    };
    if doc.is_null() {
        return false;
    }
    let ctxt = unsafe { XmlValidCtxtPtr(XmlNewValidCtxt()) };

    if ctxt.0.is_null() {
        unsafe { XmlFreeDoc(doc) };
        return false;
    }
    let ret = unsafe { XmlValidateDocument(ctxt.0, doc) };
    
    if ret != 1 {
        unsafe {
            XmlFreeDoc(doc);
            XmlFreeValidCtxt(ctxt.0);
        }
        return false;
    }
    let dtd = unsafe { XmlGetIntSubset(doc) };
    let ret = unsafe { XmlValidateDtd(ctxt.0, doc, dtd) };
    unsafe {
        XmlFreeDoc(doc);
        XmlFreeValidCtxt(ctxt.0);
    }
    ret == 1
    
}
*/

pub(crate) unsafe fn validate_xml_file(filename: &str, silent : bool) -> bool {
    let ctxt = xmlNewParserCtxt();
    let filename = CString::new(filename).unwrap();
    let options : c_int = if silent {
        XML_PARSE_DTDVALID | XML_PARSE_NOBLANKS | XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING
    } else {
        XML_PARSE_DTDVALID | XML_PARSE_NOBLANKS | XML_PARSE_NONET
    };
    let doc = xmlCtxtReadFile(ctxt, filename.as_ptr(), ptr::null(), options);
    if doc.is_null() {
        return false;
    }
    if (!ctxt.is_null()) && (*ctxt).valid != 0 {
        xmlFreeDoc(doc);
        return false;
    }

    true
}
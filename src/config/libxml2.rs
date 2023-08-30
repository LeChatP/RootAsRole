use std::{
    ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_ushort, c_void, CString},
    fmt::Display,
    path::Path,
    ptr,
};

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

#[repr(C)]
struct XmlParserCtxt {
    sax: *mut XmlSAXHandler,
    user_data: *mut c_void,
    my_doc: *mut XmlDoc,
    well_formed: c_int,
    replace_entities: c_int,
    version: *const c_char,
    encoding: *const c_char,
    standalone: c_int,
    html: c_int,
    input: *mut XmlParserInput,
    input_nr: c_int,
    input_max: c_int,
    input_tab: *mut *mut XmlParserInput,
    node: *mut XmlNode,
    node_nr: c_int,
    node_max: c_int,
    node_tab: *mut *mut XmlNode,
    record_info: c_int,
    node_seq: XmlParserNodeInfoSeq,
    err_no: c_int,
    has_external_subset: c_int,
    has_pe_refs: c_int,
    external: c_int,
    valid: c_int,
    validate: c_int,
    vctxt: XmlValidCtxt,
    instate: XmlParserInputState,
    token: c_int,
    directory: *mut c_char,
    name: *const c_char,
    name_nr: c_int,
    name_max: c_int,
    name_tab: *const *mut c_char,
    nb_chars: c_long,
    check_index: c_long,
    keep_blanks: c_int,
    disable_sax: c_int,
    in_subset: c_int,
    int_sub_name: *const c_char,
    ext_sub_uri: *mut c_char,
    ext_sub_system: *mut c_char,
    space: *mut c_int,
    space_nr: c_int,
    space_max: c_int,
    space_tab: *mut c_int,
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
    str_xml: *const c_char,
    str_xmlns: *const c_char,
    str_xml_ns: *const c_char,
    sax2: c_int,
    ns_nr: c_int,
    ns_max: c_int,
    ns_tab: *const *mut c_char,
    attallocs: *mut c_int,
    push_tab: *mut XmlStartTag,
    atts_default: *mut XmlHashTable,
    atts_special: *mut XmlHashTable,
    ns_well_formed: c_int,
    options: c_int,
    dict_names: c_int,
    free_elems_nr: c_int,
    free_elems: *mut XmlNode,
    free_attrs_nr: c_int,
    free_attrs: *mut XmlAttr,
    last_error: XmlError,
    parse_mode: XmlParserMode,
    nbentities: c_ulong,
    sizeentities: c_ulong,
    node_info: *mut XmlParserNodeInfo,
    node_info_nr: c_int,
    node_info_max: c_int,
    node_info_tab: *mut XmlParserNodeInfo,
    input_id: c_int,
    sizeentcopy: c_ulong,
    end_check_state: c_int,
    nb_errors: c_ushort,
    nb_warnings: c_ushort,
}

enum XmlElementType {}

enum _XmlDict {}

#[repr(C)]
struct XmlValidCtxt {
    user_data: *mut c_void,
    error: *mut extern "C" fn(*mut c_void, *const c_char, ...),
    warning: *mut extern "C" fn(*mut c_void, *const c_char, ...),
    node: *mut XmlNode,
    node_nr: c_int,
    node_max: c_int,
    node_tab: *mut *mut XmlNode,
    flags: c_uint,
    doc: *mut XmlDoc,
    valid: c_int,
    vstate: *mut XmlValidState,
    vstate_nr: c_int,
    vstate_max: c_int,
    vstate_tab: *mut XmlValidState,
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
    int_subset: *mut XmlDtd,
    ext_subset: *mut XmlDtd,
    oldns: *mut XmlNs,
    version: *const c_char,
    encoding: *const c_char,
    ids: *mut c_void,
    refs: *mut c_void,
    url: *const c_char,
    charset: c_int,
    dict: *mut _XmlDict,
    psvi: *mut c_void,
    parse_flags: c_int,
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

    fn xmlParseFile(filename: *const ::std::os::raw::c_char) -> *mut XmlDoc;
    fn xmlFreeDoc(cur: *mut XmlDoc);
    fn xmlNewValidCtxt() -> *mut XmlValidCtxt;
    fn xmlFreeValidCtxt(ctxt: *mut XmlValidCtxt);
    fn xmlValidateDocument(ctxt: *mut XmlValidCtxt, doc: *mut XmlDoc) -> ::std::os::raw::c_int;
    fn xmlGetIntSubset(doc: *mut XmlDoc) -> *mut XmlDtd;
    fn xmlValidateDtd(
        ctxt: *mut XmlValidCtxt,
        doc: *mut XmlDoc,
        dtd: *mut XmlDtd,
    ) -> ::std::os::raw::c_int;
    fn xmlValidityErrorFunc(ctx: *mut c_void, msg: *const c_char, ...);
    fn xmlNewParserCtxt() -> *mut XmlParserCtxt;
    fn xmlCtxtReadFile(
        ctxt: *mut XmlParserCtxt,
        filename: *const c_char,
        encoding: *const c_char,
        options: c_int,
    ) -> *mut XmlDoc;

}

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

pub(crate) unsafe fn validate_xml_file<P>(filename: &P, silent: bool) -> bool
where
    P: AsRef<Path> + Display,
{
    let ctxt = xmlNewParserCtxt();
    let filename = CString::new(filename.to_string()).unwrap();
    let options: c_int = if silent {
        XML_PARSE_DTDVALID
            | XML_PARSE_NOBLANKS
            | XML_PARSE_NONET
            | XML_PARSE_NOERROR
            | XML_PARSE_NOWARNING
    } else {
        XML_PARSE_DTDVALID | XML_PARSE_NOBLANKS | XML_PARSE_NONET | XML_PARSE_PEDANTIC
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

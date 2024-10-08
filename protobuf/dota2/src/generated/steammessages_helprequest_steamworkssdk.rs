// This file is generated by rust-protobuf 3.5.1. Do not edit
// .proto file is parsed by pure
// @generated

// https://github.com/rust-lang/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![allow(unused_attributes)]
#![cfg_attr(rustfmt, rustfmt::skip)]

#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unused_results)]
#![allow(unused_mut)]

//! Generated file from `steammessages_helprequest.steamworkssdk.proto`
// Generated for lite runtime

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::steam_vent_proto_common::protobuf::VERSION_3_5_1;

#[doc = "User uploading application logs"]
// @@protoc_insertion_point(message:CHelpRequestLogs_UploadUserApplicationLog_Request)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct CHelpRequestLogs_UploadUserApplicationLog_Request {
    // message fields
    // @@protoc_insertion_point(field:CHelpRequestLogs_UploadUserApplicationLog_Request.appid)
    pub appid: ::std::option::Option<u32>,
    // @@protoc_insertion_point(field:CHelpRequestLogs_UploadUserApplicationLog_Request.log_type)
    pub log_type: ::std::option::Option<::std::string::String>,
    // @@protoc_insertion_point(field:CHelpRequestLogs_UploadUserApplicationLog_Request.version_string)
    pub version_string: ::std::option::Option<::std::string::String>,
    // @@protoc_insertion_point(field:CHelpRequestLogs_UploadUserApplicationLog_Request.log_contents)
    pub log_contents: ::std::option::Option<::std::string::String>,
    // special fields
    // @@protoc_insertion_point(special_field:CHelpRequestLogs_UploadUserApplicationLog_Request.special_fields)
    pub special_fields: ::steam_vent_proto_common::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a CHelpRequestLogs_UploadUserApplicationLog_Request {
    fn default() -> &'a CHelpRequestLogs_UploadUserApplicationLog_Request {
        <CHelpRequestLogs_UploadUserApplicationLog_Request as ::steam_vent_proto_common::protobuf::Message>::default_instance()
    }
}

impl CHelpRequestLogs_UploadUserApplicationLog_Request {
    pub fn new() -> CHelpRequestLogs_UploadUserApplicationLog_Request {
        ::std::default::Default::default()
    }

    // optional uint32 appid = 1;

    pub fn appid(&self) -> u32 {
        self.appid.unwrap_or(0)
    }

    pub fn clear_appid(&mut self) {
        self.appid = ::std::option::Option::None;
    }

    pub fn has_appid(&self) -> bool {
        self.appid.is_some()
    }

    // Param is passed by value, moved
    pub fn set_appid(&mut self, v: u32) {
        self.appid = ::std::option::Option::Some(v);
    }

    // optional string log_type = 2;

    pub fn log_type(&self) -> &str {
        match self.log_type.as_ref() {
            Some(v) => v,
            None => "",
        }
    }

    pub fn clear_log_type(&mut self) {
        self.log_type = ::std::option::Option::None;
    }

    pub fn has_log_type(&self) -> bool {
        self.log_type.is_some()
    }

    // Param is passed by value, moved
    pub fn set_log_type(&mut self, v: ::std::string::String) {
        self.log_type = ::std::option::Option::Some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_log_type(&mut self) -> &mut ::std::string::String {
        if self.log_type.is_none() {
            self.log_type = ::std::option::Option::Some(::std::string::String::new());
        }
        self.log_type.as_mut().unwrap()
    }

    // Take field
    pub fn take_log_type(&mut self) -> ::std::string::String {
        self.log_type.take().unwrap_or_else(|| ::std::string::String::new())
    }

    // optional string version_string = 3;

    pub fn version_string(&self) -> &str {
        match self.version_string.as_ref() {
            Some(v) => v,
            None => "",
        }
    }

    pub fn clear_version_string(&mut self) {
        self.version_string = ::std::option::Option::None;
    }

    pub fn has_version_string(&self) -> bool {
        self.version_string.is_some()
    }

    // Param is passed by value, moved
    pub fn set_version_string(&mut self, v: ::std::string::String) {
        self.version_string = ::std::option::Option::Some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_version_string(&mut self) -> &mut ::std::string::String {
        if self.version_string.is_none() {
            self.version_string = ::std::option::Option::Some(::std::string::String::new());
        }
        self.version_string.as_mut().unwrap()
    }

    // Take field
    pub fn take_version_string(&mut self) -> ::std::string::String {
        self.version_string.take().unwrap_or_else(|| ::std::string::String::new())
    }

    // optional string log_contents = 4;

    pub fn log_contents(&self) -> &str {
        match self.log_contents.as_ref() {
            Some(v) => v,
            None => "",
        }
    }

    pub fn clear_log_contents(&mut self) {
        self.log_contents = ::std::option::Option::None;
    }

    pub fn has_log_contents(&self) -> bool {
        self.log_contents.is_some()
    }

    // Param is passed by value, moved
    pub fn set_log_contents(&mut self, v: ::std::string::String) {
        self.log_contents = ::std::option::Option::Some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_log_contents(&mut self) -> &mut ::std::string::String {
        if self.log_contents.is_none() {
            self.log_contents = ::std::option::Option::Some(::std::string::String::new());
        }
        self.log_contents.as_mut().unwrap()
    }

    // Take field
    pub fn take_log_contents(&mut self) -> ::std::string::String {
        self.log_contents.take().unwrap_or_else(|| ::std::string::String::new())
    }
}

impl ::steam_vent_proto_common::protobuf::Message for CHelpRequestLogs_UploadUserApplicationLog_Request {
    const NAME: &'static str = "CHelpRequestLogs_UploadUserApplicationLog_Request";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::steam_vent_proto_common::protobuf::CodedInputStream<'_>) -> ::steam_vent_proto_common::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                8 => {
                    self.appid = ::std::option::Option::Some(is.read_uint32()?);
                },
                18 => {
                    self.log_type = ::std::option::Option::Some(is.read_string()?);
                },
                26 => {
                    self.version_string = ::std::option::Option::Some(is.read_string()?);
                },
                34 => {
                    self.log_contents = ::std::option::Option::Some(is.read_string()?);
                },
                tag => {
                    ::steam_vent_proto_common::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if let Some(v) = self.appid {
            my_size += ::steam_vent_proto_common::protobuf::rt::uint32_size(1, v);
        }
        if let Some(v) = self.log_type.as_ref() {
            my_size += ::steam_vent_proto_common::protobuf::rt::string_size(2, &v);
        }
        if let Some(v) = self.version_string.as_ref() {
            my_size += ::steam_vent_proto_common::protobuf::rt::string_size(3, &v);
        }
        if let Some(v) = self.log_contents.as_ref() {
            my_size += ::steam_vent_proto_common::protobuf::rt::string_size(4, &v);
        }
        my_size += ::steam_vent_proto_common::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::steam_vent_proto_common::protobuf::CodedOutputStream<'_>) -> ::steam_vent_proto_common::protobuf::Result<()> {
        if let Some(v) = self.appid {
            os.write_uint32(1, v)?;
        }
        if let Some(v) = self.log_type.as_ref() {
            os.write_string(2, v)?;
        }
        if let Some(v) = self.version_string.as_ref() {
            os.write_string(3, v)?;
        }
        if let Some(v) = self.log_contents.as_ref() {
            os.write_string(4, v)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::steam_vent_proto_common::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::steam_vent_proto_common::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> CHelpRequestLogs_UploadUserApplicationLog_Request {
        CHelpRequestLogs_UploadUserApplicationLog_Request::new()
    }

    fn clear(&mut self) {
        self.appid = ::std::option::Option::None;
        self.log_type = ::std::option::Option::None;
        self.version_string = ::std::option::Option::None;
        self.log_contents = ::std::option::Option::None;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static CHelpRequestLogs_UploadUserApplicationLog_Request {
        static instance: CHelpRequestLogs_UploadUserApplicationLog_Request = CHelpRequestLogs_UploadUserApplicationLog_Request {
            appid: ::std::option::Option::None,
            log_type: ::std::option::Option::None,
            version_string: ::std::option::Option::None,
            log_contents: ::std::option::Option::None,
            special_fields: ::steam_vent_proto_common::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

// @@protoc_insertion_point(message:CHelpRequestLogs_UploadUserApplicationLog_Response)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct CHelpRequestLogs_UploadUserApplicationLog_Response {
    // message fields
    // @@protoc_insertion_point(field:CHelpRequestLogs_UploadUserApplicationLog_Response.id)
    pub id: ::std::option::Option<u64>,
    // special fields
    // @@protoc_insertion_point(special_field:CHelpRequestLogs_UploadUserApplicationLog_Response.special_fields)
    pub special_fields: ::steam_vent_proto_common::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a CHelpRequestLogs_UploadUserApplicationLog_Response {
    fn default() -> &'a CHelpRequestLogs_UploadUserApplicationLog_Response {
        <CHelpRequestLogs_UploadUserApplicationLog_Response as ::steam_vent_proto_common::protobuf::Message>::default_instance()
    }
}

impl CHelpRequestLogs_UploadUserApplicationLog_Response {
    pub fn new() -> CHelpRequestLogs_UploadUserApplicationLog_Response {
        ::std::default::Default::default()
    }

    // optional uint64 id = 1;

    pub fn id(&self) -> u64 {
        self.id.unwrap_or(0)
    }

    pub fn clear_id(&mut self) {
        self.id = ::std::option::Option::None;
    }

    pub fn has_id(&self) -> bool {
        self.id.is_some()
    }

    // Param is passed by value, moved
    pub fn set_id(&mut self, v: u64) {
        self.id = ::std::option::Option::Some(v);
    }
}

impl ::steam_vent_proto_common::protobuf::Message for CHelpRequestLogs_UploadUserApplicationLog_Response {
    const NAME: &'static str = "CHelpRequestLogs_UploadUserApplicationLog_Response";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::steam_vent_proto_common::protobuf::CodedInputStream<'_>) -> ::steam_vent_proto_common::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                8 => {
                    self.id = ::std::option::Option::Some(is.read_uint64()?);
                },
                tag => {
                    ::steam_vent_proto_common::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if let Some(v) = self.id {
            my_size += ::steam_vent_proto_common::protobuf::rt::uint64_size(1, v);
        }
        my_size += ::steam_vent_proto_common::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::steam_vent_proto_common::protobuf::CodedOutputStream<'_>) -> ::steam_vent_proto_common::protobuf::Result<()> {
        if let Some(v) = self.id {
            os.write_uint64(1, v)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::steam_vent_proto_common::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::steam_vent_proto_common::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> CHelpRequestLogs_UploadUserApplicationLog_Response {
        CHelpRequestLogs_UploadUserApplicationLog_Response::new()
    }

    fn clear(&mut self) {
        self.id = ::std::option::Option::None;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static CHelpRequestLogs_UploadUserApplicationLog_Response {
        static instance: CHelpRequestLogs_UploadUserApplicationLog_Response = CHelpRequestLogs_UploadUserApplicationLog_Response {
            id: ::std::option::Option::None,
            special_fields: ::steam_vent_proto_common::protobuf::SpecialFields::new(),
        };
        &instance
    }
}


const _VENT_PROTO_VERSION_CHECK: () = ::steam_vent_proto_common::VERSION_0_5_0;

#[allow(unused_imports)]
use crate::steammessages_unified_base_steamworkssdk::*;
impl ::steam_vent_proto_common::RpcMessage
for CHelpRequestLogs_UploadUserApplicationLog_Request {
    fn parse(reader: &mut dyn std::io::Read) -> ::steam_vent_proto_common::protobuf::Result<Self> {
        <Self as ::steam_vent_proto_common::protobuf::Message>::parse_from_reader(reader)
    }
    fn write(&self, writer: &mut dyn std::io::Write) -> ::steam_vent_proto_common::protobuf::Result<()> {
        use ::steam_vent_proto_common::protobuf::Message;
        self.write_to_writer(writer)
    }
    fn encode_size(&self) -> usize {
        use ::steam_vent_proto_common::protobuf::Message;
        self.compute_size() as usize
    }
}
impl ::steam_vent_proto_common::RpcMessage
for CHelpRequestLogs_UploadUserApplicationLog_Response {
    fn parse(reader: &mut dyn std::io::Read) -> ::steam_vent_proto_common::protobuf::Result<Self> {
        <Self as ::steam_vent_proto_common::protobuf::Message>::parse_from_reader(reader)
    }
    fn write(&self, writer: &mut dyn std::io::Write) -> ::steam_vent_proto_common::protobuf::Result<()> {
        use ::steam_vent_proto_common::protobuf::Message;
        self.write_to_writer(writer)
    }
    fn encode_size(&self) -> usize {
        use ::steam_vent_proto_common::protobuf::Message;
        self.compute_size() as usize
    }
}
///Service for dealing with user-submitted logs
struct HelpRequestLogs {}
impl ::steam_vent_proto_common::RpcService for HelpRequestLogs {
    const SERVICE_NAME: &'static str = "HelpRequestLogs";
}
impl ::steam_vent_proto_common::RpcMethod
for CHelpRequestLogs_UploadUserApplicationLog_Request {
    const METHOD_NAME: &'static str = "HelpRequestLogs.UploadUserApplicationLog#1";
    type Response = CHelpRequestLogs_UploadUserApplicationLog_Response;
}

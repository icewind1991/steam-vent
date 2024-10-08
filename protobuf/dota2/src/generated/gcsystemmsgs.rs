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

//! Generated file from `gcsystemmsgs.proto`
// Generated for lite runtime

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::steam_vent_proto_common::protobuf::VERSION_3_5_1;

#[derive(Clone,Copy,PartialEq,Eq,Debug,Hash)]
// @@protoc_insertion_point(enum:ESOMsg)
pub enum ESOMsg {
    // @@protoc_insertion_point(enum_value:ESOMsg.k_ESOMsg_Create)
    k_ESOMsg_Create = 21,
    // @@protoc_insertion_point(enum_value:ESOMsg.k_ESOMsg_Update)
    k_ESOMsg_Update = 22,
    // @@protoc_insertion_point(enum_value:ESOMsg.k_ESOMsg_Destroy)
    k_ESOMsg_Destroy = 23,
    // @@protoc_insertion_point(enum_value:ESOMsg.k_ESOMsg_CacheSubscribed)
    k_ESOMsg_CacheSubscribed = 24,
    // @@protoc_insertion_point(enum_value:ESOMsg.k_ESOMsg_CacheUnsubscribed)
    k_ESOMsg_CacheUnsubscribed = 25,
    // @@protoc_insertion_point(enum_value:ESOMsg.k_ESOMsg_UpdateMultiple)
    k_ESOMsg_UpdateMultiple = 26,
    // @@protoc_insertion_point(enum_value:ESOMsg.k_ESOMsg_CacheSubscriptionRefresh)
    k_ESOMsg_CacheSubscriptionRefresh = 28,
    // @@protoc_insertion_point(enum_value:ESOMsg.k_ESOMsg_CacheSubscribedUpToDate)
    k_ESOMsg_CacheSubscribedUpToDate = 29,
}

impl ::steam_vent_proto_common::protobuf::Enum for ESOMsg {
    const NAME: &'static str = "ESOMsg";

    fn value(&self) -> i32 {
        *self as i32
    }

    fn from_i32(value: i32) -> ::std::option::Option<ESOMsg> {
        match value {
            21 => ::std::option::Option::Some(ESOMsg::k_ESOMsg_Create),
            22 => ::std::option::Option::Some(ESOMsg::k_ESOMsg_Update),
            23 => ::std::option::Option::Some(ESOMsg::k_ESOMsg_Destroy),
            24 => ::std::option::Option::Some(ESOMsg::k_ESOMsg_CacheSubscribed),
            25 => ::std::option::Option::Some(ESOMsg::k_ESOMsg_CacheUnsubscribed),
            26 => ::std::option::Option::Some(ESOMsg::k_ESOMsg_UpdateMultiple),
            28 => ::std::option::Option::Some(ESOMsg::k_ESOMsg_CacheSubscriptionRefresh),
            29 => ::std::option::Option::Some(ESOMsg::k_ESOMsg_CacheSubscribedUpToDate),
            _ => ::std::option::Option::None
        }
    }

    fn from_str(str: &str) -> ::std::option::Option<ESOMsg> {
        match str {
            "k_ESOMsg_Create" => ::std::option::Option::Some(ESOMsg::k_ESOMsg_Create),
            "k_ESOMsg_Update" => ::std::option::Option::Some(ESOMsg::k_ESOMsg_Update),
            "k_ESOMsg_Destroy" => ::std::option::Option::Some(ESOMsg::k_ESOMsg_Destroy),
            "k_ESOMsg_CacheSubscribed" => ::std::option::Option::Some(ESOMsg::k_ESOMsg_CacheSubscribed),
            "k_ESOMsg_CacheUnsubscribed" => ::std::option::Option::Some(ESOMsg::k_ESOMsg_CacheUnsubscribed),
            "k_ESOMsg_UpdateMultiple" => ::std::option::Option::Some(ESOMsg::k_ESOMsg_UpdateMultiple),
            "k_ESOMsg_CacheSubscriptionRefresh" => ::std::option::Option::Some(ESOMsg::k_ESOMsg_CacheSubscriptionRefresh),
            "k_ESOMsg_CacheSubscribedUpToDate" => ::std::option::Option::Some(ESOMsg::k_ESOMsg_CacheSubscribedUpToDate),
            _ => ::std::option::Option::None
        }
    }

    const VALUES: &'static [ESOMsg] = &[
        ESOMsg::k_ESOMsg_Create,
        ESOMsg::k_ESOMsg_Update,
        ESOMsg::k_ESOMsg_Destroy,
        ESOMsg::k_ESOMsg_CacheSubscribed,
        ESOMsg::k_ESOMsg_CacheUnsubscribed,
        ESOMsg::k_ESOMsg_UpdateMultiple,
        ESOMsg::k_ESOMsg_CacheSubscriptionRefresh,
        ESOMsg::k_ESOMsg_CacheSubscribedUpToDate,
    ];
}

// Note, `Default` is implemented although default value is not 0
impl ::std::default::Default for ESOMsg {
    fn default() -> Self {
        ESOMsg::k_ESOMsg_Create
    }
}


#[derive(Clone,Copy,PartialEq,Eq,Debug,Hash)]
// @@protoc_insertion_point(enum:EGCBaseClientMsg)
pub enum EGCBaseClientMsg {
    // @@protoc_insertion_point(enum_value:EGCBaseClientMsg.k_EMsgGCPingRequest)
    k_EMsgGCPingRequest = 3001,
    // @@protoc_insertion_point(enum_value:EGCBaseClientMsg.k_EMsgGCPingResponse)
    k_EMsgGCPingResponse = 3002,
    // @@protoc_insertion_point(enum_value:EGCBaseClientMsg.k_EMsgGCToClientPollConvarRequest)
    k_EMsgGCToClientPollConvarRequest = 3003,
    // @@protoc_insertion_point(enum_value:EGCBaseClientMsg.k_EMsgGCToClientPollConvarResponse)
    k_EMsgGCToClientPollConvarResponse = 3004,
    // @@protoc_insertion_point(enum_value:EGCBaseClientMsg.k_EMsgGCCompressedMsgToClient)
    k_EMsgGCCompressedMsgToClient = 3005,
    // @@protoc_insertion_point(enum_value:EGCBaseClientMsg.k_EMsgGCCompressedMsgToClient_Legacy)
    k_EMsgGCCompressedMsgToClient_Legacy = 523,
    // @@protoc_insertion_point(enum_value:EGCBaseClientMsg.k_EMsgGCToClientRequestDropped)
    k_EMsgGCToClientRequestDropped = 3006,
    // @@protoc_insertion_point(enum_value:EGCBaseClientMsg.k_EMsgGCClientWelcome)
    k_EMsgGCClientWelcome = 4004,
    // @@protoc_insertion_point(enum_value:EGCBaseClientMsg.k_EMsgGCServerWelcome)
    k_EMsgGCServerWelcome = 4005,
    // @@protoc_insertion_point(enum_value:EGCBaseClientMsg.k_EMsgGCClientHello)
    k_EMsgGCClientHello = 4006,
    // @@protoc_insertion_point(enum_value:EGCBaseClientMsg.k_EMsgGCServerHello)
    k_EMsgGCServerHello = 4007,
    // @@protoc_insertion_point(enum_value:EGCBaseClientMsg.k_EMsgGCClientConnectionStatus)
    k_EMsgGCClientConnectionStatus = 4009,
    // @@protoc_insertion_point(enum_value:EGCBaseClientMsg.k_EMsgGCServerConnectionStatus)
    k_EMsgGCServerConnectionStatus = 4010,
}

impl ::steam_vent_proto_common::protobuf::Enum for EGCBaseClientMsg {
    const NAME: &'static str = "EGCBaseClientMsg";

    fn value(&self) -> i32 {
        *self as i32
    }

    fn from_i32(value: i32) -> ::std::option::Option<EGCBaseClientMsg> {
        match value {
            3001 => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCPingRequest),
            3002 => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCPingResponse),
            3003 => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCToClientPollConvarRequest),
            3004 => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCToClientPollConvarResponse),
            3005 => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCCompressedMsgToClient),
            523 => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCCompressedMsgToClient_Legacy),
            3006 => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCToClientRequestDropped),
            4004 => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCClientWelcome),
            4005 => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCServerWelcome),
            4006 => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCClientHello),
            4007 => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCServerHello),
            4009 => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCClientConnectionStatus),
            4010 => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCServerConnectionStatus),
            _ => ::std::option::Option::None
        }
    }

    fn from_str(str: &str) -> ::std::option::Option<EGCBaseClientMsg> {
        match str {
            "k_EMsgGCPingRequest" => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCPingRequest),
            "k_EMsgGCPingResponse" => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCPingResponse),
            "k_EMsgGCToClientPollConvarRequest" => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCToClientPollConvarRequest),
            "k_EMsgGCToClientPollConvarResponse" => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCToClientPollConvarResponse),
            "k_EMsgGCCompressedMsgToClient" => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCCompressedMsgToClient),
            "k_EMsgGCCompressedMsgToClient_Legacy" => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCCompressedMsgToClient_Legacy),
            "k_EMsgGCToClientRequestDropped" => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCToClientRequestDropped),
            "k_EMsgGCClientWelcome" => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCClientWelcome),
            "k_EMsgGCServerWelcome" => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCServerWelcome),
            "k_EMsgGCClientHello" => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCClientHello),
            "k_EMsgGCServerHello" => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCServerHello),
            "k_EMsgGCClientConnectionStatus" => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCClientConnectionStatus),
            "k_EMsgGCServerConnectionStatus" => ::std::option::Option::Some(EGCBaseClientMsg::k_EMsgGCServerConnectionStatus),
            _ => ::std::option::Option::None
        }
    }

    const VALUES: &'static [EGCBaseClientMsg] = &[
        EGCBaseClientMsg::k_EMsgGCPingRequest,
        EGCBaseClientMsg::k_EMsgGCPingResponse,
        EGCBaseClientMsg::k_EMsgGCToClientPollConvarRequest,
        EGCBaseClientMsg::k_EMsgGCToClientPollConvarResponse,
        EGCBaseClientMsg::k_EMsgGCCompressedMsgToClient,
        EGCBaseClientMsg::k_EMsgGCCompressedMsgToClient_Legacy,
        EGCBaseClientMsg::k_EMsgGCToClientRequestDropped,
        EGCBaseClientMsg::k_EMsgGCClientWelcome,
        EGCBaseClientMsg::k_EMsgGCServerWelcome,
        EGCBaseClientMsg::k_EMsgGCClientHello,
        EGCBaseClientMsg::k_EMsgGCServerHello,
        EGCBaseClientMsg::k_EMsgGCClientConnectionStatus,
        EGCBaseClientMsg::k_EMsgGCServerConnectionStatus,
    ];
}

// Note, `Default` is implemented although default value is not 0
impl ::std::default::Default for EGCBaseClientMsg {
    fn default() -> Self {
        EGCBaseClientMsg::k_EMsgGCPingRequest
    }
}



const _VENT_PROTO_VERSION_CHECK: () = ::steam_vent_proto_common::VERSION_0_5_0;

impl ::steam_vent_proto_common::MsgKindEnum for ESOMsg {}
impl ::steam_vent_proto_common::MsgKindEnum for EGCBaseClientMsg {}

use crate::proto_path_to_rust_mod;
use proc_macro2::{Ident, Span, TokenStream};
use protobuf_parse::Parser;
use quote::quote;
use std::path::{Path, PathBuf};

pub fn get_kinds(base: &Path, protos: &[PathBuf]) -> Vec<Kind> {
    let mut parser = Parser::new();
    parser.pure().include(base).inputs(protos);
    let mut parsed = parser.parse_and_typecheck().unwrap().file_descriptors;
    let kinds_enums = parsed
        .iter_mut()
        .flat_map(|parsed| {
            let mod_name = proto_path_to_rust_mod(parsed.name());
            parsed
                .enum_type
                .iter_mut()
                .map(move |e| (mod_name.clone(), e))
        })
        .filter(|(_, e)| {
            e.name().starts_with("E")
                && (e.name().ends_with("Msg") || e.name().ends_with("Messages"))
        });

    let mut kinds = kinds_enums
        .flat_map(|(mod_name, kinds_enum)| {
            let enum_name = kinds_enum.take_name();

            kinds_enum
                .value
                .iter_mut()
                .map(move |opt| Kind::new(&mod_name, &enum_name, opt.name()))
        })
        .collect::<Vec<_>>();

    // sort kinds with prefix in front
    kinds.sort_by(|a, b| a.enum_prefix.len().cmp(&b.enum_prefix.len()).reverse());
    kinds
}

#[derive(Debug, Clone)]
pub struct Kind {
    mod_name: String,
    enum_name: String,
    enum_prefix: String,
    variant_prefix: String,
    variant_prefix_alt: String,
    variant_prefix_alt2: String,
    variant: String,
    is_gc: bool,
    struct_name_prefix_alt_len: usize,
}

impl Kind {
    pub fn new(mod_name: &str, enum_name: &str, variant_name: &str) -> Self {
        let prefix: String = enum_name
            .chars()
            .skip(1)
            .take_while(char::is_ascii_uppercase)
            .collect();
        let prefix = prefix[0..prefix.len() - 1].to_string();
        let variant_prefix = format!("k_EMsg{}", prefix);
        let variant_prefix_alt = format!("k_E{}Msg_", prefix);
        let variant_prefix_alt2 = "k_EMsg".to_string();
        let enum_prefix = prefix.to_ascii_lowercase();

        Kind {
            is_gc: variant_prefix.contains("GC"),
            mod_name: mod_name.to_string(),
            enum_name: enum_name.to_string(),
            enum_prefix,
            variant_prefix,
            variant_prefix_alt,
            variant_prefix_alt2,
            variant: variant_name.to_string(),
            struct_name_prefix_alt_len: prefix.len(),
        }
    }

    pub fn matches(&self, struct_name: &str, file_name: Option<&str>) -> bool {
        let struct_name = struct_name.strip_prefix('C').unwrap_or(struct_name);
        let struct_name = struct_name.strip_prefix("Msg").unwrap_or(struct_name);

        let Some(stripped) = self
            .variant
            .strip_prefix(&self.variant_prefix)
            .or_else(|| self.variant.strip_prefix(&self.variant_prefix_alt))
            .or_else(|| self.variant.strip_prefix(&self.variant_prefix_alt2))
        else {
            return false;
        };
        if let Some(file_name) = file_name {
            if !(file_name.contains(&self.enum_prefix)
                || file_name.replace('_', "").contains(&self.enum_prefix))
            {
                return false;
            }
        }
        struct_name.eq_ignore_ascii_case(stripped)
            || (self.is_gc
                && stripped
                    .strip_prefix("GC")
                    .unwrap_or_default()
                    .eq_ignore_ascii_case(struct_name))
            || struct_name
                .get(self.struct_name_prefix_alt_len..)
                .unwrap_or_default()
                .eq_ignore_ascii_case(stripped)
    }

    pub fn ident(&self) -> TokenStream {
        let path = Ident::new(&self.mod_name, Span::call_site());
        let enum_ident = Ident::new(&self.enum_name, Span::call_site());
        let variant_ident = Ident::new(&self.variant, Span::call_site());
        quote!(crate::#path::#enum_ident::#variant_ident)
    }

    pub fn enum_ident(&self) -> TokenStream {
        let path = Ident::new(&self.mod_name, Span::call_site());
        let enum_ident = Ident::new(&self.enum_name, Span::call_site());
        quote!(crate::#path::#enum_ident)
    }
}

#[test]
fn test_find_kind() {
    assert!(Kind::new(
        "enums_clientserver",
        "EMsg",
        "k_EMsgClientSiteLicenseCheckout",
    )
    .matches(
        "CMsgClientSiteLicenseCheckout",
        Some("steammessages_sitelicenseclient")
    ));
    assert!(
        Kind::new("econ_gcmessages", "EGCItemMsg", "k_EMsgGCApplyAutograph",)
            .matches("CMsgApplyAutograph", Some("econ_gcmessages"))
    );

    assert!(
        Kind::new("dota_gcmessages_msgid", "EDOTAGCMsg", "k_EMsgGCLobbyList").matches(
            "CMsgLobbyList",
            Some("dota_gcmessages_client_match_management")
        )
    );
}

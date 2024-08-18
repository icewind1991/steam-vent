use ahash::{AHashMap, AHashSet, RandomState};
use proc_macro2::{Ident, Span, TokenStream};
use protobuf::reflect::{FileDescriptor, MessageDescriptor, ServiceDescriptor};
use protobuf::{Message, SpecialFields, UnknownValueRef};
use protobuf_codegen::{Codegen, Customize, CustomizeCallback};
use protobuf_parse::Parser;
use quote::{quote, ToTokens};
use std::cell::RefCell;
use std::cmp::Ordering;
use std::fs::{read_to_string, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use syn::__private::str;
use walkdir::WalkDir;

fn get_protos(path: impl AsRef<Path>) -> impl Iterator<Item = PathBuf> {
    WalkDir::new(path)
        .into_iter()
        .map(|res| res.expect("failed to read entry"))
        .filter(|entry| entry.path().is_file())
        .filter(|entry| {
            !entry
                .file_name()
                .to_str()
                .expect("invalid filename")
                .starts_with('.')
        })
        .map(|entry| entry.into_path())
}

#[derive(clap::Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Folder containing the proto buffers
    protos: PathBuf,
    /// Target directory
    target: PathBuf,
}

fn main() {
    use clap::Parser;
    let args: Args = Args::parse();
    let protos = get_protos(&args.protos).collect::<Vec<_>>();

    let kinds = get_kinds(&args.protos, &protos);
    let service_generator = ServiceGenerator::new(kinds);
    let service_files = service_generator.files.clone();

    let builder_version_check = format!(
        "const _VENT_PROTO_VERSION_CHECK: () = ::steam_vent_proto_common::VERSION_{};",
        env!("CARGO_PKG_VERSION").replace('.', "_")
    );

    Codegen::new()
        .pure()
        .out_dir(&args.target)
        .include(&args.protos)
        .inputs(protos.iter())
        .customize_callback(service_generator)
        .customize(Customize::default().lite_runtime(true))
        .run_from_script();

    for (file, services) in service_files.borrow().iter() {
        let mut file = proto_path_to_rust_mod(&file);
        file.push_str(".rs");
        let source_file = args.target.join(&file);
        if source_file.exists() {
            let mut code = read_to_string(&source_file).unwrap();
            let extra_code = if !services.is_empty() {
                let service_tokens = services.services.iter().map(Service::gen);
                let method_tokens = services.methods().map(|method| method.gen());
                let message_tokens = services.messages.iter().map(ServiceMessage::gen);
                let import_tokens = services.imports.iter().map(|file| {
                    let path = proto_path_to_rust_mod(file);
                    let path = Ident::new(&path, Span::call_site());
                    quote! {
                        #[allow(unused_imports)]
                        use crate::#path::*;
                    }
                });
                let enum_kind_tokens = services.kind_enums.iter().map(|enum_name| {
                    let ident = Ident::new(&enum_name, Span::call_site());
                    quote!(
                        impl ::steam_vent_proto_common::MsgKindEnum for #ident {}
                    )
                });
                let tokens = quote! {
                    #(#import_tokens)*
                    #(#message_tokens)*
                    #(#service_tokens)*
                    #(#method_tokens)*
                    #(#enum_kind_tokens)*
                };

                let syntax_tree = syn::parse2(tokens).unwrap();
                let formatted = prettyplease::unparse(&syntax_tree);
                format!("{}\n\n{}", builder_version_check, formatted)
            } else {
                builder_version_check.clone()
            };

            code = format!("{}\n\n{}", code, extra_code);
            code = code.replace("::protobuf::", "::steam_vent_proto_common::protobuf::");

            let mut file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&source_file)
                .unwrap();
            file.write_all(code.as_bytes()).unwrap();
        }
    }
}

#[derive(Debug, Clone)]
struct ServiceMethod {
    name: String,
    service_name: String,
    description: Option<String>,
    response: String,
    request: String,
}

impl Hash for ServiceMethod {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.request.hash(state)
    }
}

impl PartialEq for ServiceMethod {
    fn eq(&self, other: &Self) -> bool {
        self.request.eq(&other.request)
    }
}

impl Eq for ServiceMethod {}

impl PartialOrd for ServiceMethod {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.request.partial_cmp(&other.request)
    }
}

impl Ord for ServiceMethod {
    fn cmp(&self, other: &Self) -> Ordering {
        self.request.cmp(&other.request)
    }
}

impl ServiceMethod {
    fn gen(&self) -> TokenStream {
        let name = format!("{}.{}#1", self.service_name, self.name);
        let request_ident = Ident::new(&self.request, Span::call_site());

        let response_ident = if self.response == "NoResponse" {
            quote! {()}
        } else {
            Ident::new(&self.response, Span::call_site()).to_token_stream()
        };
        quote! {
            impl ::steam_vent_proto_common::RpcMethod for #request_ident {
                const METHOD_NAME: &'static str = #name;
                type Response = #response_ident;
            }
        }
    }
}

#[derive(Debug)]
struct Service {
    name: String,
    description: Option<String>,
    methods: Vec<ServiceMethod>,
}

struct ServiceMessage {
    name: String,
    kind: Option<Kind>,
}

impl ServiceMessage {
    fn gen(&self) -> TokenStream {
        let message_ident = Ident::new(&self.name, Span::call_site());
        let kind_tokens = self.kind.as_ref().map(|kind| {
            let kind_ident = kind.ident();
            let enum_ident = kind.enum_ident();
            quote! {
                impl ::steam_vent_proto_common::RpcMessageWithKind for #message_ident {
                    type KindEnum = #enum_ident;
                    const KIND: Self::KindEnum = #kind_ident;
                }
            }
        });

        quote! {
            impl ::steam_vent_proto_common::RpcMessage for #message_ident {
                fn parse(reader: &mut dyn std::io::Read) -> ::protobuf::Result<Self> {
                    <Self as ::protobuf::Message>::parse_from_reader(reader)
                }

                fn write(&self, writer: &mut dyn std::io::Write) -> ::protobuf::Result<()> {
                    use ::protobuf::Message;
                    self.write_to_writer(writer)
                }

                fn encode_size(&self) -> usize {
                    use ::protobuf::Message;
                    self.compute_size() as usize
                }
            }
            #kind_tokens
        }
    }
}

struct FileServices {
    services: Vec<Service>,
    imports: Vec<String>,
    messages: Vec<ServiceMessage>,
    kind_enums: Vec<String>,
}

impl FileServices {
    fn is_empty(&self) -> bool {
        // we don't check imports, since we only need to import stuff if we generate code
        self.services.is_empty() && self.messages.is_empty() && self.kind_enums.is_empty()
    }

    fn methods(&self) -> impl Iterator<Item = ServiceMethod> {
        let methods: AHashSet<ServiceMethod> = self
            .services
            .iter()
            .flat_map(|service| service.methods.iter())
            .cloned()
            .collect();
        let mut methods: Vec<_> = methods.into_iter().collect();
        methods.sort();
        methods.into_iter()
    }
}

struct ServiceGenerator {
    files: Rc<RefCell<AHashMap<String, FileServices>>>,
    descriptions: Rc<RefCell<AHashMap<String, String>>>,
    kinds: Vec<Kind>,
}

impl ServiceGenerator {
    pub fn new(kinds: Vec<Kind>) -> Self {
        Self {
            files: Rc::new(RefCell::new(AHashMap::with_capacity_and_hasher(
                16,
                RandomState::with_seeds(1, 2, 3, 4),
            ))),
            descriptions: Default::default(),
            kinds,
        }
    }

    fn find_kind(&self, message_type: &str, file_name: &str) -> Option<Kind> {
        let postfix = message_type.strip_prefix('C')?;
        self.kinds
            .iter()
            .find(|e_kind| e_kind.matches(postfix, file_name))
            .cloned()
    }
}

fn get_description(fields: &SpecialFields) -> Option<String> {
    for option in fields.unknown_fields().iter() {
        if let UnknownValueRef::LengthDelimited(bytes) = option.1 {
            if let Ok(desc) = String::from_utf8(bytes.into()) {
                return Some(desc);
            }
        }
    }
    None
}

impl From<ServiceDescriptor> for Service {
    fn from(value: ServiceDescriptor) -> Self {
        let name = value.proto().name.clone().unwrap_or_default();
        let methods = value
            .methods()
            .map(|method| ServiceMethod {
                name: method.proto().name.clone().unwrap_or_default(),
                service_name: name.clone(),
                description: get_description(method.proto().options.special_fields()),
                request: (method.input_type().full_name().into()),
                response: method.output_type().full_name().into(),
            })
            .collect();
        Service {
            name,
            description: get_description(value.proto().options.special_fields()),
            methods,
        }
    }
}

impl Service {
    fn gen(&self) -> TokenStream {
        let name = &self.name;
        let desc = self.description.as_deref().unwrap_or_default();
        let struct_name = Ident::new(&self.name, Span::call_site());
        quote! {
            #[doc = #desc]
            struct #struct_name {}

            impl ::steam_vent_proto_common::RpcService for #struct_name {
                const SERVICE_NAME: &'static str = #name;
            }
        }
    }
}

impl CustomizeCallback for ServiceGenerator {
    fn file(&self, file: &FileDescriptor) -> Customize {
        let services: Vec<Service> = file.services().map(Service::from).collect();
        let imports = file
            .deps()
            .iter()
            .map(|dep| dep.name().to_string())
            .filter(|import| !import.starts_with("google"))
            .collect();
        let messages: Vec<_> = file
            .messages()
            .map(|msg| ServiceMessage {
                name: msg.name().into(),
                kind: self.find_kind(msg.name(), file.name()),
            })
            .collect();
        let kind_enums: Vec<_> = file
            .enums()
            .filter_map(|enum_type| {
                (enum_type.name().starts_with("E") && enum_type.name().ends_with("Msg"))
                    .then(|| enum_type.name().to_string())
            })
            .collect();

        for service in services.iter() {
            for method in service.methods.iter() {
                if let Some(description) = method.description.clone() {
                    self.descriptions
                        .borrow_mut()
                        .insert(method.request.clone(), description);
                }
            }
        }

        self.files.borrow_mut().insert(
            file.name().to_string(),
            FileServices {
                services,
                imports,
                messages,
                kind_enums,
            },
        );
        Customize::default()
    }

    fn message(&self, message: &MessageDescriptor) -> Customize {
        if let Some(description) = self.descriptions.borrow().get(message.name()) {
            Customize::default().before(&format!("#[doc = \"{description}\"]"))
        } else {
            Customize::default()
        }
    }
}

fn proto_path_to_rust_mod(path: &str) -> String {
    let without_suffix = path
        .rsplit("/")
        .next()
        .unwrap()
        .strip_suffix(".proto")
        .unwrap();

    without_suffix
        .chars()
        .enumerate()
        .map(|(i, c)| {
            let valid = if i == 0 {
                ident_start(c)
            } else {
                ident_continue(c)
            };
            if valid {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
}

// Copy-pasted from libsyntax.
fn ident_start(c: char) -> bool {
    (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}

// Copy-pasted from libsyntax.
fn ident_continue(c: char) -> bool {
    (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

fn get_kinds(base: &Path, protos: &[PathBuf]) -> Vec<Kind> {
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
        .filter(|(_, e)| e.name().starts_with("E") && e.name().ends_with("Msg"));

    let mut kinds = kinds_enums
        .flat_map(|(mod_name, kinds_enum)| {
            let prefix: String = kinds_enum
                .name()
                .chars()
                .skip(1)
                .take_while(char::is_ascii_uppercase)
                .collect();
            let prefix = prefix[0..prefix.len() - 1].to_string();
            let variant_prefix = format!("k_EMsg{}", prefix);
            let enum_name = kinds_enum.take_name();
            kinds_enum.value.iter_mut().map(move |opt| Kind {
                mod_name: mod_name.clone(),
                enum_name: enum_name.clone(),
                enum_prefix: prefix.to_ascii_lowercase(),
                variant_prefix: variant_prefix.clone(),
                variant: opt.take_name(),
            })
        })
        .collect::<Vec<_>>();

    // sort kinds with prefix in front
    kinds.sort_by(|a, b| a.enum_prefix.len().cmp(&b.enum_prefix.len()).reverse());
    kinds
}

#[derive(Debug, Clone)]
struct Kind {
    mod_name: String,
    enum_name: String,
    enum_prefix: String,
    variant_prefix: String,
    variant: String,
}

impl Kind {
    pub fn matches(&self, struct_name: &str, file_name: &str) -> bool {
        let struct_name = struct_name.strip_prefix("Msg").unwrap_or(struct_name);
        let Some(stripped) = self.variant.strip_prefix(&self.variant_prefix) else {
            return false;
        };
        file_name.contains(&self.enum_prefix) && struct_name.eq_ignore_ascii_case(stripped)
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

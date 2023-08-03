use clap::Parser;
use proc_macro2::{Ident, Span, TokenStream};
use protobuf::reflect::{FileDescriptor, ServiceDescriptor};
use protobuf::{Message, SpecialFields, UnknownValueRef};
use protobuf_codegen::{Codegen, Customize, CustomizeCallback};
use quote::{quote, ToTokens};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::rc::Rc;
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

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Folder containing the proto buffers
    protos: PathBuf,
    /// Target directory
    target: PathBuf,
}

fn main() {
    let args: Args = Args::parse();
    let protos = get_protos(&args.protos).collect::<Vec<_>>();

    let service_generator = ServiceGenerator::default();
    let service_files = service_generator.files.clone();

    Codegen::new()
        .pure()
        .out_dir(&args.target)
        .include(&args.protos)
        .inputs(protos.iter())
        .customize_callback(service_generator)
        .customize(Customize::default().lite_runtime(true))
        .run_from_script();

    for (file, services) in service_files.take().into_iter() {
        let mut file = proto_path_to_rust_mod(&file);
        file.push_str(".rs");
        let source_file = args.target.join(file);
        if source_file.exists() && !services.is_empty() {
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
            let tokens = quote! {
                #(#import_tokens)*
                #(#message_tokens)*
                #(#service_tokens)*
                #(#method_tokens)*
            };

            let syntax_tree = syn::parse2(tokens).unwrap();
            let formatted = prettyplease::unparse(&syntax_tree);

            let mut file = OpenOptions::new()
                .write(true)
                .append(true)
                .truncate(false)
                .open(&source_file)
                .unwrap();
            file.write(formatted.as_bytes()).unwrap();
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
            impl crate::RpcMethod for #request_ident {
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
}

impl ServiceMessage {
    fn gen(&self) -> TokenStream {
        let message_ident = Ident::new(&self.name, Span::call_site());

        quote! {
            impl crate::RpcMessage for #message_ident {
                fn parse(reader: &mut dyn std::io::Read) -> protobuf::Result<Self> {
                    <Self as protobuf::Message>::parse_from_reader(reader)
                }

                fn write(&self, writer: &mut dyn std::io::Write) -> protobuf::Result<()> {
                    use protobuf::Message;
                    self.write_to_writer(writer)
                }

                fn encode_size(&self) -> usize {
                    use protobuf::Message;
                    self.compute_size() as usize
                }
            }
        }
    }
}

struct FileServices {
    services: Vec<Service>,
    imports: Vec<String>,
    messages: Vec<ServiceMessage>,
}

impl FileServices {
    fn is_empty(&self) -> bool {
        // we don't check imports, since we only need to import stuff if we generate code
        self.services.is_empty() && self.messages.is_empty()
    }

    fn methods(&self) -> impl Iterator<Item = ServiceMethod> {
        let methods: HashSet<ServiceMethod> = self
            .services
            .iter()
            .flat_map(|service| service.methods.iter())
            .cloned()
            .collect();
        methods.into_iter()
    }
}

#[derive(Default)]
struct ServiceGenerator {
    files: Rc<RefCell<HashMap<String, FileServices>>>,
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

            impl crate::RpcService for #struct_name {
                const SERVICE_NAME: &'static str = #name;
            }
        }
    }
}

impl CustomizeCallback for ServiceGenerator {
    fn file(&self, file: &FileDescriptor) -> Customize {
        let services = file.services().map(Service::from).collect();
        let imports = file
            .deps()
            .iter()
            .map(|dep| dep.name().to_string())
            .filter(|import| !import.starts_with("google"))
            .collect();
        let messages = file
            .messages()
            .map(|msg| ServiceMessage {
                name: msg.name().into(),
            })
            .collect();
        self.files.borrow_mut().insert(
            file.name().to_string(),
            FileServices {
                services,
                imports,
                messages,
            },
        );
        Customize::default()
    }
}

fn proto_path_to_rust_mod(path: &str) -> String {
    let without_suffix = path.strip_suffix(".proto").unwrap();

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

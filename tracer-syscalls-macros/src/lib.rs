use convert_case::{Case, Casing};
use paste::paste;
use proc_macro::TokenStream;
use proc_macro_crate::{crate_name, FoundCrate};
use quote::{format_ident, quote, ToTokens};
use syn::{
  braced, bracketed, parenthesized, parse::Parse, parse_macro_input, punctuated::Punctuated,
  spanned::Spanned, token, Field, Ident, PathArguments, Token, Type,
};

struct SyscallEntry {
  name: syn::Ident,
  paren_token: token::Paren,
  raw_args: Punctuated<Field, Token![,]>,
  separator: Token![/],
  brace_token: token::Brace,
  args: Punctuated<Field, Token![,]>,
  arrow: Token![->],
  ret: Punctuated<Ident, Token![+]>,
  for_tokens: Token![for],
  bracket_token: token::Bracket,
  archs: Punctuated<Arch, Token![,]>,
}

impl Parse for SyscallEntry {
  fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
    let content;
    let raw_args;
    let archs_content;
    Ok(SyscallEntry {
      name: input.parse()?,
      paren_token: parenthesized!(raw_args in input),
      raw_args: raw_args.parse_terminated(Field::parse_named, Token![,])?,
      separator: input.parse()?,
      brace_token: braced!(content in input),
      args: content.parse_terminated(Field::parse_named, Token![,])?,
      arrow: input.parse()?,
      ret: Punctuated::<Ident, Token![+]>::parse_separated_nonempty(input)?,
      for_tokens: input.parse()?,
      bracket_token: bracketed!(archs_content in input),
      archs: archs_content.parse_terminated(Arch::parse, Token![,])?,
    })
  }
}

struct Arch {
  name: syn::Ident,
  colon: Token![:],
  number: syn::LitInt,
}

impl Parse for Arch {
  fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
    Ok(Arch {
      name: input.parse()?,
      colon: input.parse()?,
      number: input.parse()?,
    })
  }
}

struct GenSyscallArgsStructResult {
  args_struct: proc_macro2::TokenStream,
  name: Ident,
  args_struct_type: Ident,
  archs: Vec<String>,
  syscall_number: Ident,
}

fn gen_syscall_args_struct(
  syscall: &SyscallEntry,
  crate_token: proc_macro2::TokenStream,
) -> GenSyscallArgsStructResult {
  let name = &syscall.name;
  let args = &syscall.args;
  let arch_name_0 = syscall.archs.first().as_ref().unwrap().name.to_string();
  let arch_number_0 = &syscall.archs.first().as_ref().unwrap().number;
  let (mut arch_names, numbers): (Vec<_>, Vec<_>) = syscall
    .archs
    .iter()
    .skip(1)
    .map(|x| (x.name.to_string(), x.number.clone()))
    .unzip();
  let syscall_number = quote! {
    if cfg!(target_arch = #arch_name_0) {
      #arch_number_0
    }
    #(
    else if cfg!(target_arch = #arch_names) {
      #numbers
    }
    )*
    else {
      unreachable!()
    }
  };
  arch_names.insert(0, arch_name_0);
  let mut camel_case_name = name.to_string().to_case(Case::UpperCamel);
  let camel_case_ident = Ident::new(&camel_case_name, name.span());
  camel_case_name.push_str("Args");
  let camel_case_args_type = Ident::new(&camel_case_name, name.span());
  let mut inspects = vec![];
  let mut arg_names = vec![];
  let mut wrapped_arg_types = vec![];
  for (i, arg) in args.iter().enumerate() {
    let arg_name = &arg.ident;
    arg_names.push(arg_name.clone().unwrap());
    let arg_type = &arg.ty;
    let wrapped_arg_type = wrap_syscall_arg_type(arg_type, crate_token.clone());
    wrapped_arg_types.push(wrapped_arg_type.clone());
    let literal_i = syn::LitInt::new(&i.to_string(), arg_type.span());
    // TODO: We shouldn't compare types as strings
    match arg_type.to_token_stream().to_string().as_str() {
      // Primitive types
      "i32" | "i64" | "isize" | "i16" | "RawFd" | "socklen_t" | "c_int" => {
        let inspect = quote! {
          let #arg_name = syscall_arg!(regs, #literal_i) as #wrapped_arg_type;
        };
        inspects.push(inspect);
      }
      // Types that need memory inspection
      _ => {
        let inspect = quote! {
          let #arg_name = #crate_token::InspectFromPid::inspect_from(pid, syscall_arg!(regs, #literal_i) as #crate_token::AddressType);
        };
        inspects.push(inspect);
      }
    }
  }
  let syscall_const_name = format_ident!("SYS_{}", name);
  GenSyscallArgsStructResult {
    syscall_number: syscall_const_name.clone(),
    args_struct: quote::quote! {
      #[cfg(any(#(target_arch = #arch_names),*))]
      pub const #syscall_const_name: isize = #syscall_number;

      #[cfg(any(#(target_arch = #arch_names),*))]
      #[derive(Debug, Clone, PartialEq)]
      pub struct #camel_case_args_type {
        #(#arg_names: #wrapped_arg_types),*
      }

      impl #crate_token::SyscallNumber for #camel_case_args_type {
        #[inline(always)]
        fn syscall_number(&self) -> isize {
          #syscall_const_name
        }
      }

      impl From<#camel_case_args_type> for #crate_token::SyscallArgs {
        fn from(args: #camel_case_args_type) -> Self {
          #crate_token::SyscallArgs::#camel_case_ident(args)
        }
      }

      impl #crate_token::FromInspectingRegs for #camel_case_args_type {
        fn from_inspecting_regs(pid: #crate_token::Pid, regs: &#crate_token::arch::PtraceRegisters) -> Self {
          use #crate_token::arch::syscall_arg;
          #(#inspects)*
          Self {
            #(#arg_names),*
          }
        }
      }
    },
    name: camel_case_ident,
    args_struct_type: camel_case_args_type,
    archs: arch_names.clone(),
  }
}

#[proc_macro]
pub fn gen_syscalls(input: TokenStream) -> TokenStream {
  let input =
    parse_macro_input!(input with Punctuated::<SyscallEntry, syn::Token![,]>::parse_terminated);
  let mut arg_structs = vec![];
  let mut arg_struct_names = vec![];
  let mut arg_struct_types = vec![];
  let mut supported_archs = vec![];
  let mut syscall_numbers = vec![];
  let crate_token = get_crate("tracer-syscalls");
  for syscall in &input {
    let GenSyscallArgsStructResult {
      args_struct,
      name,
      args_struct_type,
      archs,
      syscall_number,
    } = gen_syscall_args_struct(syscall, crate_token.clone());
    arg_structs.push(args_struct);
    arg_struct_types.push(args_struct_type);
    arg_struct_names.push(name);
    supported_archs.push(archs);
    syscall_numbers.push(syscall_number.clone());
  }
  TokenStream::from(quote::quote! {
    #(#arg_structs)*
    #[non_exhaustive]
    #[derive(Debug, Clone, PartialEq)]
    pub enum SyscallArgs {
      #(
        #[cfg(any(#(target_arch = #supported_archs),*))]
        #arg_struct_names(#arg_struct_types),
      )*
      Unknown(#crate_token::UnknownArgs),
    }

    impl #crate_token::SyscallNumber for SyscallArgs {
      #[inline(always)]
      fn syscall_number(&self) -> isize {
        match self {
          #(
            SyscallArgs::#arg_struct_names(args) => args.syscall_number(),
          )*
          SyscallArgs::Unknown(args) => args.syscall_number(),
        }
      }
    }

    impl #crate_token::FromInspectingRegs for SyscallArgs {
      fn from_inspecting_regs(pid: #crate_token::Pid, regs: &#crate_token::arch::PtraceRegisters) -> Self {
        use #crate_token::arch::syscall_no_from_regs;
        match syscall_no_from_regs!(regs) as isize {
          #(
            #syscall_numbers => {
              SyscallArgs::#arg_struct_names(#crate_token::FromInspectingRegs::from_inspecting_regs(pid, regs))
            },
          )*
          _ => {
            SyscallArgs::Unknown(#crate_token::FromInspectingRegs::from_inspecting_regs(pid, regs))
          }
        }
      }
    }
  })
}

fn get_crate(name: &str) -> proc_macro2::TokenStream {
  let found_crate =
    crate_name(name).unwrap_or_else(|_| panic!("`{}` not found in `Cargo.toml`", name));

  match found_crate {
    FoundCrate::Itself => quote!(crate),
    FoundCrate::Name(name) => {
      let ident = format_ident!("{}", &name);
      quote!( #ident )
    }
  }
}

fn wrap_syscall_arg_type(
  ty: &Type,
  crate_token: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
  match ty {
    Type::Path(ty) => {
      assert_eq!(ty.path.segments.len(), 1);
      let ty = &ty.path.segments[0];

      let ty_str = ty.to_token_stream().to_string();
      match ty_str.as_str() {
        "i32" => quote!(i32),
        "i64" => quote!(i64),
        "isize" => quote!(isize),
        "i16" => quote!(i16),
        "c_int" => quote!(c_int),
        "socklen_t" => quote!(socklen_t),
        "sockaddr" => quote!(Result<sockaddr, #crate_token::InspectError>),
        "RawFd" => quote!(RawFd),
        "CString" => quote!(Result<CString, #crate_token::InspectError>),
        "PathBuf" => quote!(Result<PathBuf, #crate_token::InspectError>),
        _ => {
          if ty.ident == "Option" {
            let PathArguments::AngleBracketed(arg) = &ty.arguments else {
              panic!("Unsupported syscall arg type: {:?}", ty_str);
            };
            let arg = arg.args.to_token_stream().to_string();
            match arg.as_str() {
              "PathBuf" => quote!(Result<Option<PathBuf>, #crate_token::InspectError>),
              _ => panic!("Unsupported syscall arg type: {:?}", arg),
            }
          } else if ty.ident == "Vec" {
            let PathArguments::AngleBracketed(arg) = &ty.arguments else {
              panic!("Unsupported syscall arg type: {:?}", ty_str);
            };
            let arg = arg.args.to_token_stream().to_string();
            match arg.as_str() {
              "CString" => quote!(Result<Vec<CString>, #crate_token::InspectError>),
              _ => panic!("Unsupported syscall arg type: {:?}", arg),
            }
          } else {
            panic!("Unsupported syscall arg type: {:?}", ty_str);
          }
        }
      }
    }
    _ => panic!("Multi segment path is not supported here"),
  }
}

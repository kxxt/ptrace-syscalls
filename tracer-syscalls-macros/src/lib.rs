use convert_case::{Case, Casing};
use paste::paste;
use proc_macro::TokenStream;
use proc_macro_crate::{crate_name, FoundCrate};
use quote::{format_ident, quote};
use syn::{
  braced, bracketed, parse::Parse, parse_macro_input, punctuated::Punctuated, token, Field, Ident,
  Token,
};

struct SyscallEntry {
  name: syn::Ident,
  number: syn::LitInt,
  brace_token: token::Brace,
  args: Punctuated<Field, Token![,]>,
  for_tokens: Token![for],
  bracket_token: token::Bracket,
  archs: Punctuated<Ident, Token![,]>,
}

impl Parse for SyscallEntry {
  fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
    let content;
    let archs_content;
    Ok(SyscallEntry {
      name: input.parse()?,
      number: input.parse()?,
      brace_token: braced!(content in input),
      args: content.parse_terminated(Field::parse_named, Token![,])?,
      for_tokens: input.parse()?,
      bracket_token: bracketed!(archs_content in input),
      archs: archs_content.parse_terminated(Ident::parse, Token![,])?,
    })
  }
}

struct GenSyscallArgsStructResult {
  args_struct: proc_macro2::TokenStream,
  name: Ident,
  args_struct_type: Ident,
  archs: Vec<String>,
}

fn gen_syscall_args_struct(
  syscall: &SyscallEntry,
  crate_token: proc_macro2::TokenStream,
) -> GenSyscallArgsStructResult {
  let number = &syscall.number;
  let name = &syscall.name;
  let args = &syscall.args;
  let archs = &syscall
    .archs
    .iter()
    .map(|x| x.to_string())
    .collect::<Vec<_>>();
  let mut camel_case_name = name.to_string().to_case(Case::UpperCamel);
  let camel_case_ident = Ident::new(&camel_case_name, name.span());
  camel_case_name.push_str("Args");
  let camel_case_args_type = Ident::new(&camel_case_name, name.span());
  GenSyscallArgsStructResult {
    args_struct: quote::quote! {
      #[cfg(any(#(target_arch = #archs),*))]
      #[derive(Debug, Clone, PartialEq)]
      pub struct #camel_case_args_type {
        #args
      }

      impl #crate_token::SyscallNumber for #camel_case_args_type {
        #[inline(always)]
        fn syscall_number(&self) -> isize {
          #number as isize
        }
      }

      impl From<#camel_case_args_type> for #crate_token::SyscallArgs {
        fn from(args: #camel_case_args_type) -> Self {
          #crate_token::SyscallArgs::#camel_case_ident(args)
        }
      }
    },
    name: camel_case_ident,
    args_struct_type: camel_case_args_type,
    archs: archs.clone(),
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
    } = gen_syscall_args_struct(syscall, crate_token.clone());
    arg_structs.push(args_struct);
    arg_struct_types.push(args_struct_type);
    arg_struct_names.push(name);
    supported_archs.push(archs);
    syscall_numbers.push(syscall.number.clone());
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
            SyscallArgs::#arg_struct_names(_) => #syscall_numbers as isize,
          )*
          SyscallArgs::Unknown(args) => args.syscall_number(),
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

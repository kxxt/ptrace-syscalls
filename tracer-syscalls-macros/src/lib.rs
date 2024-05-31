use convert_case::{Case, Casing};
use paste::paste;
use proc_macro::TokenStream;
use proc_macro_crate::{crate_name, FoundCrate};
use quote::{format_ident, quote, ToTokens};
use syn::{
  braced, bracketed, parenthesized, parse::Parse, parse_macro_input, punctuated::Punctuated,
  spanned::Spanned, token, Field, Ident, PathArguments, Token, Type, TypePath,
};

struct ModifiedArgsExpr {
  plus: Token![+],
  brace_token: token::Brace,
  args: Punctuated<Field, Token![,]>,
}

impl Parse for ModifiedArgsExpr {
  fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
    let content;
    Ok(Self {
      plus: input.parse()?,
      brace_token: braced!(content in input),
      args: content.parse_terminated(Field::parse_named, Token![,])?,
    })
  }
}

struct SyscallEntry {
  name: syn::Ident,
  paren_token: token::Paren,
  raw_args: Punctuated<Field, Token![,]>,
  separator: Token![/],
  brace_token: token::Brace,
  args: Punctuated<Field, Token![,]>,
  arrow: Token![->],
  result: Ident,
  modified_args: Option<ModifiedArgsExpr>,
  for_token: Token![for],
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
      result: input.parse()?,
      modified_args: {
        let lookahead = input.lookahead1();
        if lookahead.peek(token::Plus) {
          Some(input.parse()?)
        } else {
          None
        }
      },
      for_token: input.parse()?,
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
  raw_args_struct: proc_macro2::TokenStream,
  modified_args_struct: proc_macro2::TokenStream,
  name: Ident,
  args_struct_type: Ident,
  raw_args_struct_type: Ident,
  modified_args_struct_type: Ident,
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
  camel_case_name.replace_range((camel_case_name.len() - 4).., "RawArgs");
  let camel_case_raw_args_type = Ident::new(&camel_case_name, name.span());
  camel_case_name.replace_range((camel_case_name.len() - 7).., "ModifiedArgs");
  let camel_case_modified_args_type = Ident::new(&camel_case_name, name.span());
  let mut inspects = vec![];
  let mut arg_names = vec![];
  let mut wrapped_arg_types = vec![];
  for arg in args.iter() {
    let i = syscall
      .raw_args
      .iter()
      .position(|x| x.ident == arg.ident)
      .unwrap();
    let arg_name = &arg.ident;
    arg_names.push(arg_name.clone().unwrap());
    let arg_type = &arg.ty;
    let (wrapped_arg_type, need_memory_inspection) =
      wrap_syscall_arg_type(arg_type, crate_token.clone());
    wrapped_arg_types.push(wrapped_arg_type.clone());
    let literal_i = syn::LitInt::new(&i.to_string(), arg_type.span());
    if !need_memory_inspection {
      let inspect = quote! {
        let #arg_name = syscall_arg!(regs, #literal_i) as #wrapped_arg_type;
      };
      inspects.push(inspect);
    } else {
      let inspect = quote! {
        let #arg_name = #crate_token::InspectFromPid::inspect_from(inspectee_pid, syscall_arg!(regs, #literal_i) as #crate_token::AddressType);
      };
      inspects.push(inspect);
    }
  }
  let mut raw_arg_names = vec![];
  let mut raw_arg_types = vec![];
  let mut inspect_raw_args = vec![];
  for (i, raw_arg) in syscall.raw_args.iter().enumerate() {
    let arg_name = &raw_arg.ident;
    raw_arg_names.push(arg_name.clone().unwrap());
    let arg_type = &raw_arg.ty;
    raw_arg_types.push(arg_type.clone());
    let literal_i = syn::LitInt::new(&i.to_string(), arg_type.span());
    inspect_raw_args.push(quote! {
      let #arg_name = syscall_arg!(regs, #literal_i) as #arg_type;
    });
  }
  let mut modified_arg_names = vec![];
  let mut modified_arg_types = vec![];
  let mut inspect_modified_args = vec![];
  let syscall_result_type = &syscall.result;
  modified_arg_names.push(format_ident!("syscall_result"));
  modified_arg_types.push(quote! { #syscall_result_type });
  inspect_modified_args.push(if syscall_result_type != "Unit" {
    quote! {
      let syscall_result = syscall_res_from_regs!(regs) as #syscall_result_type;
    }
  } else {
    quote! {let syscall_result = ();}
  });
  if let Some(modified_args) = &syscall.modified_args {
    for modified_arg in modified_args.args.iter() {
      let i = syscall
        .raw_args
        .iter()
        .position(|x| x.ident == modified_arg.ident)
        .unwrap();
      let arg_name = &modified_arg.ident;
      modified_arg_names.push(arg_name.clone().unwrap());
      let arg_type = &modified_arg.ty;
      let (wrapped_arg_type, need_memory_inspection) =
        wrap_syscall_arg_type(arg_type, crate_token.clone());
      modified_arg_types.push(wrapped_arg_type.clone());
      let literal_i = syn::LitInt::new(&i.to_string(), arg_type.span());
      if !need_memory_inspection {
        let inspect = quote! {
          let #arg_name = syscall_arg!(regs, #literal_i) as #wrapped_arg_type;
        };
        inspect_modified_args.push(inspect);
      } else {
        let inspect = quote! {
          let #arg_name = #crate_token::InspectFromPid::inspect_from(inspectee_pid, syscall_arg!(regs, #literal_i) as #crate_token::AddressType);
        };
        inspect_modified_args.push(inspect);
      }
    }
  }
  let syscall_const_name = format_ident!("SYS_{}", name);
  GenSyscallArgsStructResult {
    syscall_number: syscall_const_name.clone(),
    raw_args_struct: quote! {
      #[cfg(any(#(target_arch = #arch_names),*))]
      #[derive(Debug, Clone, Copy, PartialEq)]
      pub struct #camel_case_raw_args_type {
        #(#raw_arg_names: #raw_arg_types),*
      }

      #[cfg(any(#(target_arch = #arch_names),*))]
      impl #crate_token::FromInspectingRegs for #camel_case_raw_args_type {
        fn from_inspecting_regs(inspectee_pid: #crate_token::Pid, regs: &#crate_token::arch::PtraceRegisters) -> Self {
          use #crate_token::arch::syscall_arg;
          #(#inspect_raw_args)*
          Self {
            #(#raw_arg_names),*
          }
        }
      }

      #[cfg(any(#(target_arch = #arch_names),*))]
      impl #crate_token::SyscallNumber for #camel_case_raw_args_type {
        #[inline(always)]
        fn syscall_number(&self) -> isize {
          #syscall_const_name
        }
      }
    },
    args_struct: quote::quote! {
      #[cfg(any(#(target_arch = #arch_names),*))]
      pub const #syscall_const_name: isize = #syscall_number;

      #[cfg(any(#(target_arch = #arch_names),*))]
      #[derive(Debug, Clone, PartialEq)]
      pub struct #camel_case_args_type {
        #(#arg_names: #wrapped_arg_types),*
      }

      #[cfg(any(#(target_arch = #arch_names),*))]
      impl #crate_token::SyscallNumber for #camel_case_args_type {
        #[inline(always)]
        fn syscall_number(&self) -> isize {
          #syscall_const_name
        }
      }

      #[cfg(any(#(target_arch = #arch_names),*))]
      impl From<#camel_case_args_type> for #crate_token::SyscallArgs {
        fn from(args: #camel_case_args_type) -> Self {
          #crate_token::SyscallArgs::#camel_case_ident(args)
        }
      }

      #[cfg(any(#(target_arch = #arch_names),*))]
      impl #crate_token::FromInspectingRegs for #camel_case_args_type {
        fn from_inspecting_regs(inspectee_pid: #crate_token::Pid, regs: &#crate_token::arch::PtraceRegisters) -> Self {
          use #crate_token::arch::syscall_arg;
          #(#inspects)*
          Self {
            #(#arg_names),*
          }
        }
      }
    },
    modified_args_struct: quote! {
      #[cfg(any(#(target_arch = #arch_names),*))]
      #[derive(Debug, Clone, PartialEq)]
      pub struct #camel_case_modified_args_type {
        #(#modified_arg_names: #modified_arg_types),*
      }

      #[cfg(any(#(target_arch = #arch_names),*))]
      impl #crate_token::SyscallNumber for #camel_case_modified_args_type {
        #[inline(always)]
        fn syscall_number(&self) -> isize {
          #syscall_const_name
        }
      }

      #[cfg(any(#(target_arch = #arch_names),*))]
      impl From<#camel_case_modified_args_type> for #crate_token::SyscallModifiedArgs {
        fn from(args: #camel_case_modified_args_type) -> Self {
          #crate_token::SyscallModifiedArgs::#camel_case_ident(args)
        }
      }

      #[cfg(any(#(target_arch = #arch_names),*))]
      impl #crate_token::FromInspectingRegs for #camel_case_modified_args_type {
        fn from_inspecting_regs(inspectee_pid: #crate_token::Pid, regs: &#crate_token::arch::PtraceRegisters) -> Self {
          use #crate_token::arch::syscall_arg;
          #(#inspect_modified_args)*
          Self {
            #(#modified_arg_names),*
          }
        }
      }
    },
    name: camel_case_ident,
    args_struct_type: camel_case_args_type,
    raw_args_struct_type: camel_case_raw_args_type,
    modified_args_struct_type: camel_case_modified_args_type,
    archs: arch_names.clone(),
  }
}

#[proc_macro]
pub fn gen_syscalls(input: TokenStream) -> TokenStream {
  let input =
    parse_macro_input!(input with Punctuated::<SyscallEntry, syn::Token![,]>::parse_terminated);
  let mut arg_structs = vec![];
  let mut raw_arg_structs = vec![];
  let mut modified_arg_structs = vec![];
  let mut names = vec![];
  let mut raw_arg_struct_types = vec![];
  let mut arg_struct_types = vec![];
  let mut modified_arg_struct_types = vec![];
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
      raw_args_struct,
      raw_args_struct_type,
      modified_args_struct,
      modified_args_struct_type,
    } = gen_syscall_args_struct(syscall, crate_token.clone());
    arg_structs.push(args_struct);
    raw_arg_structs.push(raw_args_struct);
    modified_arg_structs.push(modified_args_struct);
    arg_struct_types.push(args_struct_type);
    raw_arg_struct_types.push(raw_args_struct_type);
    modified_arg_struct_types.push(modified_args_struct_type);
    names.push(name);
    supported_archs.push(archs);
    syscall_numbers.push(syscall_number.clone());
  }
  TokenStream::from(quote::quote! {
    #(#raw_arg_structs)*
    #(#arg_structs)*
    #(#modified_arg_structs)*
    #[non_exhaustive]
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum SyscallRawArgs {
      #(
        #[cfg(any(#(target_arch = #supported_archs),*))]
        #names(#raw_arg_struct_types),
      )*
      Unknown(#crate_token::UnknownArgs),
    }

    #[non_exhaustive]
    #[derive(Debug, Clone, PartialEq)]
    pub enum SyscallArgs {
      #(
        #[cfg(any(#(target_arch = #supported_archs),*))]
        #names(#arg_struct_types),
      )*
      Unknown(#crate_token::UnknownArgs),
    }

    #[non_exhaustive]
    #[derive(Debug, Clone, PartialEq)]
    pub enum SyscallModifiedArgs {
      #(
        #[cfg(any(#(target_arch = #supported_archs),*))]
        #names(#modified_arg_struct_types),
      )*
      Unknown(#crate_token::UnknownArgs),
    }

    impl #crate_token::SyscallNumber for SyscallRawArgs {
      #[inline(always)]
      fn syscall_number(&self) -> isize {
        match self {
          #(
            Self::#names(args) => args.syscall_number(),
          )*
          Self::Unknown(args) => args.syscall_number(),
        }
      }
    }

    impl #crate_token::SyscallNumber for SyscallArgs {
      #[inline(always)]
      fn syscall_number(&self) -> isize {
        match self {
          #(
            Self::#names(args) => args.syscall_number(),
          )*
          Self::Unknown(args) => args.syscall_number(),
        }
      }
    }

    impl #crate_token::FromInspectingRegs for SyscallArgs {
      fn from_inspecting_regs(inspectee_pid: #crate_token::Pid, regs: &#crate_token::arch::PtraceRegisters) -> Self {
        use #crate_token::arch::syscall_no_from_regs;
        match syscall_no_from_regs!(regs) as isize {
          #(
            #syscall_numbers => {
              Self::#names(#crate_token::FromInspectingRegs::from_inspecting_regs(inspectee_pid, regs))
            },
          )*
          _ => {
            Self::Unknown(#crate_token::FromInspectingRegs::from_inspecting_regs(inspectee_pid, regs))
          }
        }
      }
    }

    impl #crate_token::FromInspectingRegs for SyscallRawArgs {
      fn from_inspecting_regs(pid: #crate_token::Pid, regs: &#crate_token::arch::PtraceRegisters) -> Self {
        use #crate_token::arch::syscall_no_from_regs;
        match syscall_no_from_regs!(regs) as isize {
          #(
            #syscall_numbers => {
              Self::#names(#crate_token::FromInspectingRegs::from_inspecting_regs(pid, regs))
            },
          )*
          _ => {
            Self::Unknown(#crate_token::FromInspectingRegs::from_inspecting_regs(pid, regs))
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

/// returns: (wrapped type, needs memory inspection)
fn wrap_syscall_arg_type(
  ty: &Type,
  crate_token: proc_macro2::TokenStream,
) -> (proc_macro2::TokenStream, bool) {
  match ty {
    Type::Array(ty) => {
      (quote!(Result<#ty, #crate_token::InspectError>), true)
    },
    Type::Path(ty) => {
      assert_eq!(ty.path.segments.len(), 1);
      let ty = &ty.path.segments[0];
      let ty_str = ty.to_token_stream().to_string();
      match ty_str.as_str() {
        "Unit" => (quote!(()), false),
        "RawFd" | "socklen_t" | "c_int" | "c_uint" | "c_ulong" | "i16" | "i32" | "i64" | "u64"
        | "usize" | "isize" | "size_t" | "key_serial_t" | "AddressType" | "mode_t" | "uid_t" | "pid_t"
        | "gid_t" | "off_t" | "u32" | "clockid_t" => (ty.to_token_stream(), false),
        "sockaddr" | "CString" | "PathBuf" | "timex" | "cap_user_header" | "cap_user_data"
        | "timespec" | "clone_args" | "epoll_event" | "sigset_t" | "stat" | "statfs" | "futex_waitv" | "user_desc" => {
          (quote!(Result<#ty, #crate_token::InspectError>), true)
        }
        _ => {
          if ty.ident == "Option" {
            let PathArguments::AngleBracketed(arg) = &ty.arguments else {
              panic!("Unsupported syscall arg type: {:?}", ty_str);
            };
            let arg = arg.args.to_token_stream().to_string();
            match arg.as_str() {
              "PathBuf" | "timespec" | "Vec < CString >" | "CString" | "Vec < c_ulong >"=> {
                (quote!(Result<#ty, #crate_token::InspectError>), true)
              }
              _ => panic!("Unsupported inner syscall arg type: {:?}", arg),
            }
          } else if ty.ident == "Vec" {
            let PathArguments::AngleBracketed(arg) = &ty.arguments else {
              panic!("Unsupported inner syscall arg type: {:?}", ty_str);
            };
            let arg = arg.args.to_token_stream().to_string();
            match arg.as_str() {
              "u8" | "CString" | "epoll_event" | "futex_waitv" | "c_ulong" | "linux_dirent" | "linux_dirent64"=> {
                (quote!(Result<#ty, #crate_token::InspectError>), true)
              }
              _ => panic!("Unsupported inner syscall arg type: {:?}", arg),
            }
          } else if ty.ident == "Result" {
            (quote!(#ty), true)
          } else {
            panic!("Unsupported syscall arg type: {:?}", ty_str);
          }
        }
      }
    }
    _ => panic!("Multi segment path is not supported here"),
  }
}

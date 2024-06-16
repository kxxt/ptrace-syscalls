use convert_case::{Case, Casing};
use paste::paste;
use proc_macro::TokenStream;
use proc_macro2::Span;
use proc_macro_crate::{crate_name, FoundCrate};
use quote::{format_ident, quote, quote_spanned, ToTokens};
use syn::{
  braced, bracketed, parenthesized, parse::Parse, parse_macro_input, punctuated::Punctuated,
  spanned::Spanned, token, Expr, Field, GenericArgument, Ident, PathArguments, Token, Type,
  TypePath,
};

struct ModifiedArgsExpr {
  plus: Token![+],
  brace_token: token::Brace,
  args: Punctuated<ArgField, Token![,]>,
}

impl Parse for ModifiedArgsExpr {
  fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
    let content;
    Ok(Self {
      plus: input.parse()?,
      brace_token: braced!(content in input),
      args: content.parse_terminated(ArgField::parse, Token![,])?,
    })
  }
}

struct Decoder {
  at: Token![@],
  func: Ident,
  paren_token: token::Paren,
  args: Punctuated<Expr, Token![,]>,
}

impl Parse for Decoder {
  fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
    let content;
    Ok(Self {
      at: input.parse()?,
      func: input.parse()?,
      paren_token: parenthesized!(content in input),
      args: content.parse_terminated(Expr::parse, Token![,])?,
    })
  }
}

struct ArgField {
  ident: Ident,
  colon_token: Token![:],
  ty: Type,
  decoder: Option<Decoder>,
}

impl Parse for ArgField {
  fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
    let ident = input.parse()?;
    let colon_token = input.parse()?;
    let ty = input.parse()?;
    let lookahead = input.lookahead1();
    let decoder = if lookahead.peek(Token![@]) {
      Some(input.parse()?)
    } else {
      None
    };
    Ok(Self {
      ident,
      colon_token,
      ty,
      decoder,
    })
  }
}

struct SyscallEntry {
  name: syn::Ident,
  paren_token: token::Paren,
  raw_args: Punctuated<ArgField, Token![,]>,
  separator: Token![/],
  brace_token: token::Brace,
  args: Punctuated<ArgField, Token![,]>,
  arrow: Token![->],
  result: Ident,
  modified_args: Option<ModifiedArgsExpr>,
  for_token: Token![for],
  bracket_token: token::Bracket,
  archs: Punctuated<Arch, Token![,]>,
  group_token: Token![~],
  bracket_token_2: token::Bracket,
  groups: Punctuated<Ident, Token![,]>,
  span: Option<Span>,
}

impl Parse for SyscallEntry {
  fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
    let content;
    let raw_args;
    let archs_content;
    let groups_content;
    let start;
    let end;
    Ok(SyscallEntry {
      name: {
        let name: Ident = input.parse()?;
        start = name.span();
        name
      },
      paren_token: parenthesized!(raw_args in input),
      raw_args: raw_args.parse_terminated(ArgField::parse, Token![,])?,
      separator: input.parse()?,
      brace_token: braced!(content in input),
      args: content.parse_terminated(ArgField::parse, Token![,])?,
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
      group_token: input.parse()?,
      bracket_token_2: bracketed!(groups_content in input),
      groups: groups_content.parse_terminated(Ident::parse, Token![,])?,
      for_token: input.parse()?,
      bracket_token: bracketed!(archs_content in input),
      archs: {
        let archs = archs_content.parse_terminated(Arch::parse, Token![,])?;
        end = archs.last().unwrap().span;
        archs
      },
      span: end.and_then(|end| start.join(end)),
    })
  }
}

struct Arch {
  name: syn::Ident,
  colon: Token![:],
  number: syn::LitInt,
  span: Option<Span>,
}

impl Parse for Arch {
  fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
    let start;
    let end;
    Ok(Arch {
      name: {
        let name: Ident = input.parse()?;
        start = name.span();
        name
      },
      colon: input.parse()?,
      number: {
        let number: syn::LitInt = input.parse()?;
        end = number.span();
        number
      },
      span: start.join(end),
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
  syscall_const_name: Ident,
}

fn gen_syscall_args_struct(
  syscall: &SyscallEntry,
  crate_token: proc_macro2::TokenStream,
) -> GenSyscallArgsStructResult {
  let span = syscall.span.clone().unwrap_or_else(|| Span::call_site());
  let name = &syscall.name;
  let args = &syscall.args;
  let groups_idents = &syscall.groups.iter().collect::<Vec<_>>();
  let groups = if groups_idents.is_empty() {
    quote_spanned! { span =>
      #crate_token::SyscallGroups::empty()
    }
  } else {
    quote_spanned! { span =>
      #(#crate_token::SyscallGroups::#groups_idents)|*
    }
  };
  let arch_name_0 = syscall.archs.first().as_ref().unwrap().name.to_string();
  let arch_number_0 = &syscall.archs.first().as_ref().unwrap().number;
  let (mut arch_names, numbers): (Vec<_>, Vec<_>) = syscall
    .archs
    .iter()
    .skip(1)
    .map(|x| (x.name.to_string(), x.number.clone()))
    .unzip();
  let syscall_number = quote_spanned! { span =>
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
    let arg_name = &arg.ident;
    arg_names.push(arg_name.clone());
    let arg_type = &arg.ty;
    let (wrapped_arg_type, need_memory_inspection) =
      wrap_syscall_arg_type(arg_type, crate_token.clone());
    wrapped_arg_types.push(wrapped_arg_type.clone());
    if !need_memory_inspection {
      let inspect = quote_spanned! { span =>
        let #arg_name = raw_args.#arg_name as #wrapped_arg_type;
      };
      inspects.push(inspect);
    } else {
      let inspect = quote_spanned! { span =>
        let #arg_name = #crate_token::InspectFromPid::inspect_from(inspectee_pid, raw_args.#arg_name as #crate_token::AddressType);
      };
      inspects.push(inspect);
    }
  }
  let mut raw_arg_names = vec![];
  let mut raw_arg_types = vec![];
  let mut inspect_raw_args = vec![];
  for (i, raw_arg) in syscall.raw_args.iter().enumerate() {
    let arg_name = &raw_arg.ident;
    raw_arg_names.push(arg_name.clone());
    let arg_type = &raw_arg.ty;
    raw_arg_types.push(arg_type.clone());
    let literal_i = syn::LitInt::new(&i.to_string(), arg_type.span());
    inspect_raw_args.push(quote_spanned! { span =>
      let #arg_name = syscall_arg!(regs, #literal_i) as #arg_type;
    });
  }
  let mut modified_arg_names = vec![];
  let mut modified_arg_names_err = vec![];
  let mut modified_arg_types = vec![];
  let mut inspect_modified_args = vec![];
  let syscall_result_type = &syscall.result;
  modified_arg_names.push(format_ident!("syscall_result"));
  modified_arg_types.push(quote_spanned! { span => #syscall_result_type });
  let (inspect_syscall_result, is_syscall_failed) = if syscall_result_type != "Unit" {
    (
      quote_spanned! {
        span =>
        let syscall_result = syscall_res_from_regs!(regs) as #syscall_result_type;
      },
      quote_spanned! { span => (syscall_result as isize) < 0 },
    )
  } else {
    (
      quote_spanned! { span => let syscall_result = (); },
      quote_spanned! { span => false },
    )
  };
  if let Some(modified_args) = &syscall.modified_args {
    for modified_arg in modified_args.args.iter() {
      let arg_name = &modified_arg.ident;
      modified_arg_names.push(arg_name.clone());
      modified_arg_names_err.push(quote_spanned! { span =>
        #arg_name: Err(InspectError::SyscallFailure)
      });
      let arg_type = &modified_arg.ty;
      let (wrapped_arg_type, need_memory_inspection) =
        wrap_syscall_arg_type(arg_type, crate_token.clone());
      modified_arg_types.push(wrapped_arg_type.clone());
      if !need_memory_inspection {
        let inspect = quote_spanned! { span =>
          let #arg_name = raw_args.#arg_name as #wrapped_arg_type;
        };
        inspect_modified_args.push(inspect);
      } else {
        let inspect = quote_spanned! { span =>
          let #arg_name = #crate_token::InspectFromPid::inspect_from(inspectee_pid, raw_args.#arg_name as #crate_token::AddressType);
        };
        inspect_modified_args.push(inspect);
      }
    }
  }
  let syscall_const_name = format_ident!("SYS_{}", name);
  GenSyscallArgsStructResult {
    syscall_number: syscall_const_name.clone(),
    raw_args_struct: quote_spanned! { span =>
      #[cfg(any(#(target_arch = #arch_names),*))]
      pub const #syscall_const_name: isize = #syscall_number;

      #[cfg(any(#(target_arch = #arch_names),*))]
      #[derive(Debug, Clone, Copy, PartialEq)]
      pub struct #camel_case_raw_args_type {
        #(pub #raw_arg_names: #raw_arg_types),*
      }

      #[cfg(any(#(target_arch = #arch_names),*))]
      impl #camel_case_raw_args_type {
        fn from_regs(regs: &#crate_token::arch::PtraceRegisters) -> Self {
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

      #[cfg(any(#(target_arch = #arch_names),*))]
      impl #crate_token::SyscallGroupsGetter for #camel_case_raw_args_type {
        #[inline(always)]
        fn syscall_groups(&self) -> ::enumflags2::BitFlags<#crate_token::SyscallGroups> {
          use ::enumflags2::BitFlag;
          {
            #groups
          }.into()
        }
      }

      #[cfg(any(#(target_arch = #arch_names),*))]
      impl #crate_token::SyscallStopInspect for #camel_case_raw_args_type {
        type Args = #camel_case_args_type;
        type Result = #camel_case_modified_args_type;
        fn inspect_sysenter(self, inspectee_pid: Pid) -> Self::Args {
          let raw_args = self;
          #(#inspects)*
          Self::Args {
            #(#arg_names),*
          }
        }
        fn inspect_sysexit(self, inspectee_pid: Pid, regs: &PtraceRegisters) -> Self::Result {
          let raw_args = self;
          #inspect_syscall_result
          if #is_syscall_failed {
            Self::Result {
              syscall_result,
              #(#modified_arg_names_err),*
            }
          } else {
            #(#inspect_modified_args)*
            Self::Result {
              #(#modified_arg_names),*
            }
          }
        }
      }
    },
    args_struct: quote_spanned! { span =>
      #[cfg(any(#(target_arch = #arch_names),*))]
      #[derive(Debug, Clone, PartialEq)]
      pub struct #camel_case_args_type {
        #(pub #arg_names: #wrapped_arg_types),*
      }

      #[cfg(any(#(target_arch = #arch_names),*))]
      impl #crate_token::SyscallNumber for #camel_case_args_type {
        #[inline(always)]
        fn syscall_number(&self) -> isize {
          #syscall_const_name
        }
      }

      #[cfg(any(#(target_arch = #arch_names),*))]
      impl #crate_token::SyscallGroupsGetter for #camel_case_args_type {
        #[inline(always)]
        fn syscall_groups(&self) -> ::enumflags2::BitFlags<#crate_token::SyscallGroups> {
          use ::enumflags2::BitFlag;
          {
            #groups
          }.into()
        }
      }

      #[cfg(any(#(target_arch = #arch_names),*))]
      impl From<#camel_case_args_type> for #crate_token::SyscallArgs {
        fn from(args: #camel_case_args_type) -> Self {
          #crate_token::SyscallArgs::#camel_case_ident(args)
        }
      }
    },
    modified_args_struct: quote_spanned! { span =>
      #[cfg(any(#(target_arch = #arch_names),*))]
      #[derive(Debug, Clone, PartialEq)]
      pub struct #camel_case_modified_args_type {
        #(pub #modified_arg_names: #modified_arg_types),*
      }

      #[cfg(any(#(target_arch = #arch_names),*))]
      impl #crate_token::SyscallNumber for #camel_case_modified_args_type {
        #[inline(always)]
        fn syscall_number(&self) -> isize {
          #syscall_const_name
        }
      }

      #[cfg(any(#(target_arch = #arch_names),*))]
      impl #crate_token::SyscallGroupsGetter for #camel_case_modified_args_type {
        #[inline(always)]
        fn syscall_groups(&self) -> ::enumflags2::BitFlags<#crate_token::SyscallGroups> {
          use ::enumflags2::BitFlag;
          {
            #groups
          }.into()
        }
      }

      #[cfg(any(#(target_arch = #arch_names),*))]
      impl From<#camel_case_modified_args_type> for #crate_token::SyscallModifiedArgs {
        fn from(args: #camel_case_modified_args_type) -> Self {
          #crate_token::SyscallModifiedArgs::#camel_case_ident(args)
        }
      }

    },
    name: camel_case_ident,
    args_struct_type: camel_case_args_type,
    raw_args_struct_type: camel_case_raw_args_type,
    modified_args_struct_type: camel_case_modified_args_type,
    archs: arch_names.clone(),
    syscall_const_name,
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
  let mut syscall_names_dedup = vec![];
  let mut supported_archs_dedup = vec![];
  let mut syscall_consts = vec![];
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
      syscall_const_name,
    } = gen_syscall_args_struct(syscall, crate_token.clone());
    arg_structs.push(args_struct);
    raw_arg_structs.push(raw_args_struct);
    modified_arg_structs.push(modified_args_struct);
    arg_struct_types.push(args_struct_type);
    raw_arg_struct_types.push(raw_args_struct_type);
    modified_arg_struct_types.push(modified_args_struct_type);
    names.push(name.clone());
    supported_archs.push(archs.clone());
    syscall_numbers.push(syscall_number.clone());
    syscall_consts.push(syscall_const_name);
    if syscall_names_dedup.last() != Some(&syscall.name) {
      syscall_names_dedup.push(syscall.name.clone());
      supported_archs_dedup.push(archs.clone());
    } else {
      supported_archs_dedup.last_mut().unwrap().extend(archs);
    }
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
            #[cfg(any(#(target_arch = #supported_archs),*))]
            Self::#names(args) => args.syscall_number(),
          )*
          Self::Unknown(args) => args.syscall_number(),
        }
      }
    }

    impl #crate_token::SyscallGroupsGetter for SyscallRawArgs {
      #[inline(always)]
      fn syscall_groups(&self) -> ::enumflags2::BitFlags<#crate_token::SyscallGroups> {
        match self {
          #(
            #[cfg(any(#(target_arch = #supported_archs),*))]
            Self::#names(args) => args.syscall_groups(),
          )*
          Self::Unknown(args) => args.syscall_groups(),
        }
      }
    }

    impl #crate_token::SyscallNumber for SyscallArgs {
      #[inline(always)]
      fn syscall_number(&self) -> isize {
        match self {
          #(
            #[cfg(any(#(target_arch = #supported_archs),*))]
            Self::#names(args) => args.syscall_number(),
          )*
          Self::Unknown(args) => args.syscall_number(),
        }
      }
    }

    impl #crate_token::SyscallGroupsGetter for SyscallArgs {
      #[inline(always)]
      fn syscall_groups(&self) -> ::enumflags2::BitFlags<#crate_token::SyscallGroups> {
        match self {
          #(
            #[cfg(any(#(target_arch = #supported_archs),*))]
            Self::#names(args) => args.syscall_groups(),
          )*
          Self::Unknown(args) => args.syscall_groups(),
        }
      }
    }

    impl SyscallRawArgs {
      fn from_regs(regs: &#crate_token::arch::PtraceRegisters) -> Self {
        use #crate_token::arch::syscall_no_from_regs;
        match syscall_no_from_regs!(regs) as isize {
          #(
            #[cfg(any(#(target_arch = #supported_archs),*))]
            #syscall_numbers => {
              Self::#names(#raw_arg_struct_types::from_regs(regs))
            },
          )*
          _ => {
            Self::Unknown(UnknownArgs::from_regs(regs))
          }
        }
      }
    }

    impl SyscallStopInspect for SyscallRawArgs {
      type Args = SyscallArgs;
      type Result = SyscallModifiedArgs;

      fn inspect_sysenter(self, inspectee_pid: Pid) -> Self::Args {
        match self {
          #(
            #[cfg(any(#(target_arch = #supported_archs),*))]
            Self::#names(raw_args) => {
              SyscallArgs::#names(raw_args.inspect_sysenter(inspectee_pid))
            },
          )*
          Self::Unknown(unknown) => {
            SyscallArgs::Unknown(unknown)
          }
        }
      }

      fn inspect_sysexit(self, inspectee_pid: Pid, regs: &PtraceRegisters) -> Self::Result {
        match self {
          #(
            #[cfg(any(#(target_arch = #supported_archs),*))]
            Self::#names(raw_args) => {
              SyscallModifiedArgs::#names(raw_args.inspect_sysexit(inspectee_pid, regs))
            },
          )*
          Self::Unknown(unknown) => {
            SyscallModifiedArgs::Unknown(unknown)
          }
        }
      }
    }

    // This is not going to work. TODO: maybe create a rust issue for #[cfg(macro!(...))]?
    // #[macro_export]
    // macro_rules! cfg_if_has_syscall {
    //   // match if/else chains with a final `else`
    //   (
    //       $(
    //           if #[has $i_syscall:ident] { $( $i_tokens:tt )* }
    //       ) else+
    //       else { $( $e_tokens:tt )* }
    //   ) => {
    //     ::cfg_if::cfg_if! {
    //       $(
    //           if #[cfg($crate::cfg_if_has_syscall!(__internal__, $i_syscall))] { $( $i_tokens:tt )* }
    //       ) else+
    //       else { $( $e_tokens:tt )* }
    //     }
    //   };

    //   // match if/else chains lacking a final `else`
    //   (
    //       if #[has $i_syscall:ident] { $( $i_tokens:tt )* }
    //       $(
    //           else if #[has $e_syscall:ident] { $( $e_tokens:tt )* }
    //       )*
    //   ) => {
    //     ::cfg_if::cfg_if! {
    //       if #[cfg($crate::cfg_if_has_syscall!(__internal__, $i_syscall))] { $( $i_tokens:tt )* }
    //       $(
    //           else if #[cfg($crate::cfg_if_has_syscall!(__internal__, $e_syscall))] { $( $e_tokens:tt )* }
    //       )*
    //     }
    //   };
    //   #(
    //     (__internal__, #syscall_names_dedup) => {
    //       any(#(target_arch = #supported_archs_dedup),*)
    //     }
    //   );*
    // }
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
      let element_ty = &ty.elem;
      (quote!(Result<#ty, InspectError<Vec<#element_ty>>>), true)
    }
    Type::Path(ty) => {
      assert_eq!(ty.path.segments.len(), 1);
      let ty = &ty.path.segments[0];
      let ty_str = ty.to_token_stream().to_string();
      match ty_str.as_str() {
        "Unit" => (quote!(()), false),
        "RawFd" | "socklen_t" | "c_int" | "c_uint" | "c_ulong" | "c_long" | "i16" | "i32"
        | "i64" | "u64" | "usize" | "isize" | "size_t" | "key_serial_t" | "AddressType"
        | "mode_t" | "uid_t" | "pid_t" | "gid_t" | "off_t" | "u32" | "clockid_t" | "id_t"
        | "key_t" | "mqd_t" | "aio_context_t" | "dev_t" | "nfds_t" | "loff_t" | "qid_t"
        | "idtype_t" | "time_t" | "timer_t" => (ty.to_token_stream(), false),
        "sockaddr"
        | "CString"
        | "PathBuf"
        | "iovec"
        | "timex"
        | "cap_user_header"
        | "cap_user_data"
        | "timespec"
        | "clone_args"
        | "epoll_event"
        | "sigset_t"
        | "stat"
        | "statfs"
        | "futex_waitv"
        | "user_desc"
        | "itimerval"
        | "rlimit"
        | "rusage"
        | "timeval"
        | "__aio_sigset"
        | "timezone"
        | "iocb"
        | "io_event"
        | "io_uring_params"
        | "open_how"
        | "landlock_ruleset_attr"
        | "mq_attr"
        | "sigevent"
        | "msqid_ds"
        | "pollfd"
        | "__mount_arg"
        | "msghdr"
        | "riscv_hwprobe"
        | "siginfo_t"
        | "sched_attr"
        | "sched_param"
        | "stack_t"
        | "mnt_id_req"
        | "statx"
        | "sysinfo"
        | "itimerspec"
        | "tms"
        | "utsname"
        | "ustat"
        | "shmid_ds"
        | "cachestat"
        | "cachestat_range" => (quote!(InspectResult<#ty>), true),
        _ => {
          if ty.ident == "Option" {
            let PathArguments::AngleBracketed(arg) = &ty.arguments else {
              panic!("Unsupported syscall arg type: {:?}", ty_str);
            };
            let argstr = arg.args.to_token_stream().to_string();
            match argstr.as_str() {
              "PathBuf" | "timespec" | "Vec < CString >" | "CString" | "Vec < c_ulong >"
              | "Vec < c_uint >" | "Vec < gid_t >" | "timezone" | "mq_attr" | "siginfo_t"
              | "sigset_t" | "iovec" | "rlimit64" | "fd_set" | "sockaddr" | "sigaction"
              | "timeval" | "itimerval" | "stack_t" | "timer_t" | "time_t" | "sigevent"
              | "itimerspec" | "utimbuf" | "rusage" => (quote!(InspectResult<#ty>), true),
              "[timespec; 2]" | "[timeval; 2]"
               | "[timespec ; 2]" | "[timeval ; 2]"
                => {
                let GenericArgument::Type(inner) = arg.args.first().unwrap() else {
                  panic!("Unsupported inner syscall arg type: {:?}", argstr);
                };
                let Type::Array(inner) = inner else {
                  panic!("Unsupported inner syscall arg type: {:?}", argstr)
                };
                let element_ty = &inner.elem;
                (quote!(Result<#ty, InspectError<Vec<#element_ty>>>), true)
              }
              _ => panic!("Unsupported inner syscall arg type: {:?}", argstr),
            }
          } else if ty.ident == "Vec" {
            let PathArguments::AngleBracketed(arg) = &ty.arguments else {
              panic!("Unsupported inner syscall arg type: {:?}", ty_str);
            };
            let arg = arg.args.to_token_stream().to_string();
            match arg.as_str() {
              "c_int" | "u8" | "CString" | "epoll_event" | "futex_waitv" | "c_ulong"
              | "linux_dirent" | "io_event" | "linux_dirent64" | "gid_t" | "AddressType"
              | "kexec_segment" | "c_uchar" | "u64" | "mount_attr" | "pollfd" | "iovec"
              | "riscv_hwprobe" | "mmsghdr" | "sembuf" => (quote!(InspectResult<#ty>), true),
              _ => panic!("Unsupported inner syscall arg type: {:?}", arg),
            }
          } else if ty.ident == "InspectResult" {
            (quote!(#ty), true)
          } else if ty.ident == "Arc" {
            let PathArguments::AngleBracketed(arg) = &ty.arguments else {
              panic!("Unsupported inner syscall arg type: {:?}", ty_str);
            };
            let arg = arg.args.to_token_stream().to_string();
            match arg.as_str() {
              "rseq" | "statmount" => (quote!(InspectResult<#ty>), true),
              _ => panic!("Unsupported inner syscall arg type: {:?}", arg),
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

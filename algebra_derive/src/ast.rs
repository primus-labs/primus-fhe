use proc_macro2::{Ident, Span};
use syn::{DeriveInput, Error, Generics, Index, Member, Result, Type};

use crate::attr::{self, Attrs};

pub(crate) struct Input<'a> {
    pub(crate) original: &'a DeriveInput,
    pub(crate) attrs: Attrs,
    pub(crate) ident: Ident,
    pub(crate) _generics: &'a Generics,
    pub(crate) field: Field<'a>,
}

pub(crate) struct Field<'a> {
    pub(crate) original: &'a syn::Field,
    pub(crate) _member: Member,
    pub(crate) ty: &'a Type,
}

impl<'a> Input<'a> {
    pub(crate) fn from_syn(node: &'a DeriveInput) -> Result<Self> {
        let attrs = attr::get(&node.attrs)?;

        if attrs.modulus.is_none() {
            return Err(Error::new_spanned(node, "modulus should supplied"));
        }

        match node.data {
            syn::Data::Struct(ref data) => {
                let field = match data.fields.iter().next() {
                    Some(field) => field,
                    None => {
                        return Err(Error::new_spanned(
                            node,
                            "one element in struct is necessary",
                        ))
                    }
                };
                let field = Field::from_syn(field)?;

                Ok(Input {
                    original: node,
                    attrs,
                    ident: node.ident.clone(),
                    _generics: &node.generics,
                    field,
                })
            }
            _ => Err(Error::new_spanned(node, "only struct is supported")),
        }
    }
}

impl<'a> Field<'a> {
    fn from_syn(node: &'a syn::Field) -> Result<Self> {
        Ok(Field {
            original: node,
            _member: node.ident.clone().map(Member::Named).unwrap_or_else(|| {
                Member::Unnamed(Index {
                    index: 0,
                    span: Span::call_site(),
                })
            }),
            ty: &node.ty,
        })
    }
}

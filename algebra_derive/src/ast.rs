use proc_macro2::{Ident, Span};
use syn::{DeriveInput, Error, Generics, Index, Member, Result, Type};

use crate::attr::{self, Attrs};

pub(crate) struct Input<'a> {
    pub original: &'a DeriveInput,
    pub attrs: Attrs,
    pub ident: Ident,
    pub generics: &'a Generics,
    pub field: Field<'a>,
}

pub(crate) struct Field<'a> {
    pub original: &'a syn::Field,
    pub member: Member,
    pub ty: &'a Type,
}

impl<'a> Input<'a> {
    pub(crate) fn from_syn(node: &'a DeriveInput) -> Result<Self> {
        match &node.data {
            syn::Data::Struct(data) => {
                let attrs = attr::get(&node.attrs)?;

                if attrs.modulus.is_none() {
                    return Err(Error::new_spanned(node, "modulus should supplied"));
                }

                let first = match &data.fields.iter().next() {
                    Some(f) => *f,
                    None => {
                        return Err(Error::new_spanned(
                            node,
                            "one element in struct is necessary",
                        ))
                    }
                };
                let field = Field::from_syn(first)?;

                Ok(Input {
                    original: node,
                    attrs,
                    ident: node.ident.clone(),
                    generics: &node.generics,
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
            member: node.ident.clone().map(Member::Named).unwrap_or_else(|| {
                Member::Unnamed(Index {
                    index: 0,
                    span: Span::call_site(),
                })
            }),
            ty: &node.ty,
        })
    }
}

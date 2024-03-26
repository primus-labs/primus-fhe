use proc_macro2::Ident;
use syn::{DeriveInput, Error, Generics, Result, Type};

use crate::attr::{self, Attrs};

pub(crate) struct Input<'a> {
    pub(crate) _original: &'a DeriveInput,
    pub(crate) attrs: Attrs,
    pub(crate) ident: Ident,
    pub(crate) _generics: &'a Generics,
    pub(crate) field: Field<'a>,
}

#[derive(Clone, Copy)]
pub(crate) struct Field<'a> {
    pub(crate) original: &'a syn::Field,
    pub(crate) ty: &'a Type,
}

impl<'a> Input<'a> {
    pub(crate) fn from_syn(node: &'a DeriveInput) -> Result<Self> {
        match node.data {
            syn::Data::Struct(ref data) => {
                let mut field_iter = data.fields.iter();
                let field = match field_iter.next() {
                    Some(field) => field,
                    None => return Err(Error::new_spanned(node, "One element is necessary.")),
                };
                if let Some(second_field) = field_iter.next() {
                    return Err(Error::new_spanned(
                        second_field,
                        "Only one element is enough. Do not supply more elements.",
                    ));
                }
                let field = Field::from_syn(field)?;

                let attrs = attr::get(node, field)?;

                Ok(Input {
                    _original: node,
                    attrs,
                    ident: node.ident.clone(),
                    _generics: &node.generics,
                    field,
                })
            }
            _ => Err(Error::new_spanned(node, "Only struct is supported.")),
        }
    }
}

impl<'a> Field<'a> {
    fn from_syn(node: &'a syn::Field) -> Result<Self> {
        if let Some(ident) = node.ident.as_ref() {
            return Err(Error::new_spanned(
                ident,
                "Named field like `self.x` is not supported. You should use an unnamed field like `self.0`.",
            ));
        }
        Ok(Field {
            original: node,
            ty: &node.ty,
        })
    }
}

use pkcs11::types::*;

#[derive(Debug)]
pub(crate) enum ObjectClass {
    Certificate,
    PrivateKey,
}

impl Into<&CK_OBJECT_CLASS> for &ObjectClass {
    fn into(self) -> &'static CK_OBJECT_CLASS {
        match self {
            ObjectClass::Certificate => &CKO_CERTIFICATE,
            ObjectClass::PrivateKey => &CKO_PRIVATE_KEY,
        }
    }
}

macro_rules! attributes {
    ($($name:ident<$t:ty> => $cka:expr),*) => {
        #[derive(Debug, PartialEq)]
        pub(crate) enum AttributeType {
            $($name,)*
        }

        #[derive(Debug)]
        pub(crate) enum Attribute {
            $($name($t),)*
        }

        impl Into<AttributeType> for &Attribute {
            fn into(self) -> AttributeType {
                match self {
                    $(Attribute::$name(_) => AttributeType::$name,)*
                }
            }
        }

        impl Into<CK_ATTRIBUTE_TYPE> for &AttributeType {
            fn into(self) -> CK_ATTRIBUTE_TYPE {
                match self {
                    $(AttributeType::$name => $cka,)*
                }
            }
        }
    };
}

attributes![
    Class<ObjectClass> => CKA_CLASS,
    Label<String> => CKA_LABEL,
    Token<bool> => CKA_TOKEN,
    Value<Vec<CK_BYTE>> => CKA_VALUE,
    Issuer<Vec<CK_BYTE>> => CKA_ISSUER,
    SerialNumber<Vec<CK_BYTE>> => CKA_SERIAL_NUMBER,
    Subject<Vec<CK_BYTE>> => CKA_SUBJECT,
    Id<Vec<CK_BYTE>> => CKA_ID,
    Private<bool> => CKA_PRIVATE,
    CertificateType<CK_CERTIFICATE_TYPE> => CKA_CERTIFICATE_TYPE,
    Modulus<Vec<CK_BYTE>> => CKA_MODULUS,
    ModulusBits<Vec<CK_BYTE>> => CKA_MODULUS_BITS,
    PublicExponent<Vec<CK_BYTE>> => CKA_PUBLIC_EXPONENT,
    KeyType<CK_KEY_TYPE> => CKA_KEY_TYPE,
    Sensitive<bool> => CKA_SENSITIVE,
    Sign<bool> => CKA_SIGN
];

impl Into<CK_ATTRIBUTE> for &Attribute {
    fn into(self) -> CK_ATTRIBUTE {
        match self {
            Attribute::Class(class) => CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(class.into()),
            Attribute::Label(label) => CK_ATTRIBUTE::new(CKA_LABEL).with_string(label),
            Attribute::Token(token) => CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(match token {
                true => &CK_TRUE,
                _ => &CK_FALSE,
            }),
            Attribute::Issuer(issuer) => CK_ATTRIBUTE::new(CKA_ISSUER).with_bytes(issuer),
            _ => unimplemented!(),
        }
    }
}

impl From<(CK_ATTRIBUTE, Vec<u8>)> for Attribute {
    fn from((template, buffer): (CK_ATTRIBUTE, Vec<u8>)) -> Self {
        match template.attrType {
            CKA_LABEL => Self::Label(String::from_utf8(buffer).unwrap()),
            CKA_VALUE => Self::Value(buffer),
            CKA_ISSUER => Self::Issuer(buffer),
            CKA_SERIAL_NUMBER => Self::SerialNumber(buffer),
            CKA_SUBJECT => Self::Subject(buffer),
            CKA_ID => Self::Id(buffer),
            CKA_MODULUS => Self::Modulus(buffer),
            CKA_MODULUS_BITS => Self::ModulusBits(buffer),
            CKA_PUBLIC_EXPONENT => Self::PublicExponent(buffer),
            _ => unimplemented!(),
        }
    }
}

impl Attribute {
    pub(crate) fn ty(&self) -> AttributeType {
        self.into()
    }
}

pub(crate) struct Attributes {
    vec: Vec<Attribute>,
}

impl From<(Vec<CK_ATTRIBUTE>, Vec<Vec<u8>>)> for Attributes {
    fn from((template, buffers): (Vec<CK_ATTRIBUTE>, Vec<Vec<u8>>)) -> Self {
        Self {
            vec: template
                .into_iter()
                .zip(buffers.into_iter())
                .map(Attribute::from)
                .collect(),
        }
    }
}

impl Attributes {
    pub(crate) fn of_type(&self, ty: AttributeType) -> Option<&Attribute> {
        self.vec.iter().find(|&attr| attr.ty() == ty)
    }
}

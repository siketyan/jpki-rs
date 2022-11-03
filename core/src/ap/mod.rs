//! Collection of APs that corresponds with DF (Dedicated File) in the card

pub mod crypto;
pub mod support;
pub mod surface;

pub use self::crypto::CryptoAp;
pub use self::support::SupportAp;
pub use self::surface::SurfaceAp;

macro_rules! open {
    ($t: ty, $ctx: ty, $df: expr) => {
        /// Opens the AP in the card by selecting the DF.
        pub fn open(ctx: Ctx, card: Rc<crate::Card<$t, $ctx>>) -> Result<Self, crate::card::Error> {
            let ap = Self { card };

            ap.card.select_df(ctx, $df.into()).map(|_| ap)
        }
    };
}

pub(crate) use open;

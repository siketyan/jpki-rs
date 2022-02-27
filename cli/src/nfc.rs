use std::marker::PhantomData;
use std::ptr;

use nfc1_sys as libnfc;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Input / output error, device may not be usable anymore without re-open it")]
    IOError,

    #[error("Invalid argument(s)")]
    InvalidArgument,

    #[error("Operation not supported by device")]
    DeviceNotSupported,

    #[error("No such device")]
    NoSuchDevice,

    #[error("Buffer overflow")]
    BufferOverflow,

    #[error("Operation timed out")]
    OperationTimeout,

    #[error("Operation aborted (by user)")]
    OperationAborted,

    #[error("Not (yet) implemented")]
    NotImplemented,

    #[error("Target released")]
    TargetReleased,

    #[error("Error while RF transmission")]
    RFTransmission,

    #[error("MIFARE Classic: authentication failed")]
    MFCAuthenticationFailed,

    #[error("Software error (allocation, file/pipe creation, etc.)")]
    Software,

    #[error("Device's internal chip error")]
    Chip,

    #[error("Error occurred during library initialization")]
    InitializationFailed,

    #[error("Unknown error: {0}")]
    Unknown(i32),
}

impl From<i32> for Error {
    fn from(e: i32) -> Self {
        match e {
            libnfc::NFC_EIO => Self::IOError,
            libnfc::NFC_EINVARG => Self::InvalidArgument,
            libnfc::NFC_EDEVNOTSUPP => Self::DeviceNotSupported,
            libnfc::NFC_ENOTSUCHDEV => Self::NoSuchDevice,
            libnfc::NFC_EOVFLOW => Self::BufferOverflow,
            libnfc::NFC_ETIMEOUT => Self::OperationTimeout,
            libnfc::NFC_EOPABORTED => Self::OperationAborted,
            libnfc::NFC_ENOTIMPL => Self::NotImplemented,
            libnfc::NFC_ETGRELEASED => Self::TargetReleased,
            libnfc::NFC_ERFTRANS => Self::RFTransmission,
            libnfc::NFC_EMFCAUTHFAIL => Self::MFCAuthenticationFailed,
            libnfc::NFC_ESOFT => Self::Software,
            libnfc::NFC_ECHIP => Self::Chip,
            _ => Self::Unknown(e),
        }
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

macro_rules! as_result {
    ($i: expr) => {
        if ($i as i32) < nfc1_sys::NFC_SUCCESS as i32 {
            Err(Error::from($i as i32))
        } else {
            Ok($i)
        }
    };
}

pub struct Context<'a> {
    ptr: *mut libnfc::nfc_context,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> Context<'a> {
    pub fn try_new() -> Result<Self> {
        let mut ptr: *mut libnfc::nfc_context = ptr::null_mut();
        unsafe { libnfc::nfc_init(&mut ptr) }

        if ptr.is_null() {
            Err(Error::InitializationFailed)
        } else {
            Ok(Self {
                ptr,
                _lifetime: Default::default(),
            })
        }
    }

    pub fn open<'b>(&self) -> Result<Device<'b>> {
        let ptr: *mut nfc1_sys::nfc_device = unsafe { libnfc::nfc_open(self.ptr, ptr::null_mut()) };
        if ptr.is_null() {
            Err(Error::InitializationFailed)
        } else {
            Ok(Device::new(ptr))
        }
    }
}

impl<'a> Drop for Context<'a> {
    fn drop(&mut self) {
        unsafe {
            libnfc::nfc_exit(self.ptr);
        }
    }
}

pub struct Device<'a> {
    ptr: *mut libnfc::nfc_device,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> Device<'a> {
    fn new(ptr: *mut libnfc::nfc_device) -> Self {
        Self {
            ptr,
            _lifetime: Default::default(),
        }
    }
}

impl<'a> Drop for Device<'a> {
    fn drop(&mut self) {
        unsafe {
            libnfc::nfc_close(self.ptr);
        }
    }
}

pub struct Initiator<'a> {
    device: Device<'a>,
}

impl<'a> Initiator<'a> {
    pub fn select_dep_target(self) -> Result<Target<'a>> {
        let target: *mut nfc1_sys::nfc_target = ptr::null_mut();
        as_result!(unsafe {
            nfc1_sys::nfc_initiator_select_dep_target(
                self.device.ptr,
                nfc1_sys::nfc_dep_mode_NDM_PASSIVE,
                nfc1_sys::nfc_baud_rate_NBR_212,
                ptr::null_mut(),
                target,
                1000,
            )
        })?;

        Ok(Target {
            initiator: self,
            _info: target,
        })
    }
}

impl<'a> TryFrom<Device<'a>> for Initiator<'a> {
    type Error = Error;

    fn try_from(device: Device<'a>) -> std::result::Result<Self, Self::Error> {
        as_result!(unsafe { nfc1_sys::nfc_initiator_init(device.ptr) })?;

        Ok(Self { device })
    }
}

pub struct Target<'a> {
    initiator: Initiator<'a>,
    _info: *mut nfc1_sys::nfc_target,
}

impl<'a> Target<'a> {
    pub fn transmit(&self, tx: &[u8]) -> Result<Vec<u8>> {
        let mut rx = vec![0u8; 512];
        let len: i32 = as_result!(unsafe {
            nfc1_sys::nfc_initiator_transceive_bytes(
                self.initiator.device.ptr,
                tx.as_ptr(),
                tx.len() as nfc1_sys::size_t,
                rx.as_mut_ptr(),
                rx.len() as nfc1_sys::size_t,
                0,
            )
        })?;

        unsafe {
            rx.set_len(len as usize);
        }

        Ok(rx)
    }
}

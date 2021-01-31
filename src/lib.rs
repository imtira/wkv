// This Source Code Form is subject to the terms of the Mozilla Public License,
// v. 2.0. If a copy of the MPL was not distributed with this file, You can
// obtain one at https://mozilla.org/MPL/2.0/.
#![feature(try_trait)]
#![warn(clippy::all, clippy::restriction, clippy::pedantic, clippy::nursery)]
#![allow(clippy::blanket_clippy_restriction_lints,
         clippy::enum_glob_use,
         clippy::implicit_return,
         clippy::integer_arithmetic,
         clippy::missing_errors_doc)]
//! Windows Key Validation
//! Validate and/or identify Windows product keys.

/// Main error enum returned when an invalid key is parsed
#[derive(Clone, Debug, PartialEq)]
pub enum WKVError
{
  /// There are no product key formats that match the length of the given key
  TooShort,
  /// There are no product key formats that match the length of the given key
  TooLong,
  /// `(sum of relevant digits) % 7 != 0`
  /// Only applies to formats using Microsoft's "mod 7" scheme.
  BadMod7,
  /// Expected a digit, encountered a character
  ExpectedDigit,
  /// For formats that explicitly bar certain digit(s) from being in certain
  /// place(s).
  InvalidDigitPosition,
  /// Used when converting from NoneError. Usually encountered when .get()
  /// accesses a range that's larger than the slice.
  BadAccess,
}

// Used with .get(). If the get is out of range, the key is too short.
impl std::convert::From<std::option::NoneError> for WKVError
{
  #[inline]
  fn from(_: std::option::NoneError) -> Self
  {
    Self::BadAccess
  }
}

/// Represents a key, invalid or otherwise.
#[derive(Clone, Debug, PartialEq)]
pub struct Key
{
  /// The Windows release that this key is used for.
  pub release: KeyType,
}

/// An enum containing every type of Windows key that wkv can validate.
#[derive(Clone, Copy, Debug, PartialEq)]
// The enum names are pretty self-explanatory here.
#[allow(clippy::missing_docs_in_private_items)]
pub enum KeyType
{
  Windows95,
  Windows95OEM,
  Windows98,
  Unknown,
}

/// Validates a given `key`. Returns a [`Key`](struct.Key.html)
#[inline]
pub fn validate(key: &'_ str) -> Result<Key, WKVError>
{
  match key.len() {
    x if x <= 10 => Err(WKVError::TooShort),
    // Ex: 000-0000000
    11 => validate_windows95(key),
    _ => Err(WKVError::TooLong),
  }
}

/// Validates a Windows 95 format key.
///
/// # Accuracy
/// Many sources on Windows 95 key validation are roughly correct, but
/// nonetheless inaccurate. Fortunately, [stacksmashing](https://youtu.be/cwyH59nACzQ)
/// decompiled the Windows 95 installer to confirm its specific workings.
///
/// This function is simply a Rust reimplementation of that function.
///
/// # References
/// <https://youtu.be/cwyH59nACzQ>
#[inline]
pub fn validate_windows95(key: &'_ str) -> Result<Key, WKVError>
{
  match key.get(0..=2)? {
    "333" | "444" | "555" | "666" | "777" | "888" | "999" => Err(WKVError::InvalidDigitPosition),
    _ =>
      if mod7(key.as_bytes().get(4..)?)? {
        Ok(Key { release: KeyType::Windows95, })
      } else {
        Err(WKVError::BadMod7)
      },
  }
}

/// mod7 implements Microsoft's "mod 7" validation scheme, as described here:
/// <https://youtu.be/cwyH59nACzQ?t=306>
#[inline]
#[allow(clippy::as_conversions)]
pub fn mod7(key: &[u8]) -> Result<bool, WKVError>
{
  Ok(key.iter().try_fold(0_u32, |a, &x| {
                  match (x as char).to_digit(10) {
                    Some(x) => Ok(a + x),
                    None => Err(WKVError::ExpectedDigit),
                  }
                })?
     % 7
     == 0)
}

#[cfg(test)]
/// Some of these tests may look bizzare and clearly wrong. They are designed
/// to ensure wkv validates keys that are also validated as a result of quirks
/// in Windows. For example, Windows 95 keys are supposed to be purely numeric
/// in the format DDD-DDDDDDD, but the fourth character is always ignored
/// and the first three are only validated by ensuring they aren't one of 333
/// 444, 555, 666, 777, 888, or 999, ergo YOLO111111 is completely valid.
mod tests
{
  use super::*;

  #[test]
  #[allow(clippy::non_ascii_literal)]
  fn very_invalid()
  {
    assert_eq!(validate("8Oݼ񰤁ܢ잲Nܾ󌥀z㿒"), Err(WKVError::TooLong));
  }

  #[test]
  fn empty()
  {
    assert_eq!(validate(""), Err(WKVError::TooShort));
  }

  #[test]
  fn w95_all_zeroes()
  {
    assert_eq!(validate("000-0000000"),
               Ok(Key { release: KeyType::Windows95, }));
  }

  #[test]
  fn w95_yolo()
  {
    assert_eq!(validate("YOLO1111111"),
               Ok(Key { release: KeyType::Windows95, }));
  }

  #[test]
  fn w95_real()
  {
    assert_eq!(validate("757-2573155"),
               Ok(Key { release: KeyType::Windows95, }));
  }

  #[test]
  fn w95_invalid()
  {
    assert_eq!(validate("555-5555555"), Err(WKVError::InvalidDigitPosition));
  }

  #[test]
  fn w95_invalid_good_start()
  {
    assert_eq!(validate("000-5555555"), Err(WKVError::BadMod7));
  }
}

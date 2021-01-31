# wkv

Validate and/or identify Windows product keys

## Accuracy

Please note that many sources on Windows product key validation algorithms are
**wrong**. For example, many sites state that Windows 95 keys *must* be numeric,
but Windows will accept any character, and that the first three characters are
ignored, but in fact they must not be one of 333, 444, 555, 666, 777, 888, or
999 (multiple sources event used `666-0077700` as an example key, which
*wouldn't work*).

Other sources may be wrong in ways I cannot identify. If you've found a key
that wkv validates but Windows does not (or vice versa), please file an issue.

WKV doesn't validate keys with Microsoft servers. The checks are syntactic
right now.

Functions are usually left public for the purpose of documenting their process,
the main function you'd be using is `validate`.
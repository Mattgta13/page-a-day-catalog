# Page-a-Day catalog

The signed photo catalog for the Page-a-Day desktop widget. The widget checks this
repository about once a day for new photos and subjects.

Every photo listed here comes from a source that already identifies it (for example
a Wikimedia Commons category for that exact car), and each entry records how its
caption was confirmed in its `verified` field. Photos remain the work of their
photographers and are used under the licenses shown with each entry.

## Why it's safe to be public

`catalog/index.json` is signed with a private key that is never stored here. The
widget only accepts an index whose signature matches the public key built into it,
and each subject file must match the SHA-256 hash recorded in that signed index.
Anyone could read or copy this repository, but no one without the key can change
what the widget shows.

## Updating

1. Edit or add files in `catalog/subjects/`.
2. Sign: `pip install cryptography` then
   `python tools/sign_catalog.py --key path/to/catalog-signing-key.pem`
3. Commit and push. The **Verify catalog** check confirms the signature, hashes and
   entries exactly the way the widget will.

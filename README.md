# CLA signatures

This orphan branch holds the Contributor License Agreement signature record for
Kessa, and nothing else. It carries no source code and is never merged into
`main`.

`signatures.json` is written by
[`.github/workflows/cla.yml`](https://github.com/Gneiss-Group/Kessa/blob/main/.github/workflows/cla.yml)
when a contributor signs. Do not edit it by hand: this branch's commit history
*is* the signature record, so a hand edit is an unattributable change to a legal
document.

It lives here rather than on `main` because `main` requires signed commits and
forbids direct pushes (see
[`docs/branching.md`](https://github.com/Gneiss-Group/Kessa/blob/main/docs/branching.md)),
and a GitHub Action can satisfy neither. The alternative was a ruleset bypass on
`main`, which would trade a standing hole in that protection for convenience.

The agreements themselves are
[`CLA.md`](https://github.com/Gneiss-Group/Kessa/blob/main/CLA.md) and
[`CLA-CORPORATE.md`](https://github.com/Gneiss-Group/Kessa/blob/main/CLA-CORPORATE.md)
on `main`.

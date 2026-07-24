# Story images

Rendered user-story cards for the README and pitch material. Each `.svg` here is
generated, not hand-drawn: it is rendered from the verbatim ALLOW/DENY output of
a real run of the reporting-agent scenarios (`make stories-capture`).

Do not edit the `.svg` files by hand. To change what a card says, change the
scenario in `scripts/stories/run.sh` (so the binaries actually produce the new
outcome) and re-render. The full design and generation instructions live in
[`docs/stories.md`](../../stories.md).

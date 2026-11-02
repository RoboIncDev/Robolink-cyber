# Bundled country flags

Circular flag icons from **circle-flags** by HatScripts (MIT licence, see `LICENSE`): https://github.com/HatScripts/circle-flags
One SVG per ISO 3166-1 alpha-2 code the map can show (240 files, about 1 MB). They are plain SVG shapes: every file was checked for scripts, event
handlers, external references and entities before it was added. `sh.svg` and `sj.svg` are copies of the upstream `sh-hl.svg` and `no.svg`.
The dashboard shows them as decorative images next to a country name; the name is always written out (a flag alone never carries meaning).
Served by the robosec server at `/static/flags/<cc>.svg`. No emoji are used anywhere in the interface (Signal System rule).

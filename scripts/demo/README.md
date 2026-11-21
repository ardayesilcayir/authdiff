# README demo GIF

`transcript.txt` is the real terminal output of `authdiff version`,
`authdiff inventory` (trimmed to 10 rows) and `authdiff scan` against the local
`vuln-lab` (log lines on stderr removed). `render_gif.py` turns it into
`docs/assets/demo.gif` and `docs/assets/demo.png`.

Dev dependency (not part of the project requirements): Pillow.

```sh
python -m venv .demo-venv && .demo-venv/bin/pip install Pillow   # or reuse any venv
python scripts/demo/render_gif.py
```

Font: Consolas on Windows, DejaVu Sans Mono elsewhere. To refresh the
transcript, start the lab, load `examples/vuln-lab.env`, run the three commands
and paste the output (no tokens appear in the output).

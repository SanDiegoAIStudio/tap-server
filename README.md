# tap-server

tap-server is a small HTTP server that listens on your own machine only, so that buttons, a checkbox and a note box on an HTML page opened from disk can act on that machine. A button runs one command from a list you wrote, and the checkbox and the note are appended to a log file. It is for people who build local pages and tools and want them to do real work without a cloud service, and it uses only the Python standard library.

## Quick start

From a fresh clone, in the cloned folder. This needs Python 3.9 or newer.

Run the tests:

```
python3 -m unittest discover -s tests -q
```

Copy the example command list into the run folder:

```
mkdir -p run
cp commands.example.json run/commands.json
```

Start the server and leave it running:

```
python3 tap_server.py
```

Open `demo.html` from this same folder in a browser (on macOS, `open demo.html`). Press Date, then tick the checkbox or save a note. The page loads its two tokens from `run/tap-token.js` and `run/page-token.js`, which the server writes when it starts, so there is nothing to paste. If you opened the page before the server had started, reload it.

## Example

This is a real run on Python 3.9.6. The server was started from the cloned folder with the example command list, and these calls were made from a second terminal.

The server prints this line when it starts. It names the two token files and never prints a token:

```
tap-server on 127.0.0.1:7373 (command token file: run/token, page token file: run/page-token)
```

Health check, which needs no token:

```
$ curl -s http://127.0.0.1:7373/health
ok
```

Run the `date` command with the command token. The shell reads the token from its file, so the token never appears on the command line you type:

```
$ curl -s -w ' (%{http_code})\n' -X POST 'http://127.0.0.1:7373/tap?cmd=date' -H "X-Tap-Token: $(cat run/token)"
Fri Nov 13 14:56:00 PST 2026 (200)
```

The same call without a token:

```
$ curl -s -w ' (%{http_code})\n' -X POST 'http://127.0.0.1:7373/tap?cmd=date'
bad or missing tap token (403)
```

Save a note with the page token, read from its file the same way:

```
$ curl -s -w ' (%{http_code})\n' -X POST http://127.0.0.1:7373/page -H "X-Tap-Token: $(cat run/page-token)" -H 'Content-Type: application/json' -d '{"slug":"demo","kind":"note","text":"hello from curl"}'
 (204)
```

The line that call appended to `run/page.jsonl`:

```
{"slug": "demo", "kind": "note", "received_ts": "2026-11-13T14:56:00", "text": "hello from curl"}
```

## How it works

There are two routes that do anything, `POST /tap` and `POST /page`, plus `GET /health`. Any other GET is handled as the same path sent with POST, and an unknown path gets 404.

Two tokens. The command token opens `POST /tap` and nothing else. The page token opens `POST /page` and nothing else. Each is 48 hexadecimal characters from `secrets.token_hex(24)`, kept in its own file (`run/token` and `run/page-token` by default). A missing file is created on first use with mode 600, and a file found with looser permissions is set back to 600 when it is next read. A file that cannot be read gets 500, and nothing runs. The files are read again on every request, so replacing a file changes the token with no restart. The command token is refused on `/page` and the page token is refused on `/tap`, each with 403. The token travels in the `X-Tap-Token` request header.

Token files for pages. Beside each token file the server keeps a one-line script file in step with it: `tap-token.js` holds `window.TAP_TOKEN = "TOKEN";` and `page-token.js` holds `window.PAGE_TOKEN = "TOKEN";`, where TOKEN is the token. Each is written with mode 600 when it is missing or differs from the token file, each time a token is loaded, by writing a new file beside it and moving it into place, so a page never reads a half-written file. A page opened from disk loads them with two script tags and sends the values in the header. No route returns a token.

Order of checks. On both routes the server checks the Origin rule first, then the token, and only then reads the body. A caller without the right token learns nothing about the body rules.

The Origin rule. A request with no Origin header, an Origin of `null`, or an Origin that starts with `file:` passes. Any other Origin gets 403.

The command list. `/tap?cmd=NAME` looks NAME up in the commands file (`run/commands.json` by default), a JSON object that maps each name to one argument list. The list is run without a shell, with a 90 second timeout, and the output is the reply. Each command runs in its own process group, and on a timeout the whole group is stopped. A reply longer than 100000 characters is cut there, with a line saying so. A name that is not in the file gets 400. The file is read again on every request.

The page log. `/page` takes a JSON object with a `slug` and a `kind` of `check` or `note`, and appends one line of JSON to the log (`run/page.jsonl` by default). It also accepts `card_id`, `text`, `note`, `ts`, `queued`, `sid` and `id`. `card_id` names the box a check belongs to and must be 1 to 80 letters, digits, dots, colons, dashes or underscores, or the request gets 400. `sid` and `id` are written into the line as given, cut to 80 characters, so a page can tag each line with its own session and record ids. A note needs text. A request with no Origin header cannot save a check unless it carries a `note`. That stops a careless script from ticking a box without a word. It is no security check, because any client can send an Origin of `null`; the page token is what keeps other programs out. The log file is created with mode 600, like the token files.

The queue in the page. `demo.html` keeps taps and page writes in the browser's local storage when the server does not answer, and sends them in order when it answers again. If the server answers 403, the page pauses the queue and asks you to reload, so it reads the token files again.

Settings, all optional, each read from an environment variable:

```
TAP_PORT=7373
TAP_TOKEN_FILE=run/token
TAP_PAGE_TOKEN_FILE=run/page-token
TAP_COMMANDS_FILE=run/commands.json
TAP_PAGE_LOG=run/page.jsonl
```

The page expects the server on port 7373 and the token script files in `run/` beside `demo.html`. If you change either, edit `demo.html` to match.

## Security model

What each check stops:

- The loopback bind: other machines on the network cannot connect.
- The Origin rule: a request that names a web site as its origin is refused, even with a valid token.
- The tokens: a request from anything that cannot read the token files is refused. Because there are two, a page that only holds the page token cannot run commands.
- The command list: a caller picks a name, never a command, and nothing goes through a shell, so a request cannot make the server run anything you did not list.
- The body size cap (120000 bytes) and the rule order: an oversized body is refused, and a caller without a token cannot probe the body rules.
- No route returns a token, and token files, token script files and the page log are mode 600.

What it does not protect against:

- Any program running as your user can read the token files, so it can use both tokens.
- Whoever can edit the commands file decides what runs.
- Commands run with the server's own permissions.
- `/health` answers anyone, so a web page can tell that the server is running.
- A sandboxed frame on a web page can send Origin `null`, which the rule lets through. The Origin rule therefore never stands alone, and this is why no route returns a token.
- There is no TLS. The server listens on loopback only, so requests to it do not cross the network.

## Limits

- One machine, one user. It binds to 127.0.0.1 and has no option to bind elsewhere.
- A command runs for at most 90 seconds, then the caller gets 504.
- A body can be at most 120000 bytes, a note or checkbox text at most 4000 characters, and the note on a check at most 1000.
- The page log only grows. Nothing rotates or trims it.
- The server never rotates the tokens. To rotate one, replace its file.
- The queue lives in one browser's local storage, not on the server.
- Run the server from the folder that holds `demo.html`, so the default `run/` folder is the one the page loads from.
- There is no authentication beyond the two tokens and no per-page or per-user permission.

## Where this came from

This is the kernel of a private server its author has run on his own machine since July 2026 so that local pages can act. The private original has many more routes that only drive his own setup. The two-token design and the tokens-by-file delivery are the original's. Accepting a `file:` origin is new in this copy.

## License

MIT. See `LICENSE`.

## Built at San Diego AI Studio

This tool comes out of San Diego AI Studio, the builders' community in San Diego. More of what the community builds is at https://sandiegoaistudio.com/projects.

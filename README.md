# CYB333 Midterm: Socket Connection and Port Scanner

Python 3.10+ only. No third-party packages needed.

## Files

| File | Purpose |
|------|---------|
| `server.py` | TCP server that listens on 127.0.0.1:65432 and replies to each message |
| `client.py` | TCP client that connects to the server and sends typed messages |
| `port_scanner.py` | TCP connect port scanner limited to localhost and scanme.nmap.org |
| `scan_results.csv` | Sample output from the scanner's `--output` option |

## Part 1 (socket connection)

Open two terminals in this folder.

```bash
# Terminal 1
python server.py

# Terminal 2
python client.py
> hello server
> quit
```

Stop the server with `Ctrl+C`. Run `python client.py` while the server is stopped to see the connection-refused error handling.

## Part 2 (port scanner)

```bash
python port_scanner.py 127.0.0.1 -p 21,22,80,443        # common ports
python port_scanner.py 127.0.0.1 -p 65425-65440          # custom range
python port_scanner.py scanme.nmap.org -p 22,80,443,9929 # authorized remote target
python port_scanner.py 127.0.0.1 -p 70000                # invalid port
python port_scanner.py no-such-host.invalid              # unreachable host
python port_scanner.py 127.0.0.1 -p 21,22,80 --output scan_results.csv  # save results
```

Options include `--timeout` (seconds per port, default 0.5), `--delay` (pause between ports, default 0.1), `--open-only`, and `--output FILE` (save results as CSV).

## Windows notes

- The server uses a 1-second socket timeout so `Ctrl+C` works on Windows, where a blocking `accept()` otherwise ignores keyboard interrupts.
- On 127.0.0.1, Windows delays refused connections, so the scanner reports any local port that does not answer as closed rather than filtered.

## Ethical use

The scanner refuses any target other than localhost, 127.0.0.1, and scanme.nmap.org. It caps remote scans at 100 ports and waits between attempts.
